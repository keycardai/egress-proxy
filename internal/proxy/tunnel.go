package proxy

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/elazarl/goproxy"

	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/policy"
)

const (
	httpsPort = 443

	connectEstablished = "HTTP/1.1 200 Connection established\r\n\r\n"
	contentTypeText    = "text/plain; charset=utf-8"
)

var (
	errNoSNI        = errors.New("the handshake named no server")
	errHostMismatch = errors.New("the server name is not the CONNECT authority")
	errNoSource     = errors.New("this process has no credential source")
)

// tunnel is what the connection decision hands to the requests inside the
// tunnel. host and port are the CONNECT authority. The handshake fills in
// sni before the tunnel server reads any request.
type tunnel struct {
	connectionID string
	host         string
	port         int
	sni          string
}

// tunnelConn is a decrypted tunnel that the tunnel server accepts. The
// wrapper keeps net/http from handshaking again, and it lets ConnContext
// find the tunnel state.
type tunnelConn struct {
	net.Conn

	state *tunnel
}

type tunnelKey struct{}

func tunnelContext(ctx context.Context, conn net.Conn) context.Context {
	if tc, ok := conn.(*tunnelConn); ok {
		return context.WithValue(ctx, tunnelKey{}, tc.state)
	}
	return ctx
}

func tunnelFrom(ctx context.Context) *tunnel {
	state, _ := ctx.Value(tunnelKey{}).(*tunnel)
	return state
}

// handleConnect makes the connection-scoped decision on the CONNECT
// authority. It refuses a denied host here, before the store mints a leaf.
//
// A refusal is recorded here. An allow is recorded once the handshake
// establishes the tunnel, so exactly one connection-scoped record describes
// a connection and an allow means the tunnel carried traffic.
func (s *Server) handleConnect(authority string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	state := &tunnel{connectionID: newID()}
	var decision policy.Decision
	host, port, ok := splitAuthority(authority)
	if ok {
		state.host, state.port = host, port
		decision = s.opts.Matcher.Connection(host, port)
	} else {
		state.host = authority
		decision = policy.Decision{Verdict: policy.VerdictDeny, Reason: policy.ReasonMalformedRequest}
	}
	if !decision.Allowed() {
		s.opts.Audit.Emit(audit.Record{
			ConnectionID: state.connectionID,
			Scope:        audit.ScopeConnection,
			Destination:  audit.Destination{Host: state.host, Port: state.port},
			Decision:     auditDecision(decision),
		})
		s.logger.Info("refused a connection",
			slog.String("connection_id", state.connectionID),
			slog.String("authority", authority),
			slog.String("reason", string(decision.Reason)))
		// goproxy writes ctx.Resp to the client. The body is an in-memory
		// reader with nothing to release.
		//nolint:bodyclose // an in-memory body has nothing to release
		ctx.Resp = denyResponse(ctx.Req, statusFor(decision.Reason), decision.Reason, state.connectionID)
		return &goproxy.ConnectAction{Action: goproxy.ConnectReject}, authority
	}
	return &goproxy.ConnectAction{
		Action: goproxy.ConnectHijack,
		Hijack: func(_ *http.Request, client net.Conn, _ *goproxy.ProxyCtx) {
			s.acceptTunnel(client, state)
		},
	}, authority
}

// acceptTunnel confirms the tunnel to the client and hands the connection to
// the handshake goroutine. It runs on the frontend's connection goroutine
// and returns at once, so the frontend never blocks on a tunnel.
func (s *Server) acceptTunnel(client net.Conn, state *tunnel) {
	if _, err := io.WriteString(client, connectEstablished); err != nil {
		s.closeConn(client, state, "confirm the tunnel")
		return
	}
	go s.handshake(client, state)
}

// handshake terminates TLS on a tunnel and passes the decrypted connection
// to the tunnel server. It recovers, so a panic costs one connection.
func (s *Server) handshake(client net.Conn, state *tunnel) {
	defer s.recoverConn(client, state)
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.HandshakeTimeout)
	defer cancel()
	tlsConn := tls.Server(client, s.tlsConfig(state))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		s.logHandshakeFailure(state, err)
		s.closeConn(tlsConn, state, "handshake")
		return
	}
	// The tunnel is established, so the allow describes a connection that
	// carried traffic. Emit it before the tunnel server reads any request.
	s.opts.Audit.Emit(audit.Record{
		ConnectionID: state.connectionID,
		Scope:        audit.ScopeConnection,
		Destination:  audit.Destination{Host: state.host, Port: state.port, SNI: state.sni},
		Decision:     audit.Decision{Verdict: policy.VerdictAllow, Reason: policy.ReasonEndpointAllowed},
	})
	if !s.intake.push(&tunnelConn{Conn: tlsConn, state: state}) {
		s.closeConn(tlsConn, state, "shutdown")
	}
}

// logHandshakeFailure reports a handshake that did not complete. A handshake
// that spends the whole budget holds a connection slot against
// limits.max_connections for HandshakeTimeout, so enough of them at once
// reach the cap and the proxy stops accepting tunnels. That case logs at
// warning level. Every other failure returns the slot as soon as the client
// errors, so it logs at info level. Neither case carries an audit record,
// because the connection-scoped allow lands only once the tunnel is up.
func (s *Server) logHandshakeFailure(state *tunnel, err error) {
	attrs := []any{
		slog.String("connection_id", state.connectionID),
		slog.String("authority", net.JoinHostPort(state.host, strconv.Itoa(state.port))),
		slog.String("error", err.Error()),
	}
	if errors.Is(err, context.DeadlineExceeded) {
		s.logger.Warn("tunnel handshake timed out and held a connection slot for the whole budget",
			append(attrs, slog.Duration("handshake_timeout", s.opts.HandshakeTimeout))...)
		return
	}
	s.logger.Info("tunnel handshake failed", attrs...)
}

// closeConn closes a tunnel's connection. It logs a close that fails for any
// reason other than the connection being closed already. Nothing waits on
// it.
func (s *Server) closeConn(conn net.Conn, state *tunnel, during string) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.logger.Warn("closing a tunnel connection",
			slog.String("connection_id", state.connectionID),
			slog.String("during", during),
			slog.String("error", err.Error()))
	}
}

func (s *Server) recoverConn(client net.Conn, state *tunnel) {
	if recovered := recover(); recovered != nil {
		s.logger.Error("recovered a panic on a tunnel; the connection is closed",
			slog.String("connection_id", state.connectionID),
			slog.Any("panic", recovered),
			slog.String("stack", string(debug.Stack())))
		s.closeConn(client, state, "panic")
	}
}

// tlsConfig is the server side of one tunnel. It mints a leaf for the SNI,
// and only when the SNI is the CONNECT authority. A handshake with no SNI,
// or with another name, fails and lands on the connection's audit record.
//
// Resumption is disabled, so crypto/tls calls GetCertificate on every
// handshake. That is the only place the SNI is checked and the only place
// state.sni is set. NEVER enable resumption here: a resumed handshake skips
// GetCertificate, which leaves state.sni empty and denies every request in
// the tunnel with host_mismatch.
func (s *Server) tlsConfig(state *tunnel) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := policy.NormalizeHost(hello.ServerName)
			var refusal error
			var reason policy.Reason
			switch {
			case sni == "":
				refusal, reason = errNoSNI, policy.ReasonNoSNI
			case sni != state.host:
				refusal, reason = errHostMismatch, policy.ReasonHostMismatch
			}
			if refusal != nil {
				s.opts.Audit.Emit(audit.Record{
					ConnectionID: state.connectionID,
					Scope:        audit.ScopeConnection,
					Destination:  audit.Destination{Host: state.host, Port: state.port, SNI: sni},
					Decision:     audit.Decision{Verdict: policy.VerdictDeny, Reason: reason},
				})
				return nil, refusal
			}
			state.sni = sni
			certificate, err := s.opts.Certificates.Certificate(sni)
			if err != nil {
				s.opts.Audit.Emit(audit.Record{
					ConnectionID: state.connectionID,
					Scope:        audit.ScopeConnection,
					Destination:  audit.Destination{Host: state.host, Port: state.port, SNI: sni},
					Decision: audit.Decision{
						Verdict: policy.VerdictDeny,
						Reason:  policy.ReasonCertificateUnavailable,
						Error:   err.Error(),
					},
				})
				return nil, fmt.Errorf("proxy: mint a leaf for %s: %w", sni, err)
			}
			return certificate, nil
		},
	}
}

// forward is what the request decision hands to the reverse proxy and reads
// back from it.
type forward struct {
	host string
	port int
	// requestID is the id on the record for this request. A refusal the
	// reverse proxy answers carries it, so every deny names a record.
	requestID string
	// writer and secret are the endpoint's credential and where it goes.
	// Both are empty for an endpoint that names none.
	writer credential.Writer
	secret string
	// writeErr is what the credential writer reported. The round trip
	// refuses a forward that carries one.
	writeErr error
	denied   bool
	// denyReason is the reason a refusal on the upstream leg records. It is
	// set wherever denied is set.
	denyReason policy.Reason
	err        error
	// status is the status the upstream answered, set before the response
	// is written.
	status int
}

type forwardKey struct{}

func forwardFrom(ctx context.Context) *forward {
	fwd, _ := ctx.Value(forwardKey{}).(*forward)
	return fwd
}

// serveTunnelRequest makes the request-scoped decision and forwards an
// allowed request.
func (s *Server) serveTunnelRequest(w http.ResponseWriter, r *http.Request) {
	// A request that arrives once the join has begun is not served,
	// because its connection is closed already.
	if !s.handlers.enter() {
		return
	}
	defer s.handlers.leave()
	state := tunnelFrom(r.Context())
	if state == nil {
		http.Error(w, "no tunnel", http.StatusInternalServerError)
		return
	}
	requestID := newID()
	record := audit.Record{
		ConnectionID: state.connectionID,
		RequestID:    requestID,
		Scope:        audit.ScopeRequest,
		Destination:  audit.Destination{Host: state.sni, Port: state.port, SNI: state.sni},
		Request:      &audit.RequestInfo{Method: r.Method, Path: r.URL.EscapedPath(), Host: r.Host},
	}
	fwd := &forward{host: state.sni, port: state.port, requestID: requestID}
	decision := s.decideRequest(r.Context(), state, r, fwd)
	record.Decision = auditDecision(decision)
	if !decision.Allowed() {
		s.opts.Audit.Emit(record)
		s.logger.Info("refused a request",
			slog.String("request_id", requestID),
			slog.String("reason", string(decision.Reason)))
		writeDeny(w, statusFor(decision.Reason), decision.Reason, requestID)
		return
	}

	recorder := &statusRecorder{ResponseWriter: w}
	// ReverseProxy panics with http.ErrAbortHandler when it cannot finish
	// copying a body, so the record is emitted from a deferred call and the
	// panic goes on to net/http, which closes the connection.
	defer func() {
		recovered := recover()
		s.emitForwarded(record, fwd, recorder, r, recovered)
		if recovered != nil {
			panic(recovered)
		}
	}()
	s.reverse.ServeHTTP(recorder, r.WithContext(context.WithValue(r.Context(), forwardKey{}, fwd)))
}

// emitForwarded records what came of an allowed request. The decision stays
// what decideRequest returned unless the forward itself was refused or
// failed. recovered is non-nil when the response did not complete.
func (s *Server) emitForwarded(
	record audit.Record, fwd *forward, recorder *statusRecorder, r *http.Request, recovered any,
) {
	// A hijacked upgrade reaches no recorder, so the forward holds its status.
	record.Outcome = &audit.Outcome{Status: cmp.Or(recorder.status, fwd.status)}
	// A refusal on the upstream leg overturns the verdict and keeps the rest
	// of the decision. The endpoint the allow named stays on the record, so
	// an audit query can find which rule covered the traffic.
	//
	// These fields can contain upstream text, which can contain the credential.
	// Redact every such field.
	switch {
	case fwd.denied:
		record.Decision.Verdict = policy.VerdictDeny
		record.Decision.Reason = fwd.denyReason
		record.Decision.Error = credential.Redact(fwd.err.Error(), fwd.secret)
	case fwd.err != nil:
		record.Decision.Verdict = policy.VerdictDeny
		record.Decision.Reason = policy.ReasonUpstreamFailed
		record.Outcome.Error = credential.Redact(fwd.err.Error(), fwd.secret)
	case recovered != nil:
		record.Outcome.Error = credential.Redact(panicOutcome(recovered, r.Context().Err()), fwd.secret)
	}
	s.opts.Audit.Emit(record)
}

// panicOutcome names what a panic out of the forward left behind. The abort
// says the response did not complete, and requestErr tells a client that
// went away from an upstream body that did not complete. Any other value is
// a panic in the handler and carries its own text.
func panicOutcome(recovered any, requestErr error) string {
	abort, _ := recovered.(error)
	switch {
	case abort == nil || !errors.Is(abort, http.ErrAbortHandler):
		return "the handler panicked: " + fmt.Sprint(recovered)
	case requestErr != nil:
		return "the client went away or the server stopped before the response completed"
	default:
		return "the upstream response body did not complete"
	}
}

// decideRequest is the per-request decision: the request is one the proxy
// can forward as written, an endpoint covers the path, and the credential
// that endpoint names is in hand. It fills fwd with the credential and
// where it goes.
func (s *Server) decideRequest(
	ctx context.Context, state *tunnel, r *http.Request, fwd *forward,
) policy.Decision {
	if refusal, refused := refuseRequestShape(state, r); refused {
		return refusal
	}
	decision := s.opts.Matcher.Request(state.sni, state.port, r.URL.EscapedPath())
	if !decision.Allowed() || decision.Endpoint == nil || decision.Endpoint.Credential == nil {
		return decision
	}
	if err := s.resolveCredential(ctx, *decision.Endpoint, fwd); err != nil {
		return policy.Decision{
			Verdict:  policy.VerdictDeny,
			Reason:   credentialReason(err),
			Endpoint: decision.Endpoint,
			Err:      err,
		}
	}
	return decision
}

// credentialReason maps a source failure onto its denial reason. A source
// says which class a failure is in, so nothing here reads a message.
func credentialReason(err error) policy.Reason {
	switch {
	case errors.Is(err, credential.ErrAccessDenied):
		return policy.ReasonAccessDenied
	case errors.Is(err, credential.ErrExchangeFailed):
		return policy.ReasonExchangeFailed
	default:
		return policy.ReasonCredentialUnavailable
	}
}

// refuseRequestShape refuses a request the proxy cannot forward unchanged.
func refuseRequestShape(state *tunnel, r *http.Request) (policy.Decision, bool) {
	if r.RequestURI == "*" || !strings.HasPrefix(r.URL.Path, "/") {
		return policy.Decision{Verdict: policy.VerdictDeny, Reason: policy.ReasonMalformedRequest}, true
	}
	// The query must parse. The reverse proxy re-encodes an invalid query and
	// drops pairs it cannot read.
	if _, err := url.ParseQuery(r.URL.RawQuery); err != nil {
		return policy.Decision{Verdict: policy.VerdictDeny, Reason: policy.ReasonMalformedRequest, Err: err}, true
	}
	hostname, port, ok := splitAuthority(r.Host)
	if !ok || hostname != state.sni || port != state.port {
		return policy.Decision{Verdict: policy.VerdictDeny, Reason: policy.ReasonHostMismatch}, true
	}
	return policy.Decision{}, false
}

// resolveCredential reads the endpoint credential and prepares its writer.
// Any failure denies the request before it leaves with the workload value.
func (s *Server) resolveCredential(ctx context.Context, endpoint policy.Endpoint, fwd *forward) error {
	if s.opts.Credentials == nil {
		return errNoSource
	}
	writer, err := credential.NewWriter(*endpoint.Credential)
	if err != nil {
		return err //nolint:wrapcheck // the message already names the placement
	}
	secret, err := s.opts.Credentials.Credential(ctx, endpoint.Resource)
	if err != nil {
		return fmt.Errorf("resource %s: %w", endpoint.Resource, err)
	}
	if err := credential.Validate(secret); err != nil {
		return fmt.Errorf("resource %s: %w", endpoint.Resource, err)
	}
	fwd.writer, fwd.secret = writer, secret
	return nil
}

// rewrite points the outbound request at the SNI on the CONNECT port and
// writes the endpoint's credential into it. It keeps the Host header as the
// workload sent it, because the request decision already checked that the
// header is the SNI.
//
// Write the credential here because the reverse proxy has already removed the
// hop-by-hop headers named by Connection.
func (s *Server) rewrite(proxied *httputil.ProxyRequest) {
	fwd := forwardFrom(proxied.In.Context())
	proxied.Out.URL.Scheme = "https"
	proxied.Out.URL.Host = net.JoinHostPort(fwd.host, strconv.Itoa(fwd.port))
	proxied.Out.Host = proxied.In.Host
	if fwd.writer == nil {
		return
	}
	if err := fwd.writer.Write(proxied.Out, fwd.secret); err != nil {
		// Rewrite cannot abort a forward. The round trip rejects this forward
		// before it reaches the upstream.
		fwd.writeErr = err
		s.logger.Warn("the credential was not written, so the request is refused",
			slog.String("request_id", fwd.requestID),
			slog.String("error", credential.Redact(err.Error(), fwd.secret)))
	}
}

// credentialNotWrittenError is the round trip's refusal of a forward whose
// credential writer failed.
type credentialNotWrittenError struct{ err error }

func (e *credentialNotWrittenError) Error() string { return e.err.Error() }

func (e *credentialNotWrittenError) Unwrap() error { return e.err }

// refuseUnwritten is the transport the reverse proxy uses. It opens no
// connection when the credential writer fails.
type refuseUnwritten struct{ next http.RoundTripper }

func (t refuseUnwritten) RoundTrip(r *http.Request) (*http.Response, error) {
	if fwd := forwardFrom(r.Context()); fwd != nil && fwd.writeErr != nil {
		return nil, &credentialNotWrittenError{err: fwd.writeErr}
	}
	return t.next.RoundTrip(r) //nolint:wrapcheck // the transport's own error reaches the error handler
}

// recordUpstreamStatus keeps the upstream's status on the forward. The
// status recorder misses a 101, which the reverse proxy writes onto the
// hijacked connection.
func (s *Server) recordUpstreamStatus(res *http.Response) error {
	if fwd := forwardFrom(res.Request.Context()); fwd != nil {
		fwd.status = res.StatusCode
	}
	return nil
}

// upstreamError answers an allowed request that produced no response. A dial
// refused by the deny list and a failed credential write are policy denials.
// Anything else is an upstream failure.
func (s *Server) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	fwd := forwardFrom(r.Context())
	fwd.err = err
	switch {
	case isType[*deniedError](err):
		fwd.denied, fwd.denyReason = true, policy.ReasonDenyAlways
	case isType[*credentialNotWrittenError](err):
		fwd.denied, fwd.denyReason = true, policy.ReasonCredentialUnavailable
	default:
		writeDeny(w, http.StatusBadGateway, policy.ReasonUpstreamFailed, fwd.requestID)
		return
	}
	writeDeny(w, statusFor(fwd.denyReason), fwd.denyReason, fwd.requestID)
}

// isType reports whether err is or wraps an error of type E.
func isType[E error](err error) bool {
	_, ok := errors.AsType[E](err)
	return ok
}

// handlePlain refuses a request that reached the proxy in absolute form
// over cleartext. Endpoints name HTTPS destinations, so a cleartext request
// matches none. The deny list still names the more specific reason.
func (s *Server) handlePlain(r *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	requestID := newID()
	host, port, _ := splitAuthority(r.URL.Host)
	decision := s.opts.Matcher.Connection(host, port)
	reason := decision.Reason
	if decision.Allowed() {
		reason = policy.ReasonNoMatchingEndpoint
	}
	s.opts.Audit.Emit(audit.Record{
		RequestID:   requestID,
		Scope:       audit.ScopeRequest,
		Destination: audit.Destination{Host: host, Port: port},
		Request:     &audit.RequestInfo{Method: r.Method, Path: r.URL.EscapedPath(), Host: r.Host},
		Decision:    audit.Decision{Verdict: policy.VerdictDeny, Reason: reason},
	})
	return r, denyResponse(r, statusFor(reason), reason, requestID)
}

// serveNonProxy refuses a request in origin form. The listener is a proxy
// and serves nothing of its own. Health lives on the admin socket.
func (s *Server) serveNonProxy(w http.ResponseWriter, r *http.Request) {
	requestID := newID()
	s.opts.Audit.Emit(audit.Record{
		RequestID:   requestID,
		Scope:       audit.ScopeRequest,
		Destination: audit.Destination{},
		Request:     &audit.RequestInfo{Method: r.Method, Path: r.URL.EscapedPath(), Host: r.Host},
		Decision:    audit.Decision{Verdict: policy.VerdictDeny, Reason: policy.ReasonNotAProxyRequest},
	})
	writeDeny(w, http.StatusBadRequest, policy.ReasonNotAProxyRequest, requestID)
}

// splitAuthority splits host[:port], defaulting the port to 443. It reports
// false for an empty host or a port outside 1 to 65535.
func splitAuthority(authority string) (string, int, bool) {
	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		host, portText = authority, strconv.Itoa(httpsPort)
	}
	host = policy.NormalizeHost(host)
	port, err := strconv.Atoi(portText)
	if host == "" || err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

func auditDecision(decision policy.Decision) audit.Decision {
	out := audit.Decision{Verdict: decision.Verdict, Reason: decision.Reason}
	if decision.Endpoint != nil {
		out.Endpoint = decision.Endpoint.ID()
	}
	if decision.Err != nil {
		out.Error = decision.Err.Error()
	}
	return out
}

// statusFor maps a reason code to the status a refusal carries.
func statusFor(reason policy.Reason) int {
	switch reason {
	case policy.ReasonMalformedRequest, policy.ReasonNotAProxyRequest:
		return http.StatusBadRequest
	case policy.ReasonUpstreamFailed, policy.ReasonExchangeFailed:
		// A dependency caused the denial, so a retry can succeed.
		return http.StatusBadGateway
	case policy.ReasonCertificateUnavailable:
		// The handshake fails before any request, so this reason reaches an
		// audit record and never a response.
		return http.StatusInternalServerError
	case policy.ReasonDenyAlways, policy.ReasonNoMatchingEndpoint, policy.ReasonHostMismatch, policy.ReasonNoSNI,
		policy.ReasonCredentialUnavailable, policy.ReasonAccessDenied:
		return http.StatusForbidden
	case policy.ReasonEndpointAllowed:
		// An allow never reaches this function. The case is here because
		// exhaustive requires every reason code, whatever the default arm
		// returns.
		return http.StatusForbidden
	default:
		return http.StatusForbidden
	}
}

func denyHeaders(header http.Header, reason policy.Reason, requestID string) {
	header.Set("Content-Type", contentTypeText)
	header.Set(HeaderReason, string(reason))
	if requestID != "" {
		header.Set(HeaderRequestID, requestID)
	}
}

func writeDeny(w http.ResponseWriter, status int, reason policy.Reason, requestID string) {
	denyHeaders(w.Header(), reason, requestID)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "egress-proxy: "+string(reason)+"\n")
}

// denyResponse is the refusal goproxy writes to the client, on a rejected
// CONNECT or a cleartext request.
func denyResponse(r *http.Request, status int, reason policy.Reason, requestID string) *http.Response {
	resp := goproxy.NewResponse(r, contentTypeText, status, "egress-proxy: "+string(reason)+"\n")
	denyHeaders(resp.Header, reason, requestID)
	return resp
}

// statusRecorder captures the status the reverse proxy wrote. Unwrap lets
// http.ResponseController reach the flusher and hijacker beneath, which the
// reverse proxy uses for streaming and upgrades.
type statusRecorder struct {
	http.ResponseWriter

	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	// An informational status precedes the final status and is not recorded.
	if status >= http.StatusOK {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(p) //nolint:wrapcheck // the reverse proxy reads the error as the client going away
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
