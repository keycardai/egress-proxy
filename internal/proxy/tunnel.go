package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/elazarl/goproxy"

	"github.com/keycardai/egress-proxy/internal/audit"
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
func (s *Server) handleConnect(authority string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	state := &tunnel{connectionID: newID()}
	var decision policy.Decision
	host, port, ok := splitAuthority(authority)
	if ok {
		state.host, state.port = host, port
		decision = s.opts.Matcher.Host(host)
	} else {
		state.host = authority
		decision = policy.Decision{Verdict: policy.VerdictDeny, Reason: policy.ReasonMalformedRequest}
	}
	s.opts.Audit.Emit(audit.Record{
		ConnectionID: state.connectionID,
		Scope:        audit.ScopeConnection,
		Destination:  audit.Destination{Host: state.host, Port: state.port},
		Decision:     auditDecision(decision),
	})
	if !decision.Allowed() {
		s.logger.Info("refused a connection",
			slog.String("connection_id", state.connectionID),
			slog.String("authority", authority),
			slog.String("reason", string(decision.Reason)))
		// goproxy writes ctx.Resp to the client. The body is an in-memory
		// reader with nothing to release.
		//nolint:bodyclose // see above
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
		s.logger.Info("tunnel handshake failed",
			slog.String("connection_id", state.connectionID),
			slog.String("authority", net.JoinHostPort(state.host, strconv.Itoa(state.port))),
			slog.String("error", err.Error()))
		s.closeConn(tlsConn, state, "handshake")
		return
	}
	if !s.intake.push(&tunnelConn{Conn: tlsConn, state: state}) {
		s.closeConn(tlsConn, state, "shutdown")
	}
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
func (s *Server) tlsConfig(state *tunnel) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
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
	denied    bool
	err       error
}

type forwardKey struct{}

func forwardFrom(ctx context.Context) *forward {
	fwd, _ := ctx.Value(forwardKey{}).(*forward)
	return fwd
}

// serveTunnelRequest makes the request-scoped decision and forwards an
// allowed request.
func (s *Server) serveTunnelRequest(w http.ResponseWriter, r *http.Request) {
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
		Request:      &audit.RequestInfo{Method: r.Method, Path: r.URL.Path, Host: r.Host},
	}
	decision := s.decideRequest(state, r)
	record.Decision = auditDecision(decision)
	if !decision.Allowed() {
		s.opts.Audit.Emit(record)
		s.logger.Info("refused a request",
			slog.String("request_id", requestID),
			slog.String("reason", string(decision.Reason)))
		writeDeny(w, statusFor(decision.Reason), decision.Reason, requestID)
		return
	}

	fwd := &forward{host: state.sni, port: state.port, requestID: requestID}
	recorder := &statusRecorder{ResponseWriter: w}
	s.reverse.ServeHTTP(recorder, r.WithContext(context.WithValue(r.Context(), forwardKey{}, fwd)))
	record.Outcome = &audit.Outcome{Status: recorder.status}
	switch {
	case fwd.denied:
		record.Decision = audit.Decision{Verdict: policy.VerdictDeny, Reason: policy.ReasonDenyAlways}
		record.Decision.Error = fwd.err.Error()
	case fwd.err != nil:
		record.Decision = audit.Decision{Verdict: policy.VerdictDeny, Reason: policy.ReasonUpstreamFailed}
		record.Outcome.Error = fwd.err.Error()
	}
	s.opts.Audit.Emit(record)
}

// decideRequest is the per-request decision: the target is well formed, the
// Host header agrees with the SNI, and an endpoint covers the path. An
// endpoint naming a credential denies until a credential source exists.
func (s *Server) decideRequest(state *tunnel, r *http.Request) policy.Decision {
	if r.RequestURI == "*" || !strings.HasPrefix(r.URL.Path, "/") {
		return policy.Decision{Verdict: policy.VerdictDeny, Reason: policy.ReasonMalformedRequest}
	}
	hostname, port, ok := splitAuthority(r.Host)
	if !ok || hostname != state.sni || port != state.port {
		return policy.Decision{Verdict: policy.VerdictDeny, Reason: policy.ReasonHostMismatch}
	}
	decision := s.opts.Matcher.Request(state.sni, r.URL.Path)
	if decision.Allowed() && decision.Endpoint != nil && decision.Endpoint.HasCredential {
		return policy.Decision{
			Verdict: policy.VerdictDeny, Reason: policy.ReasonCredentialUnavailable, Endpoint: decision.Endpoint,
		}
	}
	return decision
}

// rewrite points the outbound request at the SNI on the CONNECT port. It
// keeps the Host header as the workload sent it, because the request
// decision already checked that the header is the SNI.
func rewrite(pr *httputil.ProxyRequest) {
	fwd := forwardFrom(pr.In.Context())
	pr.Out.URL.Scheme = "https"
	pr.Out.URL.Host = net.JoinHostPort(fwd.host, strconv.Itoa(fwd.port))
	pr.Out.Host = pr.In.Host
}

// upstreamError answers an allowed request that produced no response. A dial
// the deny list refused is a policy answer. Anything else is an upstream
// failure.
func (s *Server) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	fwd := forwardFrom(r.Context())
	fwd.err = err
	if _, denied := errors.AsType[*deniedError](err); denied {
		fwd.denied = true
		writeDeny(w, http.StatusForbidden, policy.ReasonDenyAlways, fwd.requestID)
		return
	}
	writeDeny(w, http.StatusBadGateway, policy.ReasonUpstreamFailed, fwd.requestID)
}

// handlePlain refuses a request that reached the proxy in absolute form
// over cleartext. Endpoints name HTTPS destinations, so a cleartext request
// matches none. The deny list still names the more specific reason.
func (s *Server) handlePlain(r *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	requestID := newID()
	host, port, _ := splitAuthority(r.URL.Host)
	decision := s.opts.Matcher.Host(host)
	reason := decision.Reason
	if decision.Allowed() {
		reason = policy.ReasonNoMatchingEndpoint
	}
	s.opts.Audit.Emit(audit.Record{
		RequestID:   requestID,
		Scope:       audit.ScopeRequest,
		Destination: audit.Destination{Host: host, Port: port},
		Request:     &audit.RequestInfo{Method: r.Method, Path: r.URL.Path, Host: r.Host},
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
		Request:     &audit.RequestInfo{Method: r.Method, Path: r.URL.Path, Host: r.Host},
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
	return out
}

// statusFor maps a reason code to the status a refusal carries.
func statusFor(reason policy.Reason) int {
	switch reason {
	case policy.ReasonMalformedRequest, policy.ReasonNotAProxyRequest:
		return http.StatusBadRequest
	case policy.ReasonUpstreamFailed:
		return http.StatusBadGateway
	case policy.ReasonCertificateUnavailable:
		// The handshake fails before any request, so this reason reaches an
		// audit record and never a response.
		return http.StatusInternalServerError
	case policy.ReasonDenyAlways, policy.ReasonNoMatchingEndpoint, policy.ReasonHostMismatch, policy.ReasonNoSNI,
		policy.ReasonCredentialUnavailable:
		return http.StatusForbidden
	case policy.ReasonEndpointAllowed:
		// An allow never becomes a refusal. It is listed here so that a new
		// reason code must choose a status.
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
	r.status = status
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
