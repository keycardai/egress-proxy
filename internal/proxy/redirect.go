package proxy

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/policy"
)

// Redirected is what the transparent frontend recovered from one connection
// a REDIRECT rule sent to this process.
type Redirected struct {
	// Host is the name the client used: the server name from the
	// ClientHello, or the Host header on a cleartext connection.
	Host string
	// Port is the port the connection was opened to, before the redirect.
	Port int
	// Address is the destination the connection was opened to, before the
	// redirect. It is recorded, never dialled. The proxy re-resolves Host,
	// so a name that resolves into a denied range is still caught by the
	// dial guard.
	Address netip.AddrPort
	// Cleartext says the connection is HTTP rather than TLS.
	Cleartext bool
	// Refusal is a reason the frontend settled before this call. A
	// connection with one is denied with that reason and read no
	// further.
	Refusal policy.Reason
}

// drainer is a connection that reads what the client is still sending before
// it closes. A socket closed with unread data in its receive buffer sends
// RST, and the RST discards the refusal the workload was meant to read. The
// transparent frontend supplies one.
type drainer interface {
	DrainOnClose()
}

// ServeRedirected takes over a connection the transparent frontend recovered
// a destination for and makes the connection-scoped decision on it. An
// allowed connection goes through the same TLS termination and the same
// intake as an allowed CONNECT tunnel.
//
// NEVER synthesize a CONNECT here. goproxy handles the CONNECT line and
// cannot serve the loop inside a tunnel.
//
// The call returns once the decision is made. It takes ownership of the
// connection either way: a refusal closes it, and an allow passes it to the
// handshake goroutine.
func (s *Server) ServeRedirected(client net.Conn, dst Redirected) {
	state := &tunnel{
		connectionID: newID(),
		host:         dst.Host,
		port:         dst.Port,
		address:      addressText(dst.Address),
	}
	decision := s.redirectedDecision(dst)
	if decision.Allowed() {
		go s.handshake(client, state)
		return
	}
	s.opts.Audit.Emit(audit.Record{
		ConnectionID: state.connectionID,
		Scope:        audit.ScopeConnection,
		Destination:  audit.Destination{Host: state.host, Port: state.port, OriginalAddress: state.address},
		Decision:     auditDecision(decision),
	})
	s.logger.Info("refused a redirected connection",
		slog.String("connection_id", state.connectionID),
		slog.String("host", state.host),
		slog.Int("port", state.port),
		slog.String("address", state.address),
		slog.Bool("cleartext", dst.Cleartext),
		slog.String("reason", string(decision.Reason)))
	// A cleartext client reads an HTTP response, so the refusal names its
	// reason there. A TLS client is waiting for a ServerHello and has
	// nowhere to read one, so its connection is closed unanswered.
	if dst.Cleartext {
		s.writeDenyConn(client, statusFor(decision.Reason), decision.Reason, state.connectionID)
	}
	if conn, ok := client.(drainer); ok {
		conn.DrainOnClose()
	}
	s.closeConn(client, state, "refused")
}

// redirectedDecision answers a redirected connection. A reason the frontend
// settled wins, because the frontend could not read the destination the
// endpoint list matches on.
//
// The matcher runs before the cleartext rule so that a denied host keeps the
// more specific reason. Only an allow becomes cleartext_not_forwarded.
func (s *Server) redirectedDecision(dst Redirected) policy.Decision {
	if dst.Refusal != "" {
		return policy.Decision{Verdict: policy.VerdictDeny, Reason: dst.Refusal}
	}
	decision := s.opts.Matcher.Connection(dst.Host, dst.Port)
	if dst.Cleartext && decision.Allowed() {
		return policy.Decision{Verdict: policy.VerdictDeny, Reason: policy.ReasonCleartextNotForwarded}
	}
	return decision
}

// writeDenyConn writes a refusal to a raw connection, for a cleartext client
// that sent no request the proxy will answer through net/http.
func (s *Server) writeDenyConn(conn net.Conn, status int, reason policy.Reason, connectionID string) {
	body := "egress-proxy: " + string(reason) + "\n"
	resp := &http.Response{
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}
	denyHeaders(resp.Header, reason, connectionID, "")
	if err := conn.SetWriteDeadline(time.Now().Add(denyWriteBound)); err != nil {
		return
	}
	if err := resp.Write(conn); err != nil {
		s.logger.Debug("the refusal did not reach the client",
			slog.String("connection_id", connectionID),
			slog.String("error", err.Error()))
	}
}

// denyWriteBound bounds the write of a refusal to a client that is not
// reading.
const denyWriteBound = 5 * time.Second

// addressText renders a recovered destination, empty for the zero value a
// CONNECT tunnel has.
func addressText(addr netip.AddrPort) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}
