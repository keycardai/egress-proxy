package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/internal/policy"
)

// recordingSink collects the records a test emits.
type recordingSink struct {
	mu      sync.Mutex
	records []audit.Record
}

func (s *recordingSink) Emit(record audit.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, record)
}

func (s *recordingSink) all() []audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Record(nil), s.records...)
}

// unmintableHost carries a character an IA5String cannot hold, so
// x509.CreateCertificate refuses the SAN and the authority cannot mint a
// leaf for it. It is the reachable way to fail a mint for a name the policy
// allowed.
const unmintableHost = "аpple.com"

// TestGetCertificateRecordsAMintFailure covers the arm of the handshake
// where policy allows the name and the mint fails anyway. It calls
// GetCertificate directly, because crypto/tls will not carry this server
// name over the wire.
func TestGetCertificateRecordsAMintFailure(t *testing.T) {
	t.Parallel()
	deny, err := policy.NewDenyList(nil, nil)
	require.NoError(t, err, "NewDenyList")
	matcher, err := policy.Compile([]policy.Endpoint{{Host: unmintableHost, Port: 443, PathPrefix: "/"}}, deny)
	require.NoError(t, err, "Compile")
	authority, err := ca.New(ca.Options{})
	require.NoError(t, err, "ca.New")
	store, err := ca.NewStore(authority, 4)
	require.NoError(t, err, "ca.NewStore")
	sink := &recordingSink{}
	server, err := New(Options{
		Matcher:       matcher,
		Certificates:  store,
		Audit:         sink,
		UpstreamRoots: x509.NewCertPool(),
	})
	require.NoError(t, err, "New")

	state := &tunnel{connectionID: "conn-1", host: unmintableHost, port: 443}
	certificate, err := server.tlsConfig(state).GetCertificate(&tls.ClientHelloInfo{ServerName: unmintableHost})
	require.Error(t, err, "GetCertificate for a name the authority cannot mint")
	assert.Nil(t, certificate, "a failed mint yields no certificate")

	records := sink.all()
	require.Len(t, records, 1, "the failure emits one record")
	record := records[0]
	assert.Equal(t, audit.ScopeConnection, record.Scope, "record scope")
	assert.Equal(t, "conn-1", record.ConnectionID, "record connection")
	assert.Equal(t, policy.VerdictDeny, record.Decision.Verdict, "record verdict")
	assert.Equal(t, policy.ReasonCertificateUnavailable, record.Decision.Reason, "record reason")
	assert.NotEmpty(t, record.Decision.Error, "the record says why the mint failed")
	assert.Equal(t, unmintableHost, record.Destination.SNI, "record SNI")
}

// TestStatusForCertificateUnavailable pins the status the new reason maps
// to. The reason never reaches a response, so nothing else would notice a
// switch arm that forgot it.
func TestStatusForCertificateUnavailable(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 500, statusFor(policy.ReasonCertificateUnavailable), "the status for a failed mint")
}

// handshakeServer builds a proxy that allows allowedHost, logs into buf, and
// gives a tunnel handshake the budget the case asks for.
func handshakeServer(t *testing.T, buf *bytes.Buffer, budget time.Duration, sink audit.Sink) *Server {
	t.Helper()
	deny, err := policy.NewDenyList(nil, nil)
	require.NoError(t, err, "NewDenyList")
	matcher, err := policy.Compile([]policy.Endpoint{{Host: allowedHost, Port: 443, PathPrefix: "/"}}, deny)
	require.NoError(t, err, "Compile")
	authority, err := ca.New(ca.Options{})
	require.NoError(t, err, "ca.New")
	store, err := ca.NewStore(authority, 4)
	require.NoError(t, err, "ca.NewStore")
	server, err := New(Options{
		Matcher:          matcher,
		Certificates:     store,
		Audit:            sink,
		UpstreamRoots:    x509.NewCertPool(),
		HandshakeTimeout: budget,
		Logger:           slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	require.NoError(t, err, "New")
	return server
}

// allowedHost is the CONNECT authority the handshake cases tunnel to.
const allowedHost = "upstream.test"

// TestHandshakeFailureLogging covers both arms of logHandshakeFailure. A
// handshake that spends the whole budget holds a connection slot for that
// long, which is the case an operator has to see, so it warns. A client that
// fails the handshake outright gives the slot back at once and only informs.
// Neither arm emits an audit record.
func TestHandshakeFailureLogging(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		send      string
		budget    time.Duration
		wantLevel string
		wantMsg   string
	}{
		{
			name:      "the budget runs out",
			budget:    50 * time.Millisecond,
			wantLevel: "WARN",
			wantMsg:   "tunnel handshake timed out and held a connection slot for the whole budget",
		},
		{
			name:      "a cleartext preface",
			send:      "GET / HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
			budget:    time.Minute,
			wantLevel: "INFO",
			wantMsg:   "tunnel handshake failed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			sink := &recordingSink{}
			server := handshakeServer(t, &buf, tc.budget, sink)
			client, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			if tc.send != "" {
				// net.Pipe is unbuffered, so the write finishes only as the
				// handshake reads it and the close below unblocks the rest.
				go func() { _, _ = io.WriteString(peer, tc.send) }()
			}

			server.handshake(client, &tunnel{connectionID: "conn-1", host: allowedHost, port: 443})

			var entry map[string]any
			require.NoError(t, json.Unmarshal(buf.Bytes(), &entry), "the handshake logged %q", buf.String())
			assert.Equal(t, tc.wantLevel, entry["level"], "log level")
			assert.Equal(t, tc.wantMsg, entry["msg"], "log message")
			assert.Equal(t, "conn-1", entry["connection_id"], "the entry names the connection")
			assert.Equal(t, allowedHost+":443", entry["authority"], "the entry names the authority")
			assert.NotEmpty(t, entry["error"], "the entry says why the handshake failed")
			if tc.wantLevel == "WARN" {
				budget, ok := entry["handshake_timeout"].(float64)
				require.True(t, ok, "handshake_timeout is %T", entry["handshake_timeout"])
				assert.Equal(t, tc.budget.Nanoseconds(), int64(budget),
					"the warning names the budget the slot was held for")
			}
			assert.Empty(t, sink.all(), "a handshake failure emits no audit record")
		})
	}
}
