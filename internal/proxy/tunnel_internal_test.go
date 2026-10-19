package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/policy"
)

// queryKeyPlacement is a placement the redaction tests share. A query
// placement puts the credential on the wire in its own bytes, so the record
// text a case builds holds the credential itself.
var queryKeyPlacement = credential.Placement{ //nolint:gochecknoglobals // a fixture the tests share
	Kind: credential.KindQuery, Name: "key",
}

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

// unmintableHost has a character an IA5String cannot hold, so
// x509.CreateCertificate refuses the SAN and the authority cannot mint a
// leaf for it. It is the reachable way to fail a mint for a name the policy
// allowed.
const unmintableHost = "аpple.com"

// TestGetCertificateRecordsAMintFailure covers the arm of the handshake
// where policy allows the name and the mint fails anyway. It calls
// GetCertificate directly, because crypto/tls will not keep this server
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

// TestStatusForSandboxReasons pins the statuses of the connect credential
// and sandbox assertion refusals. A 407 asks the client for a credential; the
// sandbox refusals are policy answers.
func TestStatusForSandboxReasons(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 407, statusFor(policy.ReasonProxyUnauthenticated), "an unauthenticated CONNECT")
	assert.Equal(t, 403, statusFor(policy.ReasonSandboxUnidentified), "no verifiable assertion")
	assert.Equal(t, 403, statusFor(policy.ReasonSandboxUnknown), "an unmapped sandbox")
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

// TestATunnelConfigDoesNotResume holds the invariant tlsConfig documents.
// GetCertificate is the only place the SNI is checked and the only place
// state.sni is set, and a resumed handshake skips it. The case drives two
// handshakes through one config, because a config built per tunnel gets its
// own ticket keys and hides a resumption that hoisting the config would
// expose.
func TestATunnelConfigDoesNotResume(t *testing.T) {
	t.Parallel()
	server := handshakeServer(t, &bytes.Buffer{}, time.Minute, &recordingSink{})
	state := &tunnel{connectionID: "conn-1", host: allowedHost, port: 443}
	config := server.tlsConfig(state)
	cache := tls.NewLRUClientSessionCache(8)
	for _, name := range []string{"the first handshake", "the second handshake"} {
		state.sni = ""
		client, peer := net.Pipe()
		serverConn := tls.Server(peer, config)
		served := make(chan error, 1)
		go func() {
			if err := serverConn.HandshakeContext(t.Context()); err != nil {
				served <- err
				return
			}
			_, err := serverConn.Write([]byte("hi"))
			served <- err
		}()
		clientConn := tls.Client(client, &tls.Config{
			ServerName:         allowedHost,
			ClientSessionCache: cache,
			InsecureSkipVerify: true, //nolint:gosec // G402: the case is about resumption, not the chain
			MinVersion:         tls.VersionTLS12,
		})
		require.NoError(t, clientConn.HandshakeContext(t.Context()), "%s", name)
		// The read takes in any session ticket the server sent, so the next
		// handshake would offer it.
		payload := make([]byte, 2)
		_, err := io.ReadFull(clientConn, payload)
		require.NoError(t, err, "read on %s", name)
		require.NoError(t, <-served, "the server side of %s", name)

		assert.False(t, clientConn.ConnectionState().DidResume, "%s resumed", name)
		assert.Equal(t, allowedHost, state.sni, "GetCertificate ran on %s", name)
		// Close the pipe rather than the TLS conn: net.Pipe is unbuffered
		// and nothing reads the close_notify.
		_ = client.Close()
		_ = peer.Close()
	}
}

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

// TestPanicOutcome pins the audit text each panic out of the forward
// produces. The abort is the reverse proxy saying the response did not
// complete; anything else is a defect and says so.
func TestPanicOutcome(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		recovered  any
		requestErr error
		want       string
	}{
		{
			name:      "abort with the request still live",
			recovered: http.ErrAbortHandler,
			want:      "the upstream response body did not complete",
		},
		{
			name:       "abort after the request ended",
			recovered:  http.ErrAbortHandler,
			requestErr: context.Canceled,
			want:       "the client went away or the server stopped before the response completed",
		},
		{
			name:      "an error that is not the abort",
			recovered: io.ErrUnexpectedEOF,
			want:      "the handler panicked: unexpected EOF",
		},
		{
			name:      "a value that is not an error",
			recovered: 42,
			want:      "the handler panicked: 42",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, panicOutcome(tc.recovered, tc.requestErr), "outcome text")
		})
	}
}

// TestStatusRecorderKeepsOnlyFinalStatuses pins that an informational status
// never becomes the recorded one. The reverse proxy forwards a 1xx through
// WriteHeader and writes a 101 onto the hijacked connection, so a 103 before
// an upgrade must leave the recorder empty for the upstream's status.
func TestStatusRecorderKeepsOnlyFinalStatuses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		writes []int
		want   int
	}{
		{name: "an early hint alone", writes: []int{http.StatusEarlyHints}, want: 0},
		{name: "an early hint then a final status", writes: []int{http.StatusEarlyHints, http.StatusOK}, want: http.StatusOK},
		{name: "a final status alone", writes: []int{http.StatusBadGateway}, want: http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			recorder := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
			for _, status := range tc.writes {
				recorder.WriteHeader(status)
			}
			assert.Equal(t, tc.want, recorder.status, "recorded status")
		})
	}
}

// TestInflightSealsOnWait pins the seal. A handler that enters before the
// join is counted and joined, the join admits none after it, and a join
// that ran out of time reports the drain once the counted handlers leave.
func TestInflightSealsOnWait(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		running int
		want    bool
	}{
		{name: "no handler running", running: 0, want: true},
		{name: "one handler running", running: 1, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var handlers inflight
			for range tc.running {
				require.True(t, handlers.enter(), "enter before the wait")
			}
			assert.Equal(t, tc.want, handlers.wait(20*time.Millisecond), "wait within the bound")
			assert.False(t, handlers.enter(), "enter after the wait")
			for range tc.running {
				handlers.leave()
			}
			assert.True(t, handlers.wait(20*time.Millisecond), "wait after the handlers left")
		})
	}
}

// TestInflightWaitJoins pins the join: wait blocks while a handler runs,
// reports the drain when the last one leaves, and gives up at the bound.
// synctest makes the blocking and the clock deterministic.
func TestInflightWaitJoins(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		leaves bool
		want   bool
	}{
		{name: "the handler leaves", leaves: true, want: true},
		{name: "the handler stays past the bound", leaves: false, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				var handlers inflight
				require.True(t, handlers.enter(), "enter before the wait")
				joined := make(chan bool, 1)
				go func() { joined <- handlers.wait(handlerJoinBound) }()
				synctest.Wait()
				select {
				case <-joined:
					t.Fatal("wait returned while a handler runs")
				default:
				}
				if tc.leaves {
					handlers.leave()
				} else {
					time.Sleep(handlerJoinBound)
				}
				synctest.Wait()
				select {
				case got := <-joined:
					assert.Equal(t, tc.want, got, "the join reports the drain")
				default:
					t.Fatal("wait did not return")
				}
			})
		})
	}
}

// TestRewriteClearsTheUserinfo pins the invariant that no outbound request
// keeps the userinfo the workload put in the request line, whatever the
// endpoint names. The basic writer clears it too. This test covers the
// placements that do not write an Authorization header, and an endpoint with
// no credential.
func TestRewriteClearsTheUserinfo(t *testing.T) {
	t.Parallel()
	const secret = "query-sekrit" //nolint:gosec // G101: a test fixture, not a credential
	tests := []struct {
		name      string
		placement credential.Placement
		// noCredential drives an endpoint the document gave no credential,
		// which reaches rewrite with no writer.
		noCredential bool
	}{
		{
			name: "a header placement",
			placement: credential.Placement{
				Kind: credential.KindHeader, Name: "Authorization", Template: "Bearer " + credential.Token,
			},
		},
		{name: "a query placement", placement: queryKeyPlacement},
		{name: "a basic placement", placement: credential.Placement{Kind: credential.KindBasic, User: "x-access-token"}},
		{name: "an endpoint with no credential", noCredential: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := handshakeServer(t, &bytes.Buffer{}, time.Minute, &recordingSink{})
			fwd := &forward{host: allowedHost, port: 443, requestID: "req-1"}
			if !tc.noCredential {
				writer, err := credential.NewWriter(tc.placement)
				require.NoError(t, err, "NewWriter")
				fwd.setCredential(writer, tc.placement, secret)
			}
			in := httptest.NewRequestWithContext(
				context.WithValue(t.Context(), forwardKey{}, fwd),
				http.MethodGet, "https://"+allowedHost+"/repo.git?q=here", nil,
			)
			in.URL.User = url.UserPassword("alice", "hunter2")
			out := in.Clone(in.Context())
			require.NotNil(t, out.URL.User, "the case must start with userinfo on the outbound request")

			server.rewrite(&httputil.ProxyRequest{In: in, Out: out})

			assert.Nil(t, out.URL.User, "the userinfo on the outbound request line")
			assert.NotContains(t, out.URL.String(), "hunter2", "the outbound URL holds the workload password")
		})
	}
}

// textError is an error whose text is exactly what a case gives it, so a
// case can put a credential in the middle of it.
type textError string

func (e textError) Error() string { return string(e) }

// TestEmitForwardedRedactsTheCredential covers every arm that puts upstream
// text on a record. A header placement puts the credential on the wire as
// the workload would read it, and a query placement percent-encodes it into
// the URL, so an error naming that URL shows the escaped form.
func TestEmitForwardedRedactsTheCredential(t *testing.T) {
	t.Parallel()
	const secret = "a b=c+d"
	escaped := url.QueryEscape(secret)
	require.NotEqual(t, secret, escaped, "the fixture must escape to something else")
	rawText := `Get "https://maps.example/geocode?key=` + secret + `": refused`
	escapedText := `Get "https://maps.example/geocode?key=` + escaped + `": refused`
	const wantText = `Get "https://maps.example/geocode?key=` + credential.Marker + `": refused`

	// The raw credential does not appear in its basic form, so a record
	// holding the basic form is redacted only when the forward knows it.
	basicPlacement := credential.Placement{Kind: credential.KindBasic, User: "x-access-token"}
	basicText := `Get "https://git.example/repo.git": Basic ` +
		base64.StdEncoding.EncodeToString([]byte(basicPlacement.User+":"+secret)) + " refused"
	const wantBasicText = `Get "https://git.example/repo.git": Basic ` + credential.Marker + " refused"

	withSecret := func(fwd *forward, placement credential.Placement) *forward {
		fwd.setCredential(nil, placement, secret)
		return fwd
	}
	deniedError := func(text string) *forward {
		return withSecret(&forward{denied: true, err: textError(text)}, queryKeyPlacement)
	}
	upstreamError := func(text string) *forward {
		return withSecret(&forward{err: textError(text)}, queryKeyPlacement)
	}
	tests := []struct {
		name      string
		fwd       *forward
		recovered any
		// field reads the record text the arm writes.
		field func(audit.Record) string
		want  string
	}{
		{
			name: "a refusal on the upstream leg, raw", fwd: deniedError(rawText),
			field: decisionError, want: wantText,
		},
		{
			name: "a refusal on the upstream leg, query escaped", fwd: deniedError(escapedText),
			field: decisionError, want: wantText,
		},
		{
			name: "an upstream failure, raw", fwd: upstreamError(rawText),
			field: outcomeError, want: wantText,
		},
		{
			name: "an upstream failure, query escaped", fwd: upstreamError(escapedText),
			field: outcomeError, want: wantText,
		},
		{
			name: "a panic in the handler, raw", fwd: withSecret(&forward{}, queryKeyPlacement),
			recovered: textError(rawText),
			field:     outcomeError, want: "the handler panicked: " + wantText,
		},
		{
			name: "a panic in the handler, query escaped", fwd: withSecret(&forward{}, queryKeyPlacement),
			recovered: escapedText,
			field:     outcomeError, want: "the handler panicked: " + wantText,
		},
		{
			name:  "an upstream failure naming the basic credentials",
			fwd:   withSecret(&forward{err: textError(basicText)}, basicPlacement),
			field: outcomeError, want: wantBasicText,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sink := &recordingSink{}
			server := handshakeServer(t, &bytes.Buffer{}, time.Minute, sink)
			recorder := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/geocode", nil)

			server.emitForwarded(audit.Record{Scope: audit.ScopeRequest}, tc.fwd, recorder, request, tc.recovered)

			records := sink.all()
			require.Len(t, records, 1, "emitForwarded emits one record")
			assert.Equal(t, tc.want, tc.field(records[0]), "the record text")
			line, err := json.Marshal(records[0])
			require.NoError(t, err, "marshal the record")
			assert.Contains(t, string(line), credential.Marker, "the record says the text was redacted")
			assert.NotContains(t, string(line), secret, "the record holds the credential")
			assert.NotContains(t, string(line), escaped, "the record holds the escaped credential")
		})
	}
}

func decisionError(record audit.Record) string { return record.Decision.Error }

func outcomeError(record audit.Record) string {
	if record.Outcome == nil {
		return ""
	}
	return record.Outcome.Error
}

// failingWriter reports an error from every write. No writer this build
// ships can fail on a request that reached the forward, so the contract a
// later placement writer inherits needs a double to exercise it.
type failingWriter struct{ err error }

func (w failingWriter) Write(*http.Request, string) error { return w.err }

// countingRoundTripper answers every round trip that reaches the upstream
// and counts them.
type countingRoundTripper struct{ trips atomic.Int64 }

func (t *countingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	t.trips.Add(1)
	return &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{}, Body: http.NoBody, Request: r,
	}, nil
}

// TestAFailedCredentialWriteDenies verifies that a failed placement write
// denies the request instead of forwarding it without a credential. The case
// drives the reverse proxy and audit record after the request is allowed.
func TestAFailedCredentialWriteDenies(t *testing.T) {
	t.Parallel()
	const secret = "query-sekrit" //nolint:gosec // G101: a test fixture, not a credential
	tests := []struct {
		name       string
		writer     credential.Writer
		wantStatus int
		wantReason policy.Reason
		wantTrips  int64
		// wantVerdict is the verdict on the record. An allowed forward
		// keeps the verdict the decision put on the record.
		wantVerdict policy.Verdict
	}{
		{
			name:       "the writer reports an error",
			writer:     failingWriter{err: textError("the request query does not parse: key=" + secret)},
			wantStatus: http.StatusForbidden, wantReason: policy.ReasonCredentialUnavailable,
			wantTrips: 0, wantVerdict: policy.VerdictDeny,
		},
		{
			name:       "the writer succeeds",
			writer:     workingWriter{},
			wantStatus: http.StatusOK, wantReason: policy.ReasonEndpointAllowed,
			wantTrips: 1, wantVerdict: policy.VerdictAllow,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			logs := &bytes.Buffer{}
			sink := &recordingSink{}
			server := handshakeServer(t, logs, time.Minute, sink)
			upstream := &countingRoundTripper{}
			server.reverse.Transport = refuseUnwritten{next: upstream}

			fwd := &forward{host: allowedHost, port: 443, requestID: "req-1"}
			fwd.setCredential(tc.writer, queryKeyPlacement, secret)
			request := httptest.NewRequestWithContext(
				context.WithValue(t.Context(), forwardKey{}, fwd),
				http.MethodGet, "https://"+allowedHost+"/geocode?q=here", nil,
			)
			request.Host = allowedHost + ":443"
			recorder := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
			server.reverse.ServeHTTP(recorder, request)
			server.emitForwarded(audit.Record{
				Scope:    audit.ScopeRequest,
				Decision: audit.Decision{Verdict: policy.VerdictAllow, Reason: policy.ReasonEndpointAllowed},
			}, fwd, recorder, request, nil)

			written, ok := recorder.ResponseWriter.(*httptest.ResponseRecorder)
			require.True(t, ok, "the recorder wraps an httptest recorder")
			assert.Equal(t, tc.wantStatus, written.Code, "the status the client receives")
			assert.Equal(t, tc.wantTrips, upstream.trips.Load(), "round trips that reached the upstream")

			records := sink.all()
			require.Len(t, records, 1, "the request emits one record")
			assert.Equal(t, tc.wantVerdict, records[0].Decision.Verdict, "record verdict")
			assert.Equal(t, tc.wantReason, records[0].Decision.Reason, "record reason")
			if tc.wantVerdict == policy.VerdictDeny {
				assert.Equal(t, string(tc.wantReason), written.Header().Get(HeaderReason), "the deny reason header")
				assert.Equal(t, "req-1", written.Header().Get(HeaderRequestID), "the request id header")
				assert.Equal(t, "egress-proxy: "+string(tc.wantReason)+"\n", written.Body.String(), "the deny body")
				assert.NotEmpty(t, records[0].Decision.Error, "the record says why the write failed")
			}
			line, err := json.Marshal(records[0])
			require.NoError(t, err, "marshal the record")
			assert.NotContains(t, string(line), secret, "an audit record holds the credential")
			assert.NotContains(t, logs.String(), secret, "a log line holds the credential")
		})
	}
}

// workingWriter stands in for a placement writer that writes.
type workingWriter struct{}

func (workingWriter) Write(out *http.Request, secret string) error {
	out.Header.Set("Authorization", "Bearer "+secret)
	return nil
}
