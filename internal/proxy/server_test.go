package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/internal/policy"
	"github.com/keycardai/egress-proxy/internal/proxy"
)

// upstreamHost is the name every test reaches. It resolves to loopback on
// every platform, and loopback is excepted from the deny list in the
// harness document. A TLS client sends no SNI for an IP literal, so the
// tests need a name.
const upstreamHost = "localhost"

// findTimeout bounds how long find waits for a record that never arrives.
// It only decides how fast a broken test fails. A record the proxy is about
// to write wakes find as soon as Emit runs, so a passing test never waits.
const findTimeout = time.Second

// emitGate holds one Emit open: Emit closes entered for the first record
// match accepts and then waits for release. A test sets it to prove what
// waits on that emit. match must accept exactly one record.
type emitGate struct {
	match   func(audit.Record) bool
	entered chan struct{}
	release chan struct{}
}

func newEmitGate(match func(audit.Record) bool) *emitGate {
	return &emitGate{match: match, entered: make(chan struct{}), release: make(chan struct{})}
}

// memorySink keeps records for assertions and wakes find when one arrives.
type memorySink struct {
	mu      sync.Mutex
	records []audit.Record
	// arrived closes on the next Emit. Emit replaces it rather than reusing
	// it, so every waiter holding the old channel wakes exactly once.
	arrived chan struct{}
	// gate is set before Run starts and read by every emitting goroutine.
	gate *emitGate
}

func newMemorySink() *memorySink {
	return &memorySink{arrived: make(chan struct{})}
}

func (m *memorySink) Emit(record audit.Record) {
	// The gate waits before the mutex. A held emit must not stop the records
	// another goroutine writes or a test reads.
	if m.gate != nil && m.gate.match(record) {
		close(m.gate.entered)
		<-m.gate.release
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, record)
	close(m.arrived)
	m.arrived = make(chan struct{})
}

// snapshot returns the records so far and the channel that closes when the
// next one arrives. One critical section covers both, so a record that lands
// between the read and the wait closes the channel the caller already holds
// rather than going unnoticed.
func (m *memorySink) snapshot() ([]audit.Record, <-chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records), m.arrived
}

// find returns the first record matching the predicate, waiting for one that
// has not arrived yet. A request-scoped record is emitted after the response
// is written, so the test can read the response first.
func (m *memorySink) find(t *testing.T, what string, match func(audit.Record) bool) audit.Record {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), findTimeout)
	defer cancel()
	for {
		records, arrived := m.snapshot()
		for _, record := range records {
			if match(record) {
				return record
			}
		}
		select {
		case <-arrived:
		case <-ctx.Done():
			require.FailNow(t, "no record found", "for %s after %s, among %+v", what, findTimeout, records)
		}
	}
}

// byReason matches a record by scope and reason. Use it only where one
// record in the test carries that pair.
func byReason(scope audit.Scope, reason policy.Reason) func(audit.Record) bool {
	return func(record audit.Record) bool {
		return record.Scope == scope && record.Decision.Reason == reason
	}
}

// byConnection matches the connection-scoped record with that id and
// reason.
func byConnection(connectionID string, reason policy.Reason) func(audit.Record) bool {
	return func(record audit.Record) bool {
		return record.Scope == audit.ScopeConnection && record.ConnectionID == connectionID &&
			record.Decision.Reason == reason
	}
}

// byRequest matches the request-scoped record with that id.
func byRequest(requestID string) func(audit.Record) bool {
	return func(record audit.Record) bool {
		return record.Scope == audit.ScopeRequest && record.RequestID == requestID
	}
}

// upstream is a TLS server for upstreamHost that counts connections and
// echoes the request line.
type upstream struct {
	server      *httptest.Server
	port        int
	connections atomic.Int64
	// release gates the second chunk of the streaming handler.
	release chan struct{}
}

func newUpstream(t *testing.T) (*upstream, *ca.Authority) {
	t.Helper()
	authority, err := ca.New(ca.Options{CommonName: "upstream test CA"})
	require.NoError(t, err)
	leaf, err := authority.Leaf(upstreamHost)
	require.NoError(t, err)
	up := &upstream{release: make(chan struct{})}
	up.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if strings.HasPrefix(r.URL.Path, "/stall/") {
			// Never write a head. The handler returns once the proxy gives
			// up and closes the connection, so Close does not block.
			<-r.Context().Done()
			return
		}
		if strings.HasPrefix(r.URL.Path, "/stream/") {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: first\n\n")
			_ = http.NewResponseController(w).Flush()
			<-up.release
			_, _ = io.WriteString(w, "data: second\n\n")
			return
		}
		//nolint:gosec // G705: a fixture echoing as text/plain
		fmt.Fprintf(w, "%s %s host=%s", r.Method, r.URL.RequestURI(), r.Host)
	}))
	up.server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			up.connections.Add(1)
		}
	}
	up.server.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12}
	up.server.StartTLS()
	t.Cleanup(up.server.Close)
	_, portText, err := net.SplitHostPort(up.server.Listener.Addr().String())
	require.NoError(t, err)
	up.port, _ = strconv.Atoi(portText)
	return up, authority
}

// upgradeHandler answers /ok/upgrade with a protocol switch and then echoes
// what the client sends. A test installs it over the upstream's handler.
func upgradeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ok/upgrade" {
		http.NotFound(w, r)
		return
	}
	const switching = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n"
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	if _, err := brw.WriteString(switching); err != nil {
		return
	}
	if err := brw.Flush(); err != nil {
		return
	}
	// The echo reads through brw, which may already hold bytes that arrived
	// with the request head.
	_, _ = io.Copy(conn, brw)
}

// harness is a proxy in front of the upstream.
type harness struct {
	authority *ca.Authority
	store     *ca.Store
	sink      *memorySink
	upstream  *upstream
	addr      string
	server    *proxy.Server
}

type harnessOptions struct {
	// loopbackDenied leaves loopback on the deny list, so the upstream name
	// resolves into a denied range.
	loopbackDenied        bool
	maxConnections        int
	idleTimeout           time.Duration
	responseHeaderTimeout time.Duration
	// unstarted leaves Run to the test.
	unstarted bool
}

func start(t *testing.T, opts harnessOptions) *harness {
	t.Helper()
	up, upstreamCA := newUpstream(t)
	var exceptions []netip.Prefix
	if !opts.loopbackDenied {
		exceptions = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	}
	deny, err := policy.NewDenyList(nil, exceptions)
	require.NoError(t, err)
	matcher, err := policy.Compile([]policy.Endpoint{
		{Host: upstreamHost, PathPrefix: "/ok/"},
		{Host: upstreamHost, PathPrefix: "/stream/"},
		{Host: upstreamHost, PathPrefix: "/cred/", HasCredential: true},
		{Host: upstreamHost, PathPrefix: "/stall/"},
	}, deny)
	require.NoError(t, err)
	authority, err := ca.New(ca.Options{})
	require.NoError(t, err)
	store, err := ca.NewStore(authority, 16)
	require.NoError(t, err)
	sink := newMemorySink()
	server, err := proxy.New(proxy.Options{
		Matcher:      matcher,
		Certificates: store,
		Audit: audit.NewStamped(sink, audit.Stamp{
			SandboxID: "sbx-test", DocumentDigest: "sha256:doc", ConfigDigest: "sha256:cfg",
		}, nil),
		UpstreamRoots:         upstreamCA.Pool(),
		MaxConnections:        opts.maxConnections,
		IdleTimeout:           opts.idleTimeout,
		ResponseHeaderTimeout: opts.responseHeaderTimeout,
		ShutdownGrace:         time.Second,
	})
	require.NoError(t, err)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	if opts.unstarted {
		_ = listener.Close()
	} else {
		// Every test also proves that cancelling the run context stops the
		// proxy cleanly: Run must return nil once the test is done.
		ctx, cancel := context.WithCancel(t.Context())
		var group errgroup.Group
		group.Go(func() error { return server.Run(ctx, listener) })
		t.Cleanup(func() {
			cancel()
			assert.NoError(t, group.Wait(), "Run after cancellation")
		})
	}
	return &harness{
		authority: authority, store: store, sink: sink, upstream: up,
		addr: listener.Addr().String(), server: server,
	}
}

// running is a Run the test controls: cancel ends its context, finished
// closes once Run returns, and err is Run's result, valid after finished.
type running struct {
	cancel   context.CancelFunc
	finished chan struct{}
	err      error
}

// run starts Run for a harness built with unstarted, on a listener of its
// own, and points the harness at it. The cleanup cancels and waits, so every
// test that calls run also proves Run returns nil after a cancellation.
func (h *harness) run(t *testing.T) *running {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	h.addr = listener.Addr().String()
	ctx, cancel := context.WithCancel(t.Context())
	run := &running{cancel: cancel, finished: make(chan struct{})}
	go func() {
		run.err = h.server.Run(ctx, listener)
		close(run.finished)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-run.finished:
			assert.NoError(t, run.err, "Run after cancellation")
		case <-time.After(5 * time.Second):
			assert.Fail(t, "shutdown did not finish")
		}
	})
	return run
}

// reply is a response with its body read and closed.
type reply struct {
	status int
	header http.Header
	body   string
	// closed says the server asked for the connection to close.
	closed bool
}

func (r reply) reason() policy.Reason {
	return policy.Reason(r.header.Get(proxy.HeaderReason))
}

func (r reply) id() string {
	return r.header.Get(proxy.HeaderRequestID)
}

// readReply drains and closes a response.
func readReply(t *testing.T, resp *http.Response, err error) (reply, error) {
	t.Helper()
	if err != nil {
		return reply{}, fmt.Errorf("round trip: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return reply{status: resp.StatusCode, header: resp.Header, body: string(body), closed: resp.Close}, nil
}

// client is an HTTP client that trusts the minted CA and uses the proxy.
func (h *harness) client() *http.Client {
	proxyURL := &url.URL{Scheme: "http", Host: h.addr}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: h.authority.Pool(), MinVersion: tls.VersionTLS12},
		},
	}
}

// upstreamAuthority is host:port of the upstream, the CONNECT target.
func (h *harness) upstreamAuthority() string {
	return net.JoinHostPort(upstreamHost, strconv.Itoa(h.upstream.port))
}

func (h *harness) upstreamURL(path string) string {
	return "https://" + h.upstreamAuthority() + path
}

// get fetches a URL through the proxy with the trusting client.
func (h *harness) get(t *testing.T, rawURL string) (reply, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	//nolint:bodyclose // readReply closes it
	resp, err := h.client().Do(req)
	return readReply(t, resp, err)
}

// dial opens a raw connection to the proxy with a deadline.
func (h *harness) dial(t *testing.T) net.Conn {
	t.Helper()
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", h.addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

// connect sends a CONNECT for authority on a raw connection and returns the
// proxy's answer.
func (h *harness) connect(t *testing.T, conn net.Conn, reader *bufio.Reader, authority string) reply {
	t.Helper()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	return readConnect(t, reader)
}

// readConnect reads the answer to a CONNECT. A 200 carries no body, and what
// follows on the connection is the tunnel, so readConnect drains a refusal
// only.
func readConnect(t *testing.T, reader *bufio.Reader) reply {
	t.Helper()
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	require.NoError(t, err, "read the CONNECT response")
	if resp.StatusCode == http.StatusOK {
		_ = resp.Body.Close()
		return reply{status: resp.StatusCode, header: resp.Header}
	}
	answer, err := readReply(t, resp, nil)
	require.NoError(t, err)
	return answer
}

// rawTunnel opens a CONNECT tunnel to the upstream authority and returns the
// raw connection after the 200.
func (h *harness) rawTunnel(t *testing.T) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn := h.dial(t)
	reader := bufio.NewReader(conn)
	answer := h.connect(t, conn, reader, h.upstreamAuthority())
	require.Equal(t, http.StatusOK, answer.status, "CONNECT %s", h.upstreamAuthority())
	return conn, reader
}

// tlsTunnel is rawTunnel followed by a handshake naming serverName.
func (h *harness) tlsTunnel(t *testing.T, serverName string) (*tls.Conn, error) {
	t.Helper()
	conn, _ := h.rawTunnel(t)
	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:            h.authority.Pool(),
		ServerName:         serverName,
		InsecureSkipVerify: serverName == "", //nolint:gosec // G402: the no-SNI case cannot verify a name it did not send
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(t.Context()); err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	return tlsConn, nil
}

// roundTrip writes a raw request on a connection and reads the response.
func (h *harness) roundTrip(t *testing.T, conn io.ReadWriter, reader *bufio.Reader, raw string) reply {
	t.Helper()
	_, err := io.WriteString(conn, raw)
	require.NoError(t, err)
	//nolint:bodyclose // readReply closes it
	resp, readErr := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	answer, readErr := readReply(t, resp, readErr)
	require.NoError(t, readErr, "read the response to %q", raw)
	return answer
}

// upgrade drives one request the upstream answers with a protocol switch and
// returns the connection carrying it and the reader over that connection.
// The reader holds anything the upstream sent after the 101.
func (h *harness) upgrade(t *testing.T) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := h.tlsTunnel(t, upstreamHost)
	require.NoError(t, err)
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	_, err = io.WriteString(conn, "GET /ok/upgrade HTTP/1.1\r\nHost: "+h.upstreamAuthority()+
		"\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	//nolint:bodyclose // a 101 response carries http.NoBody
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	require.NoError(t, err, "read the answer to the upgrade request")
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode, "the upstream switched protocols")
	_, err = io.WriteString(conn, "ping\n")
	require.NoError(t, err)
	echoed, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "ping\n", echoed, "the upgraded connection carries bytes both ways")
	return conn, reader
}

func TestAllowedRequestReachesTheUpstream(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{})
	answer, err := h.get(t, h.upstreamURL("/ok/echo?x=1"))
	require.NoError(t, err, "GET through the proxy")
	assert.Equal(t, http.StatusOK, answer.status, "status")
	assert.Equal(t, "GET /ok/echo?x=1 host="+h.upstreamAuthority(), answer.body, "what the upstream echoed")
	assert.Equal(t, int64(1), h.upstream.connections.Load(), "upstream connections")
	assert.Equal(t, int64(1), h.store.Mints(), "leaves minted")

	connection := h.sink.find(t, "the allowed connection", byReason(audit.ScopeConnection, policy.ReasonEndpointAllowed))
	wantConnection := audit.Record{
		TS: connection.TS, SandboxID: "sbx-test", Document: audit.DocumentRef{Digest: "sha256:doc"},
		Config: audit.ConfigRef{Digest: "sha256:cfg"}, ConnectionID: connection.ConnectionID,
		Scope:       audit.ScopeConnection,
		Destination: audit.Destination{Host: upstreamHost, Port: h.upstream.port},
		// No endpoint: the connection decision took no path into account.
		Decision: audit.Decision{Verdict: policy.VerdictAllow, Reason: policy.ReasonEndpointAllowed},
	}
	assert.NotEmpty(t, connection.ConnectionID, "the connection record carries an id")
	assert.Equal(t, wantConnection, connection, "connection record")
	request := h.sink.find(t, "the allowed request", byReason(audit.ScopeRequest, policy.ReasonEndpointAllowed))
	wantRequest := audit.Record{
		TS: request.TS, SandboxID: "sbx-test", Document: audit.DocumentRef{Digest: "sha256:doc"},
		Config: audit.ConfigRef{Digest: "sha256:cfg"}, ConnectionID: connection.ConnectionID,
		RequestID: request.RequestID, Scope: audit.ScopeRequest,
		Destination: audit.Destination{Host: upstreamHost, Port: h.upstream.port, SNI: upstreamHost},
		Request:     &audit.RequestInfo{Method: http.MethodGet, Path: "/ok/echo", Host: h.upstreamAuthority()},
		Decision: audit.Decision{
			Verdict: policy.VerdictAllow, Reason: policy.ReasonEndpointAllowed, Endpoint: "localhost/ok/",
		},
		Outcome: &audit.Outcome{Status: http.StatusOK},
	}
	assert.NotEmpty(t, request.RequestID, "the request record carries an id")
	assert.Equal(t, wantRequest, request, "request record")
}

func TestDeniedConnections(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{})
	tests := []struct {
		name       string
		authority  string
		wantStatus int
		wantReason policy.Reason
	}{
		{
			name: "an unlisted host", authority: "denied.invalid:443",
			wantStatus: http.StatusForbidden, wantReason: policy.ReasonNoMatchingEndpoint,
		},
		{
			name: "the metadata address", authority: "169.254.169.254:80",
			wantStatus: http.StatusForbidden, wantReason: policy.ReasonDenyAlways,
		},
		{
			name: "a DoH resolver", authority: "dns.google:443",
			wantStatus: http.StatusForbidden, wantReason: policy.ReasonDenyAlways,
		},
		{
			name: "a bad port", authority: "denied.invalid:99999",
			wantStatus: http.StatusBadRequest, wantReason: policy.ReasonMalformedRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn := h.dial(t)
			answer := h.connect(t, conn, bufio.NewReader(conn), tc.authority)
			assert.Equal(t, tc.wantStatus, answer.status, "CONNECT status")
			assert.Equal(t, tc.wantReason, answer.reason(), "CONNECT reason")
			require.NotEmpty(t, answer.id(), "the refusal carries a connection id")
			record := h.sink.find(t, tc.name, byConnection(answer.id(), tc.wantReason))
			assert.Equal(t, policy.VerdictDeny, record.Decision.Verdict, "record = %+v", record)
		})
	}
	t.Cleanup(func() {
		assert.Zero(t, h.upstream.connections.Load(), "a denied connection reached the upstream")
		assert.Zero(t, h.store.Mints(), "a denied connection minted a leaf")
	})
}

func TestDeniedRequestsInsideAnAllowedTunnel(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{})
	authority := h.upstreamAuthority()
	tests := []struct {
		name       string
		request    string
		wantStatus int
		wantReason policy.Reason
	}{
		{
			name:       "a path outside every prefix",
			request:    "GET /other HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
			wantStatus: http.StatusForbidden, wantReason: policy.ReasonNoMatchingEndpoint,
		},
		{
			name:       "a Host header naming another host",
			request:    "GET /ok/x HTTP/1.1\r\nHost: other.example\r\n\r\n",
			wantStatus: http.StatusForbidden, wantReason: policy.ReasonHostMismatch,
		},
		{
			name:       "a Host header naming another port",
			request:    "GET /ok/x HTTP/1.1\r\nHost: " + upstreamHost + ":1\r\n\r\n",
			wantStatus: http.StatusForbidden, wantReason: policy.ReasonHostMismatch,
		},
		{
			name:       "an endpoint with a credential and no source",
			request:    "GET /cred/x HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
			wantStatus: http.StatusForbidden, wantReason: policy.ReasonCredentialUnavailable,
		},
		{
			name:       "dot segments",
			request:    "GET /ok/../cred/x HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
			wantStatus: http.StatusBadRequest, wantReason: policy.ReasonMalformedRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn, err := h.tlsTunnel(t, upstreamHost)
			require.NoError(t, err)
			answer := h.roundTrip(t, conn, bufio.NewReader(conn), tc.request)
			assert.Equal(t, tc.wantStatus, answer.status, "response status")
			assert.Equal(t, tc.wantReason, answer.reason(), "response reason")
			record := h.sink.find(t, tc.name, byRequest(answer.id()))
			assert.Equal(t, policy.VerdictDeny, record.Decision.Verdict, "record verdict")
			assert.Equal(t, tc.wantReason, record.Decision.Reason, "record reason")
			assert.Equal(t, upstreamHost, record.Destination.SNI, "record SNI")
			require.NotNil(t, record.Request, "the record names the request")
			assert.Equal(t, http.MethodGet, record.Request.Method, "record method")
		})
	}
	t.Cleanup(func() {
		assert.Zero(t, h.upstream.connections.Load(), "a denied request reached the upstream")
	})
}

func TestHandshakeRefusals(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{})
	tests := []struct {
		name       string
		serverName string
		wantReason policy.Reason
	}{
		{name: "no SNI", serverName: "", wantReason: policy.ReasonNoSNI},
		{
			name:       "an SNI that is not the CONNECT authority",
			serverName: "other.example",
			wantReason: policy.ReasonHostMismatch,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := h.tlsTunnel(t, tc.serverName)
			require.Error(t, err, "the handshake is refused")
			record := h.sink.find(t, tc.name, func(record audit.Record) bool {
				return record.Scope == audit.ScopeConnection && record.Decision.Reason == tc.wantReason &&
					record.Destination.SNI == tc.serverName
			})
			assert.Equal(t, policy.VerdictDeny, record.Decision.Verdict, "record verdict")
			assert.Equal(t, upstreamHost, record.Destination.Host, "record host")
			assert.Equal(t, h.upstream.port, record.Destination.Port, "record port")
		})
	}
	t.Cleanup(func() {
		assert.Zero(t, h.store.Mints(), "a refused handshake minted a leaf")
	})
}

// TestCrashersAreRefusedAndTheProcessKeepsServing drives the requests that
// panic goproxy v1.9.1's MITM loop: an asterisk-form target with a port in
// Host, as `OPTIONS *` and as the h2c client preface. The proxy refuses each
// one, and both the same tunnel and a new tunnel keep serving.
func TestCrashersAreRefusedAndTheProcessKeepsServing(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{})
	authority := h.upstreamAuthority()
	crashers := []struct {
		name string
		raw  string
	}{
		{name: "OPTIONS * with a port in Host", raw: "OPTIONS * HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"},
		{name: "h2c preface with a port in Host", raw: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"},
	}
	for _, tc := range crashers {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn, err := h.tlsTunnel(t, upstreamHost)
			require.NoError(t, err)
			reader := bufio.NewReader(conn)
			answer := h.roundTrip(t, conn, reader, tc.raw)
			assert.Equal(t, http.StatusBadRequest, answer.status, "response status")
			assert.Equal(t, policy.ReasonMalformedRequest, answer.reason(), "response reason")
			record := h.sink.find(t, tc.name, byRequest(answer.id()))
			assert.Equal(t, policy.ReasonMalformedRequest, record.Decision.Reason, "record reason")
			require.NotNil(t, record.Request)
			assert.Equal(t, "*", record.Request.Path, "the record names the asterisk target")
			// The tunnel is still open when the server did not close it, and a
			// new tunnel works either way.
			if !answer.closed {
				again := h.roundTrip(t, conn, reader, "GET /ok/after HTTP/1.1\r\nHost: "+authority+"\r\n\r\n")
				assert.Equal(t, http.StatusOK, again.status, "the same tunnel still serves")
			}
			fresh, err := h.get(t, h.upstreamURL("/ok/fresh"))
			require.NoError(t, err, "a fresh request after the crasher")
			assert.Equal(t, http.StatusOK, fresh.status, "a fresh tunnel still serves")
		})
	}
}

func TestACleartextPrefaceInATunnelClosesIt(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{})
	conn, reader := h.rawTunnel(t)
	_, _ = io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	_, err := reader.ReadByte()
	require.Error(t, err, "the proxy closes rather than answering a cleartext preface")
	answer, err := h.get(t, h.upstreamURL("/ok/after"))
	require.NoError(t, err, "a request after the preface")
	assert.Equal(t, http.StatusOK, answer.status, "the proxy keeps serving")
}

func TestResponsesStream(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.upstreamURL("/stream/events"), nil)
	require.NoError(t, err)
	client := h.client()
	client.Timeout = 0
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	reader := bufio.NewReader(resp.Body)
	first := make(chan string, 1)
	go func() {
		line, _ := reader.ReadString('\n')
		first <- line
	}()
	select {
	case line := <-first:
		require.Equal(t, "data: first\n", line, "the first chunk")
	case <-time.After(3 * time.Second):
		require.FailNow(t, "the response was buffered",
			"the first chunk did not arrive before the upstream finished")
	}
	close(h.upstream.release)
	rest, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Contains(t, string(rest), "data: second", "the rest of the stream")
}

func TestANameResolvingIntoADeniedRangeIsRefusedAtTheDial(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{loopbackDenied: true})
	answer, err := h.get(t, h.upstreamURL("/ok/x"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, answer.status, "response status")
	assert.Equal(t, policy.ReasonDenyAlways, answer.reason(), "response reason")
	record := h.sink.find(t, "the refused dial", byReason(audit.ScopeRequest, policy.ReasonDenyAlways))
	assert.Equal(t, policy.VerdictDeny, record.Decision.Verdict, "record verdict")
	assert.Contains(t, record.Decision.Error, "deny list", "the record says why")
	require.NotNil(t, record.Outcome)
	assert.Equal(t, http.StatusForbidden, record.Outcome.Status, "record status")
	assert.Zero(t, h.upstream.connections.Load(), "the upstream was never dialled")
}

func TestAnUnreachableUpstreamIsAGateway(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{})
	h.upstream.server.Close()
	answer, err := h.get(t, h.upstreamURL("/ok/x"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadGateway, answer.status, "response status")
	assert.Equal(t, policy.ReasonUpstreamFailed, answer.reason(), "response reason")
	record := h.sink.find(t, "the failed upstream", byReason(audit.ScopeRequest, policy.ReasonUpstreamFailed))
	require.NotNil(t, record.Outcome)
	assert.Equal(t, http.StatusBadGateway, record.Outcome.Status, "record status")
	assert.NotEmpty(t, record.Outcome.Error, "the record says why")
}

func TestCleartextAndNonProxyRequests(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{})
	tests := []struct {
		name       string
		raw        string
		wantStatus int
		wantReason policy.Reason
	}{
		{
			name:       "an absolute-form cleartext request to a listed host",
			raw:        "GET http://" + upstreamHost + "/ok/x HTTP/1.1\r\nHost: " + upstreamHost + "\r\n\r\n",
			wantStatus: http.StatusForbidden, wantReason: policy.ReasonNoMatchingEndpoint,
		},
		{
			name:       "an absolute-form cleartext request to a denied host",
			raw:        "GET http://169.254.169.254/latest HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
			wantStatus: http.StatusForbidden, wantReason: policy.ReasonDenyAlways,
		},
		{
			name:       "an origin-form request",
			raw:        "GET /healthz HTTP/1.1\r\nHost: " + h.addr + "\r\n\r\n",
			wantStatus: http.StatusBadRequest, wantReason: policy.ReasonNotAProxyRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn := h.dial(t)
			answer := h.roundTrip(t, conn, bufio.NewReader(conn), tc.raw)
			assert.Equal(t, tc.wantStatus, answer.status, "response status")
			assert.Equal(t, tc.wantReason, answer.reason(), "response reason")
			record := h.sink.find(t, tc.name, byRequest(answer.id()))
			assert.Equal(t, tc.wantReason, record.Decision.Reason, "record reason")
			assert.NotNil(t, record.Request, "the record names the request")
		})
	}
	t.Cleanup(func() {
		assert.Zero(t, h.upstream.connections.Load(), "the upstream was never reached")
	})
}

func TestConnectionCap(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{maxConnections: 1})
	held, _ := h.rawTunnel(t)

	second := h.dial(t)
	fmt.Fprintf(second, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", h.upstreamAuthority(), h.upstreamAuthority())
	_ = second.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, readErr := second.Read(make([]byte, 1))
	timeout, ok := errors.AsType[net.Error](readErr)
	require.True(t, ok && timeout.Timeout(), "the second connection was served past the cap: %v", readErr)

	_ = held.Close()
	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	answer := readConnect(t, bufio.NewReader(second))
	assert.Equal(t, http.StatusOK, answer.status, "the second CONNECT once the first closed")
}

func TestIdleConnectionsAreClosed(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{idleTimeout: 200 * time.Millisecond})
	conn := h.dial(t)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	started := time.Now()
	_, err := conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "the proxy closes an idle connection")
	assert.Less(t, time.Since(started), 2*time.Second, "it closes within the idle bound")
}

// TestRunReturnsWhenTheListenerFails proves that a failure in one server
// stops the other. The test closes the listener underneath the frontend, Run
// returns that failure, and the tunnel server stops with it.
func TestRunReturnsWhenTheListenerFails(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{unstarted: true})
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- h.server.Run(t.Context(), listener) }()
	_ = listener.Close()
	select {
	case err := <-done:
		require.ErrorContains(t, err, "frontend", "Run returns the frontend's listener failure")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "Run did not return after its listener failed")
	}
}

// TestAStalledUpstreamIsBoundedByTheResponseHeaderTimeout proves an upstream
// that accepts a request and never answers cannot hold a frontend
// connection. Without the budget the request waits until the client gives
// up, and a workload can pin the whole connection cap that way.
func TestAStalledUpstreamIsBoundedByTheResponseHeaderTimeout(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{responseHeaderTimeout: 300 * time.Millisecond})
	started := time.Now()
	answer, err := h.get(t, h.upstreamURL("/stall/x"))
	require.NoError(t, err, "the proxy answered rather than hanging")
	assert.Equal(t, http.StatusBadGateway, answer.status, "response status")
	assert.Equal(t, policy.ReasonUpstreamFailed, answer.reason(), "response reason")
	assert.Less(t, time.Since(started), 4*time.Second, "the proxy gave up on the response head")
	record := h.sink.find(t, "the stalled upstream", byReason(audit.ScopeRequest, policy.ReasonUpstreamFailed))
	assert.NotEmpty(t, record.Outcome.Error, "the record says why")
}

func TestNewRefusesMissingOptions(t *testing.T) {
	t.Parallel()
	_, err := proxy.New(proxy.Options{})
	require.Error(t, err, "New refuses empty options")
}

// TestActiveStreamOutlivesIdleTimeout proves the idle bound measures
// silence, not request length. The upstream writes a chunk every tenth of
// the bound for twice the bound, so the connection is never idle and the
// whole stream must arrive.
func TestActiveStreamOutlivesIdleTimeout(t *testing.T) {
	t.Parallel()
	const idle = time.Second
	const chunks = 20
	h := start(t, harnessOptions{idleTimeout: idle})
	h.upstream.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		ticker := time.NewTicker(idle / 10)
		defer ticker.Stop()
		for range chunks {
			if _, err := io.WriteString(w, "data: active\n\n"); err != nil {
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
	})
	client := h.client()
	// The stream outlasts the client's default budget. The request context
	// bounds a proxy that hangs instead.
	client.Timeout = 0
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.upstreamURL("/stream/events"), nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "response status")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "a continuously active response must outlive the idle timeout")
	assert.Equal(t, strings.Repeat("data: active\n\n", chunks), string(body), "the whole stream")
}

// TestTruncatedResponseIsAudited proves a forwarded request whose body ends
// short of its Content-Length still gets its request-scoped record, and
// that the record says the response did not complete.
func TestTruncatedResponseIsAudited(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{})
	h.upstream.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "short")
	})
	client := h.client()
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.upstreamURL("/ok/truncated"), nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF, "the upstream response is truncated")
	assert.Equal(t, "short", string(body), "the bytes that did arrive")
	record := h.sink.find(t, "the truncated response", func(record audit.Record) bool {
		return record.Scope == audit.ScopeRequest && record.Request != nil && record.Request.Path == "/ok/truncated"
	})
	assert.NotEmpty(t, record.RequestID, "record request id")
	require.NotNil(t, record.Outcome, "record outcome")
	assert.Equal(t, http.StatusOK, record.Outcome.Status, "record status")
	assert.NotEmpty(t, record.Outcome.Error, "the record reports the incomplete response")
}

// TestShutdownDrainsInFlightRequest proves that cancelling Run's context
// starts the grace period rather than ending the requests in flight. The
// upstream holds the request until the test releases it after the
// cancellation. A proxy that drains answers 200 after the release. A proxy
// that aborts answers before it.
func TestShutdownDrainsInFlightRequest(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{unstarted: true})
	entered := make(chan struct{})
	release := make(chan struct{})
	h.upstream.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
			_, _ = io.WriteString(w, "finished")
		case <-r.Context().Done():
		}
	})
	run := h.run(t)
	client := h.client()
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.upstreamURL("/ok/slow"), nil)
	require.NoError(t, err)
	type result struct {
		status int
		body   string
		err    error
	}
	results := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			results <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		results <- result{status: resp.StatusCode, body: string(body), err: err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the request did not reach the upstream")
	}
	run.cancel()
	// An abort answers at once, so this wait is where it shows. A proxy that
	// drains produces nothing here.
	select {
	case got := <-results:
		t.Fatalf("the request ended before its release: %+v", got)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case got := <-results:
		require.NoError(t, got.err, "read the response")
		assert.Equal(t, http.StatusOK, got.status, "response status")
		assert.Equal(t, "finished", got.body, "response body")
	case <-time.After(5 * time.Second):
		t.Fatal("the request did not finish within the shutdown grace")
	}
}

// TestAnUpgradedRequestIsAuditedBeforeRunReturns proves two contracts for a
// request the reverse proxy hijacked for a protocol upgrade: its record
// reports the 101 the upstream sent, and Run does not return before the
// record is emitted. The gate holds that emit open, so a Run that returns
// during it is caught.
func TestAnUpgradedRequestIsAuditedBeforeRunReturns(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{unstarted: true})
	h.upstream.server.Config.Handler = http.HandlerFunc(upgradeHandler)
	gate := newEmitGate(func(record audit.Record) bool {
		return record.Scope == audit.ScopeRequest && record.Request != nil && record.Request.Path == "/ok/upgrade"
	})
	h.sink.gate = gate
	run := h.run(t)
	h.upgrade(t)
	run.cancel()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the upgraded request was not audited")
	}
	// A Run that returns during the emit shows in this wait.
	select {
	case <-run.finished:
		t.Fatal("Run returned before the upgraded request's record was emitted")
	case <-time.After(250 * time.Millisecond):
	}
	close(gate.release)
	select {
	case <-run.finished:
		require.NoError(t, run.err, "Run after cancellation")
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not finish")
	}
	// The record is in the sink the moment Run returns, so nothing waits here.
	records, _ := h.sink.snapshot()
	index := slices.IndexFunc(records, gate.match)
	require.NotEqual(t, -1, index, "the upgraded request's record is in the sink once Run returned")
	record := records[index]
	assert.Equal(t, policy.VerdictAllow, record.Decision.Verdict, "record verdict")
	assert.Equal(t, policy.ReasonEndpointAllowed, record.Decision.Reason, "record reason")
	require.NotNil(t, record.Outcome, "record outcome")
	assert.Equal(t, http.StatusSwitchingProtocols, record.Outcome.Status, "the record reports the protocol switch")
}
