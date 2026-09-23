package transparent_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/internal/policy"
	"github.com/keycardai/egress-proxy/internal/proxy"
	"github.com/keycardai/egress-proxy/internal/transparent"
)

// capturePeekTimeout bounds the peek in this pipeline. The run is timed
// against it, so a peek that waits for bytes the client has not sent fails
// the test rather than merely slowing it.
//
// The whole run takes about 50ms, so this is a backstop and not a budget.
// It is low enough that a stalled peek fails the run quickly.
const capturePeekTimeout = 2 * time.Second

// captureClientTimeout turns a pipeline that never answers into a failed
// request. Keep it above capturePeekTimeout, so a stalled peek is reported
// by the frontend that refused the connection rather than by the client
// that gave up on it.
const captureClientTimeout = 5 * time.Second

// capture is the whole redirected path: the frontend recovers a
// destination, hands the connection to the proxy, the proxy terminates TLS
// and forwards the request to the upstream.
type capture struct {
	addr string
	// authority is the destination the workload names, which is the name
	// and the port the connection was opened to.
	authority string
	roots     *x509.CertPool
	records   chan audit.Record
}

// recordSink collects the records the proxy writes, so a case reads the
// decision the pipeline made.
type recordSink struct {
	records chan audit.Record
}

func (s recordSink) Emit(record audit.Record) {
	select {
	case s.records <- record:
	default:
	}
}

// newCapture wires an upstream, a proxy and a transparent frontend over
// loopback. The recovery is a fixed answer, because SO_ORIGINAL_DST needs a
// REDIRECT rule and only Linux has one. Everything the answer feeds is the
// code a redirected connection runs through.
func newCapture(t *testing.T) *capture {
	t.Helper()
	upstreamCA, err := ca.New(ca.Options{CommonName: "capture upstream CA"})
	require.NoError(t, err)
	leaf, err := upstreamCA.Leaf("upstream.test")
	require.NoError(t, err)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		//nolint:gosec // G705: a fixture echoing the path it was asked for, as text/plain
		fmt.Fprintf(w, "hello %s", r.URL.Path)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	_, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)

	deny, err := policy.NewDenyList(nil, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	require.NoError(t, err)
	matcher, err := policy.Compile([]policy.Endpoint{
		{Host: "upstream.test", Port: port, PathPrefix: "/allowed/"},
	}, deny)
	require.NoError(t, err)
	authority, err := ca.New(ca.Options{})
	require.NoError(t, err)
	store, err := ca.NewStore(authority, 16)
	require.NoError(t, err)
	records := make(chan audit.Record, 128)
	proxied, err := proxy.New(proxy.Options{
		Matcher:       matcher,
		Certificates:  store,
		Audit:         recordSink{records: records},
		UpstreamRoots: upstreamCA.Pool(),
		Logger:        slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		ShutdownGrace: time.Second,
	})
	require.NoError(t, err)

	// The upstream listens on loopback, so the address the frontend
	// recovers names it and the proxy dials it back by name.
	original := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)) //nolint:gosec // G115: a listener port
	front, err := transparent.New(transparent.Options{
		Handler:        proxied.ServeRedirected,
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		OriginalDst:    func(net.Conn) (netip.AddrPort, error) { return original, nil },
		PeekTimeout:    capturePeekTimeout,
		MaxConnections: 16,
		IdleTimeout:    30 * time.Second,
	})
	require.NoError(t, err)

	captured, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	explicit, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	var group errgroup.Group
	group.Go(func() error { return proxied.Run(ctx, explicit) })
	group.Go(func() error { return front.Serve(ctx, captured) })
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, group.Wait(), "the proxy and the frontend after cancellation")
	})
	return &capture{
		addr:      captured.Addr().String(),
		authority: net.JoinHostPort("upstream.test", portText),
		roots:     authority.Pool(),
		records:   records,
	}
}

// get makes one request the way a workload with no proxy configured does:
// it opens a connection to the redirect target and speaks TLS for
// upstream.test over it.
func (c *capture) get(t *testing.T, path string) (int, string) {
	t.Helper()
	client := &http.Client{
		Timeout: captureClientTimeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, c.addr)
			},
			TLSClientConfig: &tls.Config{RootCAs: c.roots, MinVersion: tls.VersionTLS12},
		},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+c.authority+path, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err, "GET %s through the capture", path)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

// TestCapturedConnectionsAreServedOneAfterAnother drives several requests
// through the whole redirected path in a row. One connection must not
// change what the next one gets: the frontend, the intake and the tunnel
// server are shared, and a connection that leaves state behind stops the
// ones after it.
func TestCapturedConnectionsAreServedOneAfterAnother(t *testing.T) {
	t.Parallel()
	pipeline := newCapture(t)
	// A request that spends the peek timeout still succeeds, so the run is
	// timed as well. The peek waits for one byte past what it has served
	// and hands over what has arrived, so a client that sent its whole
	// ClientHello waits for nothing.
	start := time.Now()
	for i := range 6 {
		path := fmt.Sprintf("/allowed/%d", i)
		status, body := pipeline.get(t, path)
		require.Equal(t, http.StatusOK, status, "request %d", i)
		require.Equal(t, "hello "+path, body, "request %d", i)
	}
	status, _ := pipeline.get(t, "/denied/x")
	assert.Equal(t, http.StatusForbidden, status, "a path no endpoint covers")
	status, _ = pipeline.get(t, "/allowed/after-the-denial")
	assert.Equal(t, http.StatusOK, status, "a refused request does not stop the next one")
	assert.Less(t, time.Since(start), capturePeekTimeout,
		"eight requests finish inside one peek timeout, so no request waited on the peek")
}
