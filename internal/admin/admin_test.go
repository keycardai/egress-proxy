package admin_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/keycardai/egress-proxy/internal/admin"
)

// socketPath is a short path under the system temp directory, because a Unix
// socket address is capped at 103 bytes and t.TempDir can exceed that.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "egress-admin-*") //nolint:usetesting // t.TempDir can exceed the socket path cap
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "admin.sock")
}

// errNotBound stands in for the readiness failure a starting process
// reports.
var errNotBound = errors.New("the CONNECT listener is not bound")

// nilInfo is the /info answer for a test that asserts on another route.
func nilInfo() any { return nil }

func client(path string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
}

// get returns the status and body of a route on the socket.
func get(t *testing.T, path, route string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://admin"+route, nil)
	require.NoError(t, err)
	resp, err := client(path).Do(req)
	require.NoError(t, err, "GET %s", route)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func TestServerAnswersHealthAndInfo(t *testing.T) {
	t.Parallel()
	path := socketPath(t)
	server, err := admin.New(t.Context(), admin.Options{Path: path, Info: func() any {
		return map[string]any{"version": "test", "endpoints": []string{"api.github.com"}}
	}})
	require.NoError(t, err, "admin.New")
	ctx, cancel := context.WithCancel(t.Context())
	var group errgroup.Group
	group.Go(func() error { return server.Run(ctx) })

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "socket mode")

	status, body := get(t, path, "/healthz")
	assert.Equal(t, http.StatusOK, status, "/healthz status")
	assert.Equal(t, "ok\n", body, "/healthz body")

	status, body = get(t, path, "/info")
	assert.Equal(t, http.StatusOK, status, "/info status")
	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &decoded), "/info body is not JSON:\n%s", body)
	assert.Equal(t, "test", decoded["version"], "/info version")

	status, body = get(t, path, "/readyz")
	assert.Equal(t, http.StatusOK, status, "/readyz status with no readiness gate")
	assert.Equal(t, "ok\n", body, "/readyz body")

	status, _ = get(t, path, "/metrics")
	assert.Equal(t, http.StatusNotFound, status, "/metrics is not served")

	cancel()
	require.NoError(t, group.Wait(), "Run after cancellation")
	_, err = os.Lstat(path)
	assert.True(t, os.IsNotExist(err), "the socket is unlinked once Run returns")
}

// TestRunReturnsNilOnCancellation covers the shutdown the context asks for.
// TestRunReturnsTheServeFailure, an internal test, covers the other arm,
// which needs the listener the Server does not export.
func TestRunReturnsNilOnCancellation(t *testing.T) {
	t.Parallel()
	path := socketPath(t)
	server, err := admin.New(t.Context(), admin.Options{Path: path, Info: nilInfo})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	require.NoError(t, server.Run(ctx), "Run")
}

// TestNewSetsTheDirectoryMode covers the directory a container runtime
// mounted: it exists before the proxy starts, so MkdirAll leaves its mode
// alone and the mode has to be set on every start.
func TestNewSetsTheDirectoryMode(t *testing.T) {
	t.Parallel()
	path := socketPath(t)
	dir := filepath.Dir(path)
	//nolint:gosec // the fixture stands in for a directory a container runtime mounted
	require.NoError(t, os.Chmod(dir, 0o777), "stand in for a mounted emptyDir")

	server, err := admin.New(t.Context(), admin.Options{Path: path, Info: nilInfo})
	require.NoError(t, err, "admin.New")
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_ = server.Run(ctx)
	})

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "socket directory mode")
}

func TestNewRefusals(t *testing.T) {
	t.Parallel()
	occupied := socketPath(t)
	require.NoError(t, os.WriteFile(occupied, []byte("x"), 0o600))
	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{name: "relative path", path: "admin.sock", wantErr: "is not absolute"},
		{name: "path too long", path: "/" + strings.Repeat("x", 110), wantErr: "at most 103"},
		{name: "a file that is not a socket", path: occupied, wantErr: "is not a socket"},
		{
			name:    "the directory is a file",
			path:    filepath.Join(occupied, "admin.sock"),
			wantErr: "admin: create",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := admin.New(t.Context(), admin.Options{Path: tc.path, Info: nilInfo})
			require.ErrorContains(t, err, tc.wantErr, "New(%q)", tc.path)
		})
	}
}

func TestNewReplacesAStaleSocket(t *testing.T) {
	t.Parallel()
	path := socketPath(t)
	first, err := admin.New(t.Context(), admin.Options{Path: path, Info: nilInfo})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.NoError(t, first.Run(ctx))
	// A crash leaves the socket file behind. A listener that does not unlink
	// on close stands in for one.
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	require.NoError(t, err)
	unixListener, ok := listener.(*net.UnixListener)
	require.True(t, ok, "listener is %T", listener)
	unixListener.SetUnlinkOnClose(false)
	_ = unixListener.Close()
	_, err = os.Lstat(path)
	require.NoError(t, err, "the fixture did not leave a stale socket")

	second, err := admin.New(t.Context(), admin.Options{Path: path, Info: nilInfo})
	require.NoError(t, err, "New over a stale socket")
	ctx, cancel = context.WithCancel(t.Context())
	cancel()
	require.NoError(t, second.Run(ctx))
}

// TestReadyz pins the two answers a startup probe reads. The kubelet holds
// the agent container until this route answers 200, so a 503 has to give
// the reason an operator needs.
func TestReadyz(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		ready      func() error
		wantStatus int
		wantBody   string
	}{
		{name: "serving", ready: func() error { return nil }, wantStatus: http.StatusOK, wantBody: "ok\n"},
		{
			name:       "the listener is not bound",
			ready:      func() error { return errNotBound },
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "the CONNECT listener is not bound\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := socketPath(t)
			server, err := admin.New(t.Context(), admin.Options{Path: path, Info: nilInfo, Ready: tc.ready})
			require.NoError(t, err, "admin.New")
			ctx, cancel := context.WithCancel(t.Context())
			var group errgroup.Group
			group.Go(func() error { return server.Run(ctx) })

			status, body := get(t, path, "/readyz")
			assert.Equal(t, tc.wantStatus, status, "/readyz status")
			assert.Equal(t, tc.wantBody, body, "/readyz body")

			// Liveness never follows readiness, so the kubelet does not
			// restart a container that has not finished starting.
			status, body = get(t, path, "/healthz")
			assert.Equal(t, http.StatusOK, status, "/healthz status")
			assert.Equal(t, "ok\n", body, "/healthz body")

			cancel()
			require.NoError(t, group.Wait(), "Run after cancellation")
		})
	}
}
