package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/keycardai/egress-proxy/internal/admin"
)

// socketPath is a short path under the system temporary directory, because
// a Unix socket address is capped at 103 bytes and t.TempDir can exceed it.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "egress-probe-*") //nolint:usetesting // t.TempDir can exceed the socket path cap
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "admin.sock")
}

// errNotBound stands in for the readiness failure a starting process
// reports.
var errNotBound = errors.New("the CONNECT listener is not bound")

// TestProbeReadsTheAdminSocket pins what the kubelet sees on each route.
// The startup probe holds the workload until readyz answers, so readyz has
// to fail while the process is starting and pass once it serves.
func TestProbeReadsTheAdminSocket(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		route   string
		serving bool
		wantErr string
		wantOut string
	}{
		{name: "healthz before the listener is bound", route: "healthz", wantOut: "ok\n"},
		{
			name: "readyz before the listener is bound", route: "readyz",
			wantErr: "answered 503", wantOut: "the CONNECT listener is not bound\n",
		},
		{name: "readyz once the process serves", route: "readyz", serving: true, wantOut: "ok\n"},
		{name: "info once the process serves", route: "info", serving: true, wantOut: `"version": "test"`},
		{
			name: "a route the admin socket does not serve", route: "metrics",
			wantErr: `"metrics" is not a route`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			socket := serveAdmin(t, tc.serving)
			var out strings.Builder
			err := runProbe(t.Context(), tc.route, socket, &out)
			if tc.wantErr == "" {
				require.NoError(t, err, "probe %s", tc.route)
			} else {
				require.ErrorIs(t, err, errProbe, "probe %s", tc.route)
				require.ErrorContains(t, err, tc.wantErr, "the failure says what happened")
			}
			assert.Contains(t, out.String(), tc.wantOut, "probe %s prints the answer", tc.route)
		})
	}
}

// serveAdmin runs an admin socket that reports serving as its readiness and
// stops when the test ends.
func serveAdmin(t *testing.T, serving bool) string {
	t.Helper()
	path := socketPath(t)
	server, err := admin.New(t.Context(), admin.Options{
		Path: path,
		Info: func() any { return map[string]string{"version": "test"} },
		Ready: func() error {
			if !serving {
				return errNotBound
			}
			return nil
		},
	})
	require.NoError(t, err, "admin.New")
	ctx, cancel := context.WithCancel(t.Context())
	var group errgroup.Group
	group.Go(func() error { return server.Run(ctx) })
	t.Cleanup(func() {
		cancel()
		require.NoError(t, group.Wait(), "the admin server stopped with an error")
	})
	return path
}

// TestProbeWithNoSocket covers the window before the process has created
// the socket. A probe then fails, which is what holds the workload back.
func TestProbeWithNoSocket(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "absent.sock")
	var out strings.Builder
	err := runProbe(t.Context(), "readyz", path, &out)
	require.ErrorIs(t, err, errProbe, "probe against a socket that is not there")
	require.ErrorContains(t, err, path, "the failure names the socket")
	assert.Empty(t, out.String(), "nothing is printed when there is no answer")
}

// TestProbeReadsTheSameSettingTheServerReads covers the flag and the
// variable that name the socket. The probe runs in the proxy's container,
// so a manifest that moves the socket moves it for both.
// It sets the environment, so it does not run in parallel.
func TestProbeReadsTheSameSettingTheServerReads(t *testing.T) {
	t.Setenv(envPrefix+"ADMIN", "/env/admin.sock")
	var opts flags
	cmd := command(os.Stdout, os.Stderr, func(_ context.Context, parsed flags) error {
		opts = parsed
		return nil
	})
	require.NoError(t, cmd.Run(t.Context(), []string{"egress-proxy", "--config", "/x"}), "Run")
	assert.Equal(t, "/env/admin.sock", adminSocket(&opts), "the probe reads EGRESS_PROXY_ADMIN")
	assert.Equal(t, "/run/egress/admin.sock", adminSocket(&flags{}),
		"the probe falls back to the same default the document does")
}
