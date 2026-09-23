package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/admin"
	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/internal/config"
	"github.com/keycardai/egress-proxy/internal/proxy"
	"github.com/keycardai/egress-proxy/internal/transparent"
)

// TestCommandResolvesFlagsAndEnvironment pins the precedence the command
// promises: a flag wins over its variable, and every variable reaches the
// override the parser applies. It sets the environment, so it does not run
// in parallel.
func TestCommandResolvesFlagsAndEnvironment(t *testing.T) { //nolint:paralleltest // t.Setenv
	for name, value := range map[string]string{ //nolint:gosec // G101: paths, not secret values
		"CONFIG":                  "/env/config.yaml",
		"SANDBOX_ID":              "sbx-env",
		"ZONE_URL":                "https://env.example",
		"CLIENT_ID":               "env-client",
		"WORKLOAD_TOKEN_FILE":     "/env/token",
		"IMPERSONATE_USER":        "env-user",
		"CONNECT":                 "127.0.0.1:1",
		"TRANSPARENT_PORT":        "1015",
		"ADMIN":                   "/env/admin.sock",
		"NETSETUP_RECEIPT":        "/env/netsetup.json",
		"CA_OUT_DIR":              "/env/ca",
		"CA_STATE_DIR":            "/env/state",
		"CLIENT_SECRET_FILE":      "/env/client-secret",
		"CREDENTIAL_STATIC_FILE":  "/env/credentials.yaml",
		"LEAF_TTL":                "2h",
		"CACHE_SIZE":              "5",
		"UPSTREAM_CA_FILES":       "/env/a.pem,/env/b.pem",
		"MAX_CONNECTIONS":         "9",
		"IDLE_TIMEOUT":            "90s",
		"RESPONSE_HEADER_TIMEOUT": "45s",
		"EXCHANGE_TIMEOUT":        "7s",
	} {
		t.Setenv(envPrefix+name, value)
	}

	var got flags
	cmd := command(io.Discard, io.Discard, func(_ context.Context, opts flags) error {
		got = opts
		return nil
	})
	require.NoError(t, cmd.Run(t.Context(), []string{"egress-proxy", "--connect", "127.0.0.1:2"}), "Run")

	want := config.Overrides{ //nolint:gosec // G101: paths, not secret values
		SandboxID: "sbx-env", ZoneURL: "https://env.example", ClientID: "env-client",
		WorkloadTokenFile: "/env/token", ImpersonateUser: "env-user",
		// The flag wins over EGRESS_PROXY_CONNECT.
		Connect: "127.0.0.1:2", TransparentPort: 1015, TransparentPortSet: true, Admin: "/env/admin.sock",
		NetsetupReceipt: "/env/netsetup.json", CAOutDir: "/env/ca", CAStateDir: "/env/state",
		ClientSecretFile:     "/env/client-secret",
		CredentialStaticFile: "/env/credentials.yaml",
		LeafTTL:              2 * time.Hour, CacheSize: 5, UpstreamCAFiles: []string{"/env/a.pem", "/env/b.pem"},
		MaxConnections: 9, IdleTimeout: 90 * time.Second, ResponseHeaderTimeout: 45 * time.Second,
		ExchangeTimeout: 7 * time.Second,
	}
	assert.Equal(t, "/env/config.yaml", got.configPath, "the config path comes from the variable")
	assert.Equal(t, want, got.overrides(), "every variable reaches the override the parser applies")
}

// TestCommandRequiresTheConfigPath pins the serve path's own refusal. The
// flag holds no Required, so this check is the only thing between an empty
// document path and config.Load.
func TestCommandRequiresTheConfigPath(t *testing.T) { //nolint:paralleltest // the environment must not supply it
	tests := []struct {
		name string
		args []string
	}{
		{name: "neither the flag nor the variable is set", args: []string{"egress-proxy"}},
		{name: "the flag is set to an empty path", args: []string{"egress-proxy", "--config", ""}},
	}
	for _, tc := range tests { //nolint:paralleltest // the environment must not supply the document path
		t.Run(tc.name, func(t *testing.T) {
			cmd := command(io.Discard, io.Discard, func(context.Context, flags) error {
				t.Fatal("the serve path ran with no document")
				return nil
			})
			require.ErrorIs(t, cmd.Run(t.Context(), tc.args), errNoConfig, "Run %v", tc.args)
		})
	}
}

func TestTransparentPortOverrides(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		args     []string
		unsetEnv bool
		want     int
	}{
		{name: "document without an override", unsetEnv: true, want: 1015},
		{name: "empty environment keeps the document", want: 1015},
		{name: "flag disables capture", args: []string{"--transparent-port", "0"}, want: 0},
		{name: "environment disables capture", env: "0", want: 0},
		{name: "flag disables capture over environment", env: "1016", args: []string{"--transparent-port", "0"}, want: 0},
		{name: "flag enables capture over environment", env: "0", args: []string{"--transparent-port", "1016"}, want: 1016},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envPrefix+"TRANSPARENT_PORT", tc.env)
			if tc.unsetEnv {
				require.NoError(t, os.Unsetenv(envPrefix+"TRANSPARENT_PORT"), "omit the environment override")
			}
			var cfg *config.Config
			cmd := command(io.Discard, io.Discard, func(_ context.Context, opts flags) error {
				var err error
				cfg, err = config.Parse([]byte("version: 1\nsandbox:\n  id: test\nlisten:\n  transparent_port: 1015\n"+
					"endpoints:\n  - host: example.com\n"), opts.overrides())
				require.NoError(t, err, "parse the document")
				return nil
			})
			args := append([]string{"egress-proxy", "--config", "/unused.yaml"}, tc.args...)
			require.NoError(t, cmd.Run(t.Context(), args), "parse the command and document")
			require.NotNil(t, cfg, "the command loaded the document")
			assert.Equal(t, tc.want, cfg.Listen.TransparentPort, "the effective transparent port")
			if tc.env != "" || len(tc.args) != 0 {
				assert.Contains(t, cfg.Overridden, "listen.transparent_port", "record the supplied override")
			} else {
				assert.NotContains(
					t,
					cfg.Overridden,
					"listen.transparent_port",
					"an omitted override leaves the document alone",
				)
			}
		})
	}
}

// TestBindReportsReadyOnlyOnceEveryListenerIsBound pins the order the
// kubelet depends on. A process that reported ready with the CONNECT
// listener bound and the capture sockets still closed would have the
// workload released against a redirect port that refuses connections.
func TestBindReportsReadyOnlyOnceEveryListenerIsBound(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// occupied holds listen.transparent_port before the process binds
		// it, so the capture socket cannot open. A row that leaves it false
		// runs no transparent frontend.
		occupied bool
		wantErr  error
	}{
		{name: "no transparent frontend"},
		{name: "the transparent sockets do not bind", occupied: true, wantErr: syscall.EADDRINUSE},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			proc := startingProcess(t, tc.occupied)
			require.ErrorIs(t, proc.ready(), errNotReady, "readiness before bind")

			listener, captured, err := proc.bind(t.Context())
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr, "bind")
				require.ErrorIs(t, proc.ready(), errNotReady,
					"readiness answered after a listener that never bound")
				require.ErrorContains(t, proc.ready(), "the frontend listeners are not bound",
					"the 503 says which half is missing")
				return
			}
			require.NoError(t, err, "bind")
			t.Cleanup(func() { _ = listener.Close() })
			assert.Empty(t, captured, "no transparent frontend binds no capture socket")
			assert.NoError(t, proc.ready(), "readiness once every listener is bound")
		})
	}
}

// startingProcess is a process with its certificate written and nothing
// bound, which is the state the sidecar is in when the kubelet first
// probes it. Holding the transparent port drives the row where a capture
// socket cannot open.
func startingProcess(t *testing.T, occupyTransparentPort bool) *process {
	t.Helper()
	certDir := t.TempDir()
	authority, err := ca.New(ca.Options{CommonName: "bind test"})
	require.NoError(t, err, "ca.New")
	certPath, err := authority.WriteCertificate(certDir)
	require.NoError(t, err, "WriteCertificate")

	adminServer, err := admin.New(t.Context(), admin.Options{Path: socketPath(t), Info: func() any { return nil }})
	require.NoError(t, err, "admin.New")
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_ = adminServer.Run(ctx)
	})

	// The rows bind port 0, so two of them never collide. The document
	// names no transparent port, so a row that wants one writes it after
	// the parse.
	cfg, err := config.Parse([]byte(bindDocument), config.Overrides{})
	require.NoError(t, err, "config.Parse")

	proc := &process{
		cfg:      cfg,
		logger:   slog.New(slog.DiscardHandler),
		admin:    adminServer,
		certPath: certPath,
	}
	if occupyTransparentPort {
		cfg.Listen.TransparentPort = heldPort(t)
		proc.transparent, err = transparent.New(transparent.Options{
			Handler:        func(net.Conn, proxy.Redirected) {},
			MaxConnections: 1,
			IdleTimeout:    time.Minute,
		})
		require.NoError(t, err, "transparent.New")
	}
	return proc
}

// heldPort binds a loopback port for the life of the test and reports it.
// transparent.Listen opens 127.0.0.1 first, so a bind of that port answers
// EADDRINUSE.
func heldPort(t *testing.T) int {
	t.Helper()
	holder, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err, "hold a loopback port")
	t.Cleanup(func() { _ = holder.Close() })
	_, port, err := net.SplitHostPort(holder.Addr().String())
	require.NoError(t, err, "split the held address")
	number, err := strconv.Atoi(port)
	require.NoError(t, err, "parse the held port")
	return number
}

// bindDocument is the smallest document that starts, with the CONNECT
// frontend on a port the kernel picks.
const bindDocument = "version: 1\nsandbox:\n  id: bind-test\n" +
	"listen:\n  connect: 127.0.0.1:0\nendpoints:\n  - host: example.com\n"
