package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
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
		// transparentPort is listen.transparent_port, built by the row
		// because one of them holds the port against the bind. A zero
		// result runs no transparent frontend.
		transparentPort func(t *testing.T) int
		// families is what the netsetup receipt records the redirect
		// covers.
		families    []string
		wantCapture bool
		wantErr     string
	}{
		{name: "no transparent frontend", transparentPort: noPort},
		{
			name:            "another socket already holds the redirect port",
			transparentPort: heldPort,
			families:        []string{"ipv4"},
			wantErr:         "address already in use",
		},
		{
			name:            "the receipt names ipv4 and the ipv4 socket binds",
			transparentPort: freePort,
			families:        []string{"ipv4"},
			wantCapture:     true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			connect := freeAddress(t)
			proc := startingProcess(t, connect, tc.transparentPort(t), tc.families)
			require.ErrorIs(t, proc.ready(), errNotReady, "readiness before bind")

			listener, captured, err := proc.bind(t.Context())
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr, "bind")
				require.ErrorIs(t, proc.ready(), errNotReady,
					"readiness answered after a listener that never bound")
				require.ErrorContains(t, proc.ready(), "the frontend listeners are not bound",
					"the 503 says which half is missing")
				// A bind that fails half way leaves nothing bound, so a
				// restart finds the CONNECT address free.
				reclaimed, reclaimErr := (&net.ListenConfig{}).Listen(t.Context(), "tcp", connect)
				require.NoError(t, reclaimErr, "the failed bind left the CONNECT listener open on %s", connect)
				require.NoError(t, reclaimed.Close(), "close the reclaimed CONNECT listener")
				return
			}
			require.NoError(t, err, "bind")
			t.Cleanup(func() { _ = listener.Close() })
			for _, capture := range captured {
				t.Cleanup(func() { _ = capture.Close() })
			}
			assert.Equal(t, tc.wantCapture, len(captured) > 0, "the capture sockets bound")
			assert.Empty(t, missingFamilies(tc.families, boundFamilies(captured)),
				"the capture bound every family the receipt names")
			assert.NoError(t, proc.ready(), "readiness once every listener is bound")
		})
	}
}

// noPort runs no transparent frontend.
func noPort(*testing.T) int { return 0 }

// heldPort is a loopback port a listener holds for the whole test, so the
// bind under test fails with EADDRINUSE on a real syscall. transparent.Listen
// opens 127.0.0.1 first.
func heldPort(t *testing.T) int {
	t.Helper()
	held, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err, "hold the redirect port")
	t.Cleanup(func() { _ = held.Close() })
	return portOf(t, held.Addr())
}

// freePort is a loopback port nothing is listening on. The kernel hands out
// one port at a time, so the port is free as soon as the listener that named
// it closes.
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err, "take a port")
	port := portOf(t, listener.Addr())
	require.NoError(t, listener.Close(), "release the port")
	return port
}

// portOf reads the port out of a bound address.
func portOf(t *testing.T, addr net.Addr) int {
	t.Helper()
	_, port, err := net.SplitHostPort(addr.String())
	require.NoError(t, err, "split %s", addr)
	number, err := strconv.Atoi(port)
	require.NoError(t, err, "parse the port in %s", addr)
	return number
}

// freeAddress is a loopback address nothing is listening on. The kernel
// hands out one port at a time, so the address is free as soon as the
// listener that named it closes.
func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err, "take a port")
	address := listener.Addr().String()
	require.NoError(t, listener.Close(), "release the port")
	return address
}

// startingProcess is a process with its certificate written and nothing
// bound, which is the state the sidecar is in when the kubelet first
// probes it.
func startingProcess(t *testing.T, connectAddr string, transparentPort int, families []string) *process {
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

	// Each row picks its own ports, so two of them never collide. Both
	// listen settings are written after the parse, which validates the
	// document's own.
	cfg, err := config.Parse([]byte(bindDocument), config.Overrides{})
	require.NoError(t, err, "config.Parse")
	cfg.Listen.Connect = connectAddr
	cfg.Listen.TransparentPort = transparentPort

	proc := &process{
		cfg:             cfg,
		logger:          slog.New(slog.DiscardHandler),
		admin:           adminServer,
		captureFamilies: families,
		certPath:        certPath,
	}
	if transparentPort != 0 {
		proc.transparent, err = transparent.New(transparent.Options{
			Handler:        func(net.Conn, proxy.Redirected) {},
			MaxConnections: 1,
			IdleTimeout:    time.Minute,
		})
		require.NoError(t, err, "transparent.New")
	}
	return proc
}

// bindDocument is the smallest document that starts, with the CONNECT
// frontend on a port the kernel picks.
const bindDocument = "version: 1\nsandbox:\n  id: bind-test\n" +
	"listen:\n  connect: 127.0.0.1:0\nendpoints:\n  - host: example.com\n"

// TestServeStopsReportingReadyWhileItDrains covers the other end of the
// readiness contract. Each server drains for its grace period after the
// signal, and /readyz answering 200 through that window would have the
// kubelet keep sending the workload at listeners that are closing.
func TestServeStopsReportingReadyWhileItDrains(t *testing.T) {
	t.Parallel()
	cfg, err := config.Parse([]byte(bindDocument), config.Overrides{})
	require.NoError(t, err, "config.Parse")
	cfg.Listen.Connect = freeAddress(t)
	cfg.Listen.Admin = socketPath(t)
	cfg.CA.OutDir = t.TempDir()

	proc, err := build(t.Context(), cfg, slog.New(slog.DiscardHandler), io.Discard)
	require.NoError(t, err, "build")

	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- proc.serve(ctx) }()

	// serve binds before it starts the admin server, so an answer on the
	// socket is the signal that the bind is done. Nothing here polls.
	status, body := probeAdmin(t, cfg.Listen.Admin, "readyz")
	require.Equal(t, http.StatusOK, status, "/readyz once serve has bound: %s", body)

	cancel()
	require.NoError(t, <-stopped, "serve")
	require.ErrorIs(t, proc.ready(), errNotReady, "readiness after the drain")
	require.ErrorContains(t, proc.ready(), "the frontend listeners are not bound",
		"the 503 says the listeners are gone")
}

// probeAdmin dials the admin socket the way the probe subcommand does and
// returns the status and body of one route.
func probeAdmin(t *testing.T, socket, route string) (int, string) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://admin/"+route, nil)
	require.NoError(t, err, "build the %s request", route)
	resp, err := client.Do(req)
	require.NoError(t, err, "GET /%s on %s", route, socket)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read /%s", route)
	return resp.StatusCode, string(body)
}
