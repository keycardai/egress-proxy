package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/admin"
	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/internal/config"
	"github.com/keycardai/egress-proxy/internal/netsetup"
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
		"DNS_PORT":                "53",
		"DNS_FORWARD_TO":          "10.43.0.10,fd00::a",
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
		"MAX_DNS_CONNECTIONS":     "11",
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
		Connect: "127.0.0.1:2", TransparentPort: 1015, TransparentPortSet: true, DNSPort: 53, DNSPortSet: true,
		DNSForwardTo: []string{"10.43.0.10", "fd00::a"}, Admin: "/env/admin.sock",
		NetsetupReceipt: "/env/netsetup.json", CAOutDir: "/env/ca", CAStateDir: "/env/state",
		ClientSecretFile:     "/env/client-secret",
		CredentialStaticFile: "/env/credentials.yaml",
		LeafTTL:              2 * time.Hour, CacheSize: 5, UpstreamCAFiles: []string{"/env/a.pem", "/env/b.pem"},
		MaxConnections: 9, MaxDNSConnections: 11,
		IdleTimeout: 90 * time.Second, ResponseHeaderTimeout: 45 * time.Second,
		ExchangeTimeout: 7 * time.Second,
	}
	assert.Equal(t, "/env/config.yaml", got.configPath, "the config path comes from the variable")
	assert.Equal(t, want, got.overrides(), "every variable reaches the override the parser applies")
}

// TestCommandRequiresTheConfigPath checks that starting the proxy without a
// config path fails with errNoConfig. --config is not marked Required,
// because probe and settings run without it, so the serve action has to
// check for it.
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

// TestPortOverrides pins how a port flag and its variable replace the
// document's port. Zero from either one turns the listener off, so the
// override counts as set whenever the flag or the variable is present.
func TestPortOverrides(t *testing.T) {
	settings := []struct {
		flag string
		key  string
		get  func(*config.Config) int
	}{
		{
			flag: "transparent-port", key: "listen.transparent_port",
			get: func(cfg *config.Config) int { return cfg.Listen.TransparentPort },
		},
		{
			flag: "dns-port", key: "listen.dns_port",
			get: func(cfg *config.Config) int { return cfg.Listen.DNSPort },
		},
	}
	tests := []struct {
		name     string
		env      string
		args     []string
		unsetEnv bool
		want     int
	}{
		{name: "document without an override", unsetEnv: true, want: 1015},
		{name: "empty environment keeps the document", want: 1015},
		{name: "flag disables the listener", args: []string{"0"}, want: 0},
		{name: "environment disables the listener", env: "0", want: 0},
		{name: "flag disables the listener over environment", env: "1016", args: []string{"0"}, want: 0},
		{name: "flag enables the listener over environment", env: "0", args: []string{"1016"}, want: 1016},
	}
	for _, setting := range settings {
		variable := envPrefix + strings.ToUpper(strings.ReplaceAll(setting.flag, "-", "_"))
		document := "version: 1\nsandbox:\n  id: test\nlisten:\n  " +
			strings.TrimPrefix(setting.key, "listen.") + ": 1015\nendpoints:\n  - url: https://example.com/\n"
		for _, tc := range tests {
			t.Run(setting.flag+"/"+tc.name, func(t *testing.T) {
				t.Setenv(variable, tc.env)
				if tc.unsetEnv {
					require.NoError(t, os.Unsetenv(variable), "omit the environment override")
				}
				var cfg *config.Config
				cmd := command(io.Discard, io.Discard, func(_ context.Context, opts flags) error {
					var err error
					cfg, err = config.Parse([]byte(document), opts.overrides())
					require.NoError(t, err, "parse the document")
					return nil
				})
				args := []string{"egress-proxy", "--config", "/unused.yaml"}
				for _, value := range tc.args {
					args = append(args, "--"+setting.flag, value)
				}
				require.NoError(t, cmd.Run(t.Context(), args), "parse the command and document")
				require.NotNil(t, cfg, "the command loaded the document")
				assert.Equal(t, tc.want, setting.get(cfg), "the effective %s", setting.key)
				if tc.env != "" || len(tc.args) != 0 {
					assert.Contains(t, cfg.Overridden, setting.key, "record the supplied override")
				} else {
					assert.NotContains(t, cfg.Overridden, setting.key, "an omitted override leaves the document alone")
				}
			})
		}
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
		// result does not run a transparent frontend.
		transparentPort func(t *testing.T) int
		// families is what the netsetup receipt records the redirect
		// covers.
		families []string
		// listen binds the capture sockets. Nil binds them with
		// transparent.Listen.
		listen      func(ctx context.Context, port int) ([]net.Listener, error)
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
		{
			name:            "the receipt names ipv6 and only the ipv4 socket binds",
			transparentPort: freePort,
			families:        []string{"ipv4", "ipv6"},
			listen:          listenIPv4Only,
			wantErr: "the netsetup receipt names ipv4,ipv6 and the capture bound ipv4, " +
				"so the redirect sends ipv6 nowhere",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			connect := freeAddress(t)
			port := tc.transparentPort(t)
			proc := startingProcess(t, connect, port, tc.families)
			proc.listenCapture = tc.listen
			require.ErrorIs(t, proc.ready(), errNotReady, "readiness before bind")

			listener, captured, resolver, err := proc.bind(t.Context())
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr, "bind")
				require.ErrorIs(t, err, errCapture, "every refusal here is the transparent frontend's")
				require.ErrorIs(t, proc.ready(), errNotReady,
					"readiness answered after a listener that never bound")
				require.ErrorContains(t, proc.ready(), "the frontend listeners are not bound",
					"the 503 says which half is missing")
				// A bind that fails half way leaves nothing bound, so a
				// restart finds the CONNECT address free.
				reclaimed, reclaimErr := (&net.ListenConfig{}).Listen(t.Context(), "tcp", connect)
				require.NoError(t, reclaimErr, "the failed bind left the CONNECT listener open on %s", connect)
				require.NoError(t, reclaimed.Close(), "close the reclaimed CONNECT listener")
				if tc.listen != nil {
					capture := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
					reclaimed, reclaimErr = (&net.ListenConfig{}).Listen(t.Context(), "tcp4", capture)
					require.NoError(t, reclaimErr, "the refused capture left its socket open on %s", capture)
					require.NoError(t, reclaimed.Close(), "close the reclaimed capture socket")
				}
				return
			}
			require.NoError(t, err, "bind")
			t.Cleanup(func() { _ = listener.Close() })
			t.Cleanup(func() { _ = resolver.Close() })
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

// listenIPv4Only binds the capture the way transparent.Listen does on a
// kernel with no IPv6: the IPv4 socket and nothing else.
func listenIPv4Only(ctx context.Context, port int) ([]net.Listener, error) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	return []net.Listener{listener}, nil
}

// TestReadinessNeedsTheCertificate pins the second half of readiness. The
// workload trusts ca.crt, so a process whose listeners are bound is still
// not ready while the file is missing.
func TestReadinessNeedsTheCertificate(t *testing.T) {
	t.Parallel()
	proc := startingProcess(t, freeAddress(t), 0, nil)
	listener, _, _, err := proc.bind(t.Context())
	require.NoError(t, err, "bind")
	t.Cleanup(func() { _ = listener.Close() })
	require.NoError(t, proc.ready(), "readiness with the listener bound and the certificate on disk")

	pem, err := os.ReadFile(proc.certPath)
	require.NoError(t, err, "read the certificate")
	require.NoError(t, os.Remove(proc.certPath), "remove the certificate")
	notReady := proc.ready()
	require.ErrorIs(t, notReady, errNotReady, "readiness without the certificate")
	require.ErrorContains(t, notReady, proc.certPath+" is not readable", "the 503 names the missing file")

	//nolint:gosec // G703: certPath is under the test's own temporary directory
	require.NoError(t, os.WriteFile(proc.certPath, pem, 0o600), "restore the certificate")
	assert.NoError(t, proc.ready(), "readiness once the certificate is back")
}

// noPort does not run a transparent frontend.
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

// freePort is a loopback port that was free when it returned. Nothing holds
// it, so another socket can take it before the bind under test, and the row
// then fails with EADDRINUSE.
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

// freeAddress is a loopback address that was free when it returned.
// Nothing holds it until the bind under test.
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
	"listen:\n  connect: 127.0.0.1:0\nendpoints:\n  - url: https://example.com/\n"

// resolverDocument runs the allowlist resolver and no transparent
// frontend, which is the posture the rules still have to feed.
const resolverDocument = "version: 1\nsandbox:\n  id: bind-test\n" +
	"listen:\n  connect: 127.0.0.1:0\n  dns_port: 53\n" +
	"dns:\n  forward_to: [\"10.43.0.10\"]\nendpoints:\n  - url: https://example.com/\n"

// TestDNSInfoReportsTheResolverPort pins the dns object /info serves: a port
// of 0 when no resolver runs, and listen.dns_port when one does.
func TestDNSInfoReportsTheResolverPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		document string
		want     map[string]any
	}{
		{name: "no resolver", document: bindDocument, want: map[string]any{"port": 0}},
		{
			name:     "a resolver",
			document: resolverDocument,
			want: map[string]any{
				"port": 53, "resolves": []string{"example.com"}, "forward_to": []string{"10.43.0.10:53"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Parse([]byte(tc.document), config.Overrides{})
			require.NoError(t, err, "config.Parse:\n%s", tc.document)
			resolver, err := nameResolver(cfg, nil, audit.NewJSONSink(io.Discard), slog.New(slog.DiscardHandler))
			require.NoError(t, err, "build the resolver")
			proc := &process{cfg: cfg, resolver: resolver}
			assert.Equal(t, tc.want, proc.dnsInfo(), "the dns object in /info")
		})
	}
}

// TestTheReceiptIsReadForEverySurfaceTheRulesFeed pins which postures read
// the netsetup receipt. The rules deliver the captured connections and the
// redirected lookups, so a process that serves either one refuses to start
// without a receipt that agrees with it.
func TestTheReceiptIsReadForEverySurfaceTheRulesFeed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// document is what the sidecar was given.
		document string
		// wantErr is a substring of the refusal, empty where the posture
		// reads no receipt.
		wantErr string
	}{
		{name: "no capture and no resolver reads no receipt", document: bindDocument},
		{
			name:     "a resolver with no capture reads the receipt",
			document: resolverDocument,
			wantErr:  "no netsetup receipt",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Parse([]byte(tc.document), config.Overrides{})
			require.NoError(t, err, "config.Parse:\n%s", tc.document)
			cfg.Netsetup.Receipt = filepath.Join(t.TempDir(), "netsetup.json")

			receipt, err := containment(cfg, netsetup.ContainmentRequest{})
			if tc.wantErr == "" {
				require.NoError(t, err, "a posture behind no rules starts")
				assert.Nil(t, receipt, "no receipt is read")
				return
			}
			require.ErrorContains(t, err, tc.wantErr, "the refusal names what is missing")
			assert.Nil(t, receipt, "a refused start reads no receipt")
		})
	}
}

// TestCaptureFamiliesFollowTheSocketsThatBound reads the families off real
// listeners, because that is what the receipt is compared against.
// transparent.Listen leaves the IPv6 socket out on a kernel with no IPv6,
// so the rows bind each shape it can hand the comparison.
func TestCaptureFamiliesFollowTheSocketsThatBound(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// addresses are the sockets the capture bound.
		addresses []string
		// programmed is what the netsetup receipt records.
		programmed  []string
		wantBound   []string
		wantMissing []string
	}{
		{
			name: "both families bound", addresses: []string{"127.0.0.1:0", "[::1]:0"},
			programmed: []string{"ipv4", "ipv6"}, wantBound: []string{"ipv4", "ipv6"},
		},
		{
			name: "ipv4 alone against a receipt that names ipv4", addresses: []string{"127.0.0.1:0"},
			programmed: []string{"ipv4"}, wantBound: []string{"ipv4"},
		},
		{
			name: "ipv4 alone against a receipt that names both", addresses: []string{"127.0.0.1:0"},
			programmed: []string{"ipv4", "ipv6"}, wantBound: []string{"ipv4"},
			wantMissing: []string{"ipv6"},
		},
		{
			name: "ipv6 alone against a receipt that names both", addresses: []string{"[::1]:0"},
			programmed: []string{"ipv4", "ipv6"}, wantBound: []string{"ipv6"},
			wantMissing: []string{"ipv4"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			listeners := boundListeners(t, tc.addresses)
			t.Cleanup(func() { _ = closeAll(listeners) })

			bound := boundFamilies(listeners)
			assert.Equal(t, tc.wantBound, bound, "the families the sockets cover")
			assert.Equal(t, tc.wantMissing, missingFamilies(tc.programmed, bound),
				"the families the receipt names with no socket")
		})
	}
}

// boundListeners opens one socket per address, the shape transparent.Listen
// hands the bind.
func boundListeners(t *testing.T, addresses []string) []net.Listener {
	t.Helper()
	listeners := make([]net.Listener, 0, len(addresses))
	for _, address := range addresses {
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", address)
		require.NoError(t, err, "listen on %s", address)
		listeners = append(listeners, listener)
	}
	return listeners
}

// TestServeIsNotReadyOnceItStops covers the other end of the readiness
// contract. The admin socket stops accepting as the drain starts, and
// observing that mid-drain would race it. The test asserts the flag the
// shutdown path clears, which a /readyz request already in flight reads.
func TestServeIsNotReadyOnceItStops(t *testing.T) {
	t.Parallel()
	cfg, err := config.Parse([]byte(bindDocument), config.Overrides{})
	require.NoError(t, err, "config.Parse")
	cfg.Listen.Connect = freeAddress(t)
	cfg.Listen.Admin = socketPath(t)
	cfg.CA.OutDir = t.TempDir()

	proc, err := build(t.Context(), cfg, slog.New(slog.DiscardHandler), io.Discard)
	require.NoError(t, err, "build")

	ctx, cancel := context.WithCancel(t.Context())
	// The admin socket listens from build on, but serve accepts connections
	// only after the bind succeeds. If the bind fails, nothing ever answers
	// the probe, so the probe is cancelled as soon as serve returns.
	probeCtx, serveReturned := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() {
		serveErr := proc.serve(ctx)
		serveReturned()
		stopped <- serveErr
	}()

	// serve binds before it starts the admin server, so an answer on the
	// socket is the signal that the bind is done. Nothing here polls.
	status, body, err := probeAdmin(probeCtx, t, cfg.Listen.Admin, "readyz")
	if errors.Is(err, context.Canceled) {
		require.NoError(t, <-stopped, "serve returned before /readyz answered")
	}
	require.NoError(t, err, "GET /readyz")
	require.Equal(t, http.StatusOK, status, "/readyz once serve has bound: %s", body)

	cancel()
	require.NoError(t, <-stopped, "serve")
	require.ErrorIs(t, proc.ready(), errNotReady, "readiness after the drain")
	require.ErrorContains(t, proc.ready(), "the frontend listeners are not bound",
		"the 503 says the listeners are gone")
}

// probeAdmin dials the admin socket the way the probe subcommand does and
// returns the status and body of one route. It returns the error when the
// request gets no response, so the caller can say why.
func probeAdmin(ctx context.Context, t *testing.T, socket, route string) (int, string, error) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://admin/"+route, nil)
	require.NoError(t, err, "build the %s request", route)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("GET /%s on %s: %w", route, socket, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read /%s", route)
	return resp.StatusCode, string(body), nil
}
