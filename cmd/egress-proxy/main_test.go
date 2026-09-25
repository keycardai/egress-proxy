package main

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/config"
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
	cmd := command(io.Discard, func(_ context.Context, opts flags) error {
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

func TestCommandRequiresTheConfigPath(t *testing.T) { //nolint:paralleltest // the environment must not supply it
	cmd := command(io.Discard, func(context.Context, flags) error { return nil })
	require.Error(t, cmd.Run(t.Context(), []string{"egress-proxy"}), "Run without --config")
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
			cmd := command(io.Discard, func(_ context.Context, opts flags) error {
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
