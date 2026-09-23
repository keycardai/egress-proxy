package main

import (
	"context"
	"io"
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
	for name, value := range map[string]string{ //nolint:gosec // G101: paths to secrets, not secrets
		"CONFIG":                  "/env/config.yaml",
		"SANDBOX_ID":              "sbx-env",
		"ZONE_URL":                "https://env.example",
		"CLIENT_ID":               "env-client",
		"WORKLOAD_TOKEN_FILE":     "/env/token",
		"IMPERSONATE_USER":        "env-user",
		"CONNECT":                 "127.0.0.1:1",
		"ADMIN":                   "/env/admin.sock",
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

	want := config.Overrides{ //nolint:gosec // G101: paths to secrets, not secrets
		SandboxID: "sbx-env", ZoneURL: "https://env.example", ClientID: "env-client",
		WorkloadTokenFile: "/env/token", ImpersonateUser: "env-user",
		// The flag wins over EGRESS_PROXY_CONNECT.
		Connect: "127.0.0.1:2", Admin: "/env/admin.sock", CAOutDir: "/env/ca", CAStateDir: "/env/state",
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
