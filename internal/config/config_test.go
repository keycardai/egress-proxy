package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/config"
	"github.com/keycardai/egress-proxy/internal/policy"
)

const minimal = "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - host: pypi.org\n"

func TestParseAppliesDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := config.Parse([]byte(minimal), config.Overrides{})
	require.NoError(t, err, "Parse")
	checks := []struct {
		name string
		got  any
		want any
	}{
		{"listen.connect", cfg.Listen.Connect, "127.0.0.1:3128"},
		{"listen.admin", cfg.Listen.Admin, "/run/egress/admin.sock"},
		{"ca.out_dir", cfg.CA.OutDir, "/shared-ca"},
		{"ca.state_dir", cfg.CA.StateDir, ""},
		{"ca.leaf_ttl", cfg.CA.LeafTTL.Duration(), 24 * time.Hour},
		{"ca.cache_size", cfg.CA.CacheSize, 1024},
		{"limits.max_connections", cfg.Limits.MaxConnections, 1024},
		{"limits.idle_timeout", cfg.Limits.IdleTimeout.Duration(), 5 * time.Minute},
		{"limits.response_header_timeout", cfg.Limits.ResponseHeaderTimeout.Duration(), 30 * time.Second},
		{"endpoint path_prefix", cfg.Endpoints[0].PathPrefix, "/"},
		{"endpoint resource", cfg.Endpoints[0].Resource, "https://pypi.org/"},
		{"identity absent", cfg.Identity == nil, true},
	}
	for _, check := range checks {
		assert.Equal(t, check.want, check.got, "%s", check.name)
	}
}

func TestDigestIsOverTheDocumentAsWritten(t *testing.T) {
	t.Parallel()
	yamlForm, err := config.Parse([]byte(minimal), config.Overrides{})
	require.NoError(t, err)
	// The same document as JSON, keys in another order, extra whitespace.
	jsonForm, err := config.Parse([]byte(`{"endpoints": [{"host": "pypi.org"}],
	  "sandbox": {"id": "sbx-1"}, "version": 1}`), config.Overrides{})
	require.NoError(t, err)
	assert.Equal(t, yamlForm.Digest, jsonForm.Digest, "the YAML and JSON forms of one document")
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, yamlForm.Digest, "the digest form")
	// A default written out explicitly is a different document.
	explicit, err := config.Parse([]byte(minimal+"listen:\n  connect: \"127.0.0.1:3128\"\n"), config.Overrides{})
	require.NoError(t, err)
	assert.NotEqual(t, yamlForm.Digest, explicit.Digest, "writing a default explicitly changes the digest")
	// An override does not change it either: it identifies the document as
	// mounted.
	overridden, err := config.Parse([]byte(minimal), config.Overrides{Connect: "127.0.0.1:0", SandboxID: "sbx-2"})
	require.NoError(t, err)
	assert.Equal(t, yamlForm.Digest, overridden.Digest, "an override leaves the document digest alone")
	// Those overrides decide nothing, so the effective settings, and the
	// digest over them, are the same too.
	assert.Equal(t, yamlForm.ConfigDigest, overridden.ConfigDigest,
		"an override that decides nothing leaves the config digest alone")
}

// identityDoc is the identity section the config digest tests share.
const identityDoc = "identity:\n  zone_url: https://z\n  client_id: c\n  workload_token_file: /t\n" +
	"  impersonate: {user: u}\n"

// TestConfigDigestCoversTheEffectiveSettings pins the property the audit
// record needs. Two processes that answer every request alike share a config
// digest, whatever document, flag or variable each one was given, and two
// that answer differently never do.
func TestConfigDigestCoversTheEffectiveSettings(t *testing.T) {
	t.Parallel()
	digestOf := func(t *testing.T, doc string, overrides config.Overrides) string {
		t.Helper()
		cfg, err := config.Parse([]byte(doc), overrides)
		require.NoError(t, err, "Parse:\n%s", doc)
		return cfg.ConfigDigest
	}
	base := digestOf(t, minimal+identityDoc, config.Overrides{})
	require.Regexp(t, `^sha256:[0-9a-f]{64}$`, base, "the config digest form")

	tests := []struct {
		name string
		doc  string
		// against is the document the case is compared with. Empty means
		// the base.
		against   string
		overrides config.Overrides
		wantSame  bool
	}{
		{name: "the same document twice", doc: minimal + identityDoc, wantSame: true},
		{
			name: "a value written in the document or supplied by a variable",
			doc: minimal + "identity:\n  zone_url: https://z\n  client_id: c\n" +
				"  workload_token_file: /t\n",
			overrides: config.Overrides{ImpersonateUser: "u"},
			wantSame:  true,
		},
		{
			name:     "a default written out explicitly",
			doc:      minimal + identityDoc + "limits:\n  max_connections: 1024\n  idle_timeout: 5m\n",
			wantSame: true,
		},
		{
			name: "settings that decide nothing",
			doc:  minimal + identityDoc,
			overrides: config.Overrides{
				Connect: "127.0.0.1:9", Admin: "/other/admin.sock", CAOutDir: "/other/ca",
				CacheSize: 7, MaxConnections: 3, SandboxID: "another-sandbox",
			},
			wantSame: true,
		},
		{
			name:     "a cluster range in another spelling and order",
			doc:      minimal + identityDoc + "policy:\n  cluster_cidrs: [\"10.42.0.0/16\"]\n",
			against:  minimal + identityDoc + "policy:\n  cluster_cidrs: [\"10.42.0.1/16\", \"10.42.0.0/16\"]\n",
			wantSame: true,
		},
		{name: "another endpoint", doc: minimal + "  - host: files.pythonhosted.org\n" + identityDoc},
		{
			name: "another path prefix",
			doc: strings.Replace(minimal, "- host: pypi.org", "- host: pypi.org\n    path_prefix: /simple/", 1) +
				identityDoc,
		},
		{
			name:      "another impersonated user",
			doc:       minimal + identityDoc,
			overrides: config.Overrides{ImpersonateUser: "other"},
		},
		{name: "another zone", doc: minimal + identityDoc, overrides: config.Overrides{ZoneURL: "https://other"}},
		{
			name:      "an added upstream root",
			doc:       minimal + identityDoc,
			overrides: config.Overrides{UpstreamCAFiles: []string{"/extra.pem"}},
		},
		{name: "a cluster range", doc: minimal + identityDoc + "policy:\n  cluster_cidrs: [\"10.42.0.0/16\"]\n"},
		{
			name: "a deny list exception",
			doc:  minimal + identityDoc + "policy:\n  deny_list_exceptions: [\"127.0.0.0/8\"]\n",
		},
		{name: "no identity at all", doc: minimal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			want := base
			if tc.against != "" {
				want = digestOf(t, tc.against, config.Overrides{})
			}
			got := digestOf(t, tc.doc, tc.overrides)
			if tc.wantSame {
				assert.Equal(t, want, got, "the settings decide alike, so the digests match")
				return
			}
			assert.NotEqual(t, want, got, "the settings decide differently, so the digests differ")
		})
	}
}

func TestParseRefusals(t *testing.T) {
	t.Parallel()
	endpoint := func(fields string) string {
		return "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - " + fields + "\n"
	}
	tests := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{name: "unknown key", doc: minimal + "bogus: 1\n", wantErr: `unknown field "bogus"`},
		{name: "unknown nested key", doc: minimal + "listen:\n  port: 1\n", wantErr: `unknown field "port"`},
		{name: "repeated key", doc: minimal + "sandbox:\n  id: sbx-2\n", wantErr: `key "sandbox" already set`},
		{
			name:    "keys differing only in case",
			doc:     minimal + "Listen:\n  connect: \"127.0.0.1:1\"\nlisten:\n  admin: /a\n",
			wantErr: `keys that differ only in case name one setting: "Listen" and "listen" at the top level`,
		},
		{
			name:    "keys differing only in case, nested",
			doc:     minimal + "listen:\n  connect: \"127.0.0.1:1\"\n  Connect: \"127.0.0.1:2\"\n",
			wantErr: `"Connect" and "connect" at listen`,
		},
		{
			name:    "a leading marker with content is not a mapping",
			doc:     "--- actually broken\n" + minimal,
			wantErr: "invalid configuration",
		},
		{name: "wrong version", doc: strings.Replace(minimal, "version: 1", "version: 2", 1), wantErr: "version is 2"},
		{name: "no sandbox id", doc: strings.Replace(minimal, "id: sbx-1", `id: ""`, 1), wantErr: "sandbox.id"},
		{
			name:    "sandbox id with whitespace",
			doc:     strings.Replace(minimal, "id: sbx-1", "id: sbx 1", 1),
			wantErr: "sandbox.id",
		},
		{name: "relative admin socket", doc: minimal + "listen:\n  admin: admin.sock\n", wantErr: "listen.admin"},
		{name: "connect without a port", doc: minimal + "listen:\n  connect: 127.0.0.1\n", wantErr: "listen.connect"},
		{
			name:    "state dir under out dir",
			doc:     minimal + "ca:\n  out_dir: /shared-ca\n  state_dir: /shared-ca/key\n",
			wantErr: "overlaps ca.out_dir",
		},
		{
			name:    "state dir under out dir, written with a trailing slash",
			doc:     minimal + "ca:\n  out_dir: /shared-ca/\n  state_dir: /shared-ca/state\n",
			wantErr: "overlaps ca.out_dir",
		},
		{
			name:    "state dir under out dir, reached through a dot segment",
			doc:     minimal + "ca:\n  out_dir: /shared-ca\n  state_dir: /shared-ca/../shared-ca/state\n",
			wantErr: "overlaps ca.out_dir",
		},
		{
			name:    "state dir is the out dir",
			doc:     minimal + "ca:\n  out_dir: /shared-ca\n  state_dir: /shared-ca\n",
			wantErr: "overlaps ca.out_dir",
		},
		{
			name:    "out dir under state dir",
			doc:     minimal + "ca:\n  out_dir: /run/egress/ca/shared\n  state_dir: /run/egress/ca\n",
			wantErr: "overlaps ca.out_dir",
		},
		{
			name:    "a negative response header timeout",
			doc:     minimal + "limits:\n  response_header_timeout: -1s\n",
			wantErr: "limits.response_header_timeout",
		},
		{
			name:    "a negative idle timeout",
			doc:     minimal + "limits:\n  idle_timeout: -1s\n",
			wantErr: "limits.idle_timeout",
		},
		{
			name:    "leaf ttl not a duration",
			doc:     minimal + "ca:\n  leaf_ttl: 24\n",
			wantErr: "a duration is written as a string",
		},
		{name: "leaf ttl malformed", doc: minimal + "ca:\n  leaf_ttl: soon\n", wantErr: `"soon" is not a duration`},
		{name: "zero connections", doc: minimal + "limits:\n  max_connections: -1\n", wantErr: "limits.max_connections"},
		{
			name:    "bad cluster cidr",
			doc:     minimal + "policy:\n  cluster_cidrs: [\"10.0.0.0\"]\n",
			wantErr: "policy.cluster_cidrs[0]",
		},
		{
			name:    "bad exception",
			doc:     minimal + "policy:\n  deny_list_exceptions: [x]\n",
			wantErr: "policy.deny_list_exceptions[0]",
		},
		{name: "endpoint without host", doc: endpoint("path_prefix: /"), wantErr: "host is empty"},
		{name: "endpoint host with port", doc: endpoint("host: pypi.org:443"), wantErr: "without a scheme, port"},
		{name: "endpoint host with scheme", doc: endpoint("host: https://pypi.org"), wantErr: "without a scheme, port"},
		{name: "endpoint wildcard", doc: endpoint("host: \"*.pypi.org\""), wantErr: "without a scheme, port"},
		{name: "endpoint IP literal", doc: endpoint("host: 93.184.216.34"), wantErr: "is an IP literal"},
		{name: "relative prefix", doc: endpoint("host: pypi.org\n    path_prefix: simple/"), wantErr: "path_prefix"},
		{
			name:    "prefix with dot segments",
			doc:     endpoint("host: pypi.org\n    path_prefix: /a/../b"),
			wantErr: "path_prefix",
		},
		{name: "prefix with a query", doc: endpoint("host: pypi.org\n    path_prefix: /a?x"), wantErr: "path_prefix"},
		{
			name:    "http resource",
			doc:     endpoint("host: pypi.org\n    resource: http://pypi.org/"),
			wantErr: "absolute https URL",
		},
		{
			name:    "resource with userinfo",
			doc:     endpoint("host: pypi.org\n    resource: https://u@pypi.org/"),
			wantErr: "no userinfo",
		},
		{
			name:    "repeated endpoint",
			doc:     endpoint("host: pypi.org\n  - host: PYPI.ORG."),
			wantErr: `host "pypi.org" with path_prefix "/" repeats endpoints[0]`,
		},
		{
			name: "credential without env",
			doc: endpoint(
				"host: a.example\n    credential:\n      placement: {kind: header, name: X, template: \"{credential}\"}",
			),
			wantErr: "credential.env",
		},
		{
			name: "credential env not a name",
			doc: endpoint("host: a.example\n    credential:\n      env: 1TOKEN\n" +
				"      placement: {kind: header, name: X, template: \"{credential}\"}"),
			wantErr: `credential.env "1TOKEN"`,
		},
		{
			name: "header placement without the token",
			doc: endpoint(
				"host: a.example\n    credential:\n      env: T\n      placement: {kind: header, name: X, template: Bearer}",
			),
			wantErr: "must contain {credential}",
		},
		{
			name: "header placement without a name",
			doc: endpoint(
				"host: a.example\n    credential:\n      env: T\n      placement: {kind: header, template: \"{credential}\"}",
			),
			wantErr: "header placement needs a name",
		},
		{
			name:    "query placement without a name",
			doc:     endpoint("host: a.example\n    credential:\n      env: T\n      placement: {kind: query}"),
			wantErr: "query placement needs a name",
		},
		{
			name:    "basic placement without a user",
			doc:     endpoint("host: a.example\n    credential:\n      env: T\n      placement: {kind: basic}"),
			wantErr: "basic placement needs a user",
		},
		{
			name:    "unknown placement kind",
			doc:     endpoint("host: a.example\n    credential:\n      env: T\n      placement: {kind: cookie, name: x}"),
			wantErr: `placement.kind "cookie"`,
		},
		{
			name: "identity with an http zone",
			doc: minimal + "identity:\n  zone_url: http://z\n  client_id: c\n  workload_token_file: /t\n" +
				"  impersonate: {user: u}\n",
			wantErr: "identity.zone_url",
		},
		{
			name: "identity with a relative token file",
			doc: minimal + "identity:\n  zone_url: https://z\n  client_id: c\n  workload_token_file: t\n" +
				"  impersonate: {user: u}\n",
			wantErr: "identity.workload_token_file",
		},
		{
			name:    "identity without a user",
			doc:     minimal + "identity:\n  zone_url: https://z\n  client_id: c\n  workload_token_file: /t\n",
			wantErr: "identity.impersonate.user is empty",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := config.Parse([]byte(tc.doc), config.Overrides{})
			require.ErrorContains(t, err, tc.wantErr, "Parse:\n%s", tc.doc)
		})
	}
}

func TestParseReportsEveryProblem(t *testing.T) {
	t.Parallel()
	_, err := config.Parse([]byte("version: 2\nsandbox:\n  id: \"\"\nendpoints:\n  - host: \"\"\n"), config.Overrides{})
	require.Error(t, err, "a document with three problems is refused")
	for _, want := range []string{"version is 2", "sandbox.id", "host is empty"} {
		assert.ErrorContains(t, err, want, "one run names every problem")
	}
}

func TestPolicyEndpoints(t *testing.T) {
	t.Parallel()
	cfg, err := config.Parse([]byte(minimal+
		"  - host: A.Example.\n    path_prefix: /api\n    credential:\n      env: T\n"+
		"      placement: {kind: header, name: X, template: \"{credential}\"}\n"), config.Overrides{})
	require.NoError(t, err)
	endpoints := cfg.PolicyEndpoints()
	require.Len(t, endpoints, 2)
	assert.Equal(t, policy.Endpoint{
		Host: "a.example", PathPrefix: "/api", Resource: "https://a.example/", HasCredential: true,
	}, endpoints[1], "the second endpoint, normalized and defaulted")
	assert.False(t, endpoints[0].HasCredential, "pypi.org names no credential")
}

func TestUpstreamRoots(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	require.NoError(t, os.WriteFile(empty, []byte("not a certificate\n"), 0o600))
	tests := []struct {
		name    string
		files   []string
		wantErr string
	}{
		{name: "no files is the system roots"},
		{name: "a missing file", files: []string{filepath.Join(dir, "missing.pem")}, wantErr: "missing.pem"},
		{name: "a file with no certificate", files: []string{empty}, wantErr: "holds no certificate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{}
			cfg.TLS.UpstreamCAFiles = tc.files
			pool, err := cfg.UpstreamRoots()
			if tc.wantErr == "" {
				require.NoError(t, err, "UpstreamRoots")
				assert.NotNil(t, pool, "the system roots")
				return
			}
			require.ErrorContains(t, err, tc.wantErr, "UpstreamRoots")
		})
	}
}

// TestEveryEarlierExampleStillParses reads testdata/compat and the example
// document at the repository root.
func TestEveryEarlierExampleStillParses(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(filepath.Join("testdata", "compat"))
	require.NoError(t, err)
	paths := []string{filepath.Join("..", "..", "config.example.yaml")}
	for _, entry := range entries {
		if !entry.IsDir() {
			paths = append(paths, filepath.Join("testdata", "compat", entry.Name()))
		}
	}
	require.GreaterOrEqual(t, len(paths), 2, "testdata/compat is empty, so this test proves nothing")
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Load(path, config.Overrides{})
			require.NoError(t, err, "Load")
			assert.NotEmpty(t, cfg.Endpoints, "the example names at least one endpoint")
		})
	}
}
