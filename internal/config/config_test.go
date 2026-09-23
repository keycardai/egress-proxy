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
	"github.com/keycardai/egress-proxy/internal/credential"
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
		// Zero means the setting was not named, as it does for the limits
		// and the cache size. A document cannot ask for port 0.
		{"endpoint port", cfg.Endpoints[0].Port, 443},
		{"endpoint path_prefix", cfg.Endpoints[0].PathPrefix, "/"},
		{"endpoint resource", cfg.Endpoints[0].Resource, "https://pypi.org/"},
		{"identity absent", cfg.Identity == nil, true},
	}
	for _, check := range checks {
		assert.Equal(t, check.want, check.got, "%s", check.name)
	}
}

// TestParseNormalizesTheEndpointHost pins how a host spelling reaches the
// rest of the process. Normalization runs before validation, so the two have
// to agree on which spellings are one name and which are no name at all.
func TestParseNormalizesTheEndpointHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		host string
		// wantHost is the normalized host, or empty when the document is
		// refused.
		wantHost string
		wantErr  string
	}{
		{name: "as written", host: "pypi.org", wantHost: "pypi.org"},
		{name: "with the root label", host: "pypi.org.", wantHost: "pypi.org"},
		{name: "in mixed case", host: "PyPI.ORG", wantHost: "pypi.org"},
		{name: "padded", host: " pypi.org. ", wantHost: "pypi.org"},
		// One trailing dot is the root label. A second one is an empty
		// label, which no name can carry. Normalization drops a single dot,
		// so the host still holds the empty label when it is validated.
		{name: "with two trailing dots", host: "pypi.org..", wantErr: "must be a DNS name"},
		{name: "with three trailing dots", host: "pypi.org...", wantErr: "must be a DNS name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - host: \"" + tc.host + "\"\n"
			cfg, err := config.Parse([]byte(doc), config.Overrides{})
			if tc.wantErr != "" {
				require.Error(t, err, "Parse")
				assert.Contains(t, err.Error(), tc.wantErr, "refusal")
				return
			}
			require.NoError(t, err, "Parse")
			assert.Equal(t, tc.wantHost, cfg.Endpoints[0].Host, "host")
			// The default resource is built from the normalized host, so two
			// spellings of one name produce one resource.
			assert.Equal(t, "https://"+tc.wantHost+"/", cfg.Endpoints[0].Resource, "resource")
		})
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

// twoEndpointsReversed lists the endpoints of minimal plus
// files.pythonhosted.org in the opposite document order.
const twoEndpointsReversed = "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n" +
	"  - host: files.pythonhosted.org\n  - host: pypi.org\n"

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
		{
			name:    "the same two endpoints in either order",
			doc:     minimal + "  - host: files.pythonhosted.org\n" + identityDoc,
			against: twoEndpointsReversed + identityDoc,
			// Compile sorts each host's prefixes and refuses a repeated
			// host and prefix pair, so document order decides nothing.
			wantSame: true,
		},
		{
			name: "the same two prefixes on one host in either order",
			doc: strings.Replace(minimal, "- host: pypi.org",
				"- host: pypi.org\n    path_prefix: /simple/\n  - host: pypi.org\n    path_prefix: /pypi/", 1) +
				identityDoc,
			against: strings.Replace(minimal, "- host: pypi.org",
				"- host: pypi.org\n    path_prefix: /pypi/\n  - host: pypi.org\n    path_prefix: /simple/", 1) +
				identityDoc,
			wantSame: true,
		},
		{
			name:    "the same two upstream roots in either order",
			doc:     minimal + identityDoc + "tls:\n  upstream_ca_files: [\"/a.pem\", \"/b.pem\"]\n",
			against: minimal + identityDoc + "tls:\n  upstream_ca_files: [\"/b.pem\", \"/a.pem\"]\n",
			// The same roots trust the same issuers whatever the order,
			// and a root named twice adds nothing.
			wantSame: true,
		},
		{
			name:     "an upstream root named twice",
			doc:      minimal + identityDoc + "tls:\n  upstream_ca_files: [\"/a.pem\"]\n",
			against:  minimal + identityDoc + "tls:\n  upstream_ca_files: [\"/a.pem\", \"/a.pem\"]\n",
			wantSame: true,
		},
		{
			name:    "the static source and the exchange",
			doc:     minimal + "credentials:\n  static_file: /creds.yaml\n",
			against: minimal + identityDoc,
			// A record has to name what answered. Two sidecars reading
			// different sources never share a digest.
			wantSame: false,
		},
		{
			name:     "two static files at different paths",
			doc:      minimal + "credentials:\n  static_file: /a.yaml\n",
			against:  minimal + "credentials:\n  static_file: /b.yaml\n",
			wantSame: false,
		},
		{
			name:    "an exchange on workload identity and one on a client secret",
			doc:     minimal + identityDoc,
			against: minimal + secretDoc,
			// The two mechanisms carry different authority to the zone.
			wantSame: false,
		},
		{
			name:      "the exchange budget, which bounds a call and decides nothing",
			doc:       minimal + identityDoc,
			overrides: config.Overrides{ExchangeTimeout: 42 * time.Second},
			wantSame:  true,
		},
		{
			name:     "the default port written out explicitly",
			doc:      strings.Replace(minimal, "- host: pypi.org", "- host: pypi.org\n    port: 443", 1) + identityDoc,
			wantSame: true,
		},
		{
			name: "another port on the same host",
			doc:  strings.Replace(minimal, "- host: pypi.org", "- host: pypi.org\n    port: 8443", 1) + identityDoc,
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
		{
			name:      "a credential source, which decides whether an endpoint can be reached",
			doc:       minimal,
			against:   minimal,
			overrides: config.Overrides{CredentialStaticFile: "/creds.yaml"}, //nolint:gosec // G101: a path
		},
		{
			name:      "a credential source written in the document or supplied by a variable",
			doc:       minimal,
			against:   minimal + "credentials:\n  static_file: /creds.yaml\n",
			overrides: config.Overrides{CredentialStaticFile: "/creds.yaml"}, //nolint:gosec // G101: a path
			wantSame:  true,
		},
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

// parseRefusal is one document Parse must refuse and the text that names the
// reason. The cases are grouped by what they refuse, so a failure names the
// part of the schema that changed.
type parseRefusal struct {
	name    string
	doc     string
	wantErr string
}

// runParseRefusals asserts Parse refuses every document and says why.
func runParseRefusals(t *testing.T, tests []parseRefusal) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := config.Parse([]byte(tc.doc), config.Overrides{})
			require.ErrorContains(t, err, tc.wantErr, "Parse:\n%s", tc.doc)
		})
	}
}

// TestParseRefusesMalformedDocuments covers the refusals the parser makes
// before any setting is read: a key that names no setting, a key given
// twice, two keys that name one setting, and a second document.
func TestParseRefusesMalformedDocuments(t *testing.T) {
	t.Parallel()
	runParseRefusals(t, []parseRefusal{
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
		{
			name:    "a second YAML document",
			doc:     minimal + "---\npolicy:\n  cluster_cidrs: [8.8.8.0/24]\n",
			wantErr: "invalid configuration",
		},
		{
			name:    "a trailing document separator",
			doc:     minimal + "---\n",
			wantErr: "the input holds more than one YAML document",
		},
	})
}

// TestParseAcceptsSeparatorLikeText pins the inputs that stay one document.
// A document end marker closes the only document, and "---" inside a scalar
// is text. The refusal of a second document must not widen to either.
func TestParseAcceptsSeparatorLikeText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		doc  string
	}{
		{name: "a trailing document end marker", doc: minimal + "...\n"},
		{
			name: "a separator inside a scalar",
			doc: "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - host: pypi.org\n" +
				"    credential:\n      env: TOKEN\n      placement:\n        kind: header\n" +
				"        name: Authorization\n        template: \"--- {credential}\"\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := config.Parse([]byte(tc.doc), config.Overrides{})
			require.NoError(t, err, "Parse:\n%s", tc.doc)
		})
	}
}

// TestParseRefusesInvalidSettings covers the process and per-instance
// settings, including the directory rules that keep the CA key off the
// shared mount.
func TestParseRefusesInvalidSettings(t *testing.T) {
	t.Parallel()
	runParseRefusals(t, []parseRefusal{
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
		{
			name:    "a relative upstream CA file",
			doc:     minimal + "tls:\n  upstream_ca_files: [\"upstream/ca.crt\"]\n",
			wantErr: `tls.upstream_ca_files[0] "upstream/ca.crt" must be an absolute path`,
		},
		{
			name:    "an upstream CA file that is only a dot segment",
			doc:     minimal + "tls:\n  upstream_ca_files: [\"./ca.crt\"]\n",
			wantErr: "must be an absolute path",
		},
		{
			name:    "an empty upstream CA file",
			doc:     minimal + "tls:\n  upstream_ca_files: [\"\"]\n",
			wantErr: "tls.upstream_ca_files[0] is empty",
		},
	})
}

// TestParseRefusesInvalidEndpoints covers the host forms, ports and path
// prefixes an endpoint can carry. A host must be a DNS name, so every
// spelling of an address is refused here.
func TestParseRefusesInvalidEndpoints(t *testing.T) {
	t.Parallel()
	endpoint := func(fields string) string {
		return "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - " + fields + "\n"
	}
	runParseRefusals(t, []parseRefusal{
		{name: "endpoint without host", doc: endpoint("path_prefix: /"), wantErr: "host is empty"},
		{name: "endpoint host with port", doc: endpoint("host: pypi.org:443"), wantErr: "must be a DNS name"},
		{name: "endpoint host with scheme", doc: endpoint("host: https://pypi.org"), wantErr: "must be a DNS name"},
		{name: "endpoint wildcard", doc: endpoint("host: \"*.pypi.org\""), wantErr: "must be a DNS name"},
		{name: "endpoint IP literal", doc: endpoint("host: 93.184.216.34"), wantErr: "is an IP literal"},
		{
			name:    "endpoint port above the range",
			doc:     endpoint("host: a.example\n    port: 70000"),
			wantErr: "port 70000 must be between",
		},
		{
			name:    "endpoint negative port",
			doc:     endpoint("host: a.example\n    port: -1"),
			wantErr: "port -1 must be between",
		},
		{name: "endpoint IPv6 literal", doc: endpoint("host: \"::1\""), wantErr: "is an IP literal"},
		// An address netip does not read as one still resolves as an
		// address. The deny list never sees these as addresses either, so
		// the endpoint list is the only place to refuse them.
		{name: "endpoint octal IPv4", doc: endpoint("host: 0177.0.0.1"), wantErr: "must be a DNS name"},
		{name: "endpoint IPv4 with a leading zero", doc: endpoint("host: 010.0.0.1"), wantErr: "must be a DNS name"},
		{
			name:    "endpoint IPv4 as one integer",
			doc:     endpoint("host: \"2852039166\""),
			wantErr: "must be a DNS name",
		},
		{name: "endpoint host with an underscore", doc: endpoint("host: pypi_org"), wantErr: "must be a DNS name"},
		// The matcher compares a prefix against the escaped path, so a
		// prefix holding a character a client always escapes could never
		// match.
		{
			name:    "path prefix with a space",
			doc:     endpoint("host: a.example\n    path_prefix: \"/my files/\""),
			wantErr: "path_prefix \"/my files/\" must be an absolute path",
		},
		{
			name:    "path prefix with a non-ASCII character",
			doc:     endpoint("host: a.example\n    path_prefix: /caf\u00e9/"),
			wantErr: "must be an absolute path",
		},
		{
			// Nothing unescapes a prefix, so a malformed escape would
			// prefix match by accident: "/a%" matches "/a%25b".
			name:    "path prefix with a malformed escape",
			doc:     endpoint("host: a.example\n    path_prefix: /a%zz"),
			wantErr: "must be an absolute path",
		},
		{
			name:    "path prefix ending in a bare percent",
			doc:     endpoint("host: a.example\n    path_prefix: /a%"),
			wantErr: "must be an absolute path",
		},
		{name: "endpoint host with a leading hyphen", doc: endpoint("host: -pypi.org"), wantErr: "must be a DNS name"},
		{name: "endpoint host with a trailing hyphen", doc: endpoint("host: pypi-.org"), wantErr: "must be a DNS name"},
		{name: "endpoint host with an empty label", doc: endpoint("host: pypi..org"), wantErr: "must be a DNS name"},
		// The SNI is ASCII, so a host holding non-ASCII characters never
		// matches what arrives. The first character here is Cyrillic a,
		// which reads as Latin a and would otherwise stand in for it.
		{name: "endpoint host in Cyrillic", doc: endpoint("host: аpple.com"), wantErr: "must be a DNS name"},
		{
			name:    "endpoint host with an ideographic full stop",
			doc:     endpoint("host: pypi.org。"),
			wantErr: "must be a DNS name",
		},
		{
			name:    "endpoint host label over 63 characters",
			doc:     endpoint("host: " + strings.Repeat("a", 64) + ".org"),
			wantErr: "must be a DNS name",
		},
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
	})
}

// TestParseRefusesInvalidCredentials covers the credential source and the
// placement that carries it.
func TestParseRefusesInvalidCredentials(t *testing.T) {
	t.Parallel()
	endpoint := func(fields string) string {
		return "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - " + fields + "\n"
	}
	runParseRefusals(t, []parseRefusal{
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
			name:    "a relative static credential file",
			doc:     minimal + "credentials:\n  static_file: creds.yaml\n",
			wantErr: "credentials.static_file",
		},
		{
			name:    "a static credential file together with an identity",
			doc:     minimal + "credentials:\n  static_file: /creds.yaml\n" + identityDoc,
			wantErr: "both name a credential source",
		},
		{
			name: "a header placement naming Host",
			doc: endpoint("host: a.example\n    credential:\n      env: T\n" +
				"      placement: {kind: header, name: host, template: \"{credential}\"}"),
			wantErr: "endpoints[0]: a header placement cannot name host, " +
				"a header the connection, the proxy or the upstream's trust depends on",
		},
		{
			name: "a header placement naming a hop-by-hop header",
			doc: endpoint("host: a.example\n    credential:\n      env: T\n" +
				"      placement: {kind: header, name: Connection, template: \"{credential}\"}"),
			wantErr: "endpoints[0]: a header placement cannot name Connection, ",
		},
		{
			name: "a header placement naming a body framing header",
			doc: endpoint("host: a.example\n    credential:\n      env: T\n" +
				"      placement: {kind: header, name: Content-Length, template: \"{credential}\"}"),
			wantErr: "endpoints[0]: a header placement cannot name Content-Length, ",
		},
		{
			name: "a header placement in the x-forwarded- family",
			doc: endpoint("host: a.example\n    credential:\n      env: T\n" +
				"      placement: {kind: header, name: X-Forwarded-For, template: \"{credential}\"}"),
			wantErr: "endpoints[0]: a header placement cannot name X-Forwarded-For, ",
		},
		{
			name: "a header placement in the sec- family",
			doc: endpoint("host: a.example\n    credential:\n      env: T\n" +
				"      placement: {kind: header, name: Sec-Fetch-Site, template: \"{credential}\"}"),
			wantErr: "endpoints[0]: a header placement cannot name Sec-Fetch-Site, ",
		},
	})
}

// TestParseAcceptsAnAuthorizationPlacement keeps the common placement allowed.
func TestParseAcceptsAnAuthorizationPlacement(t *testing.T) {
	t.Parallel()
	doc := "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - host: a.example\n    credential:\n" +
		"      env: GITHUB_TOKEN\n" +
		"      placement: {kind: header, name: Authorization, template: \"Bearer {credential}\"}\n"
	cfg, err := config.Parse([]byte(doc), config.Overrides{})
	require.NoError(t, err, "Parse:\n%s", doc)
	require.Len(t, cfg.Endpoints, 1, "the document names one endpoint")
	require.NotNil(t, cfg.Endpoints[0].Credential, "the endpoint names a credential")
	assert.Equal(t, "Authorization", cfg.Endpoints[0].Credential.Placement.Name, "placement.name")
}

// TestParseRefusesInvalidIdentity covers the exchange settings.
func TestParseRefusesInvalidIdentity(t *testing.T) {
	t.Parallel()
	runParseRefusals(t, []parseRefusal{
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
		{
			name: "identity with neither client authentication mechanism",
			doc: minimal + "identity:\n  zone_url: https://z\n  client_id: c\n" +
				"  impersonate: {user: u}\n",
			wantErr: "names no client authentication",
		},
		{
			name: "identity with both client authentication mechanisms",
			doc: minimal + "identity:\n  zone_url: https://z\n  client_id: c\n  workload_token_file: /t\n" +
				"  client_secret_file: /s\n  impersonate: {user: u}\n",
			wantErr: "both authenticate the exchange; configure one",
		},
		{
			name: "identity with a relative client secret file",
			doc: minimal + "identity:\n  zone_url: https://z\n  client_id: c\n  client_secret_file: s\n" +
				"  impersonate: {user: u}\n",
			wantErr: "identity.client_secret_file",
		},
	})
}

// secretDoc is the identity section that authenticates with a client
// secret. It differs from identityDoc only in the mechanism.
const secretDoc = "identity:\n  zone_url: https://z\n  client_id: c\n  client_secret_file: /s\n" +
	"  impersonate: {user: u}\n"

// TestCredentialSourceNamesTheSourceInForce pins what the process
// announces, what /info reports, and what the config digest covers.
func TestCredentialSourceNamesTheSourceInForce(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		doc  string
		want config.CredentialSourceKind
	}{
		{name: "no source", doc: minimal, want: config.SourceNone},
		{
			name: "a static file",
			doc:  minimal + "credentials:\n  static_file: /creds.yaml\n",
			want: config.SourceStaticFile,
		},
		{name: "an exchange on workload identity", doc: minimal + identityDoc, want: config.SourceExchange},
		{name: "an exchange on a client secret", doc: minimal + secretDoc, want: config.SourceExchange},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Parse([]byte(tc.doc), config.Overrides{})
			require.NoError(t, err, "Parse:\n%s", tc.doc)
			assert.Equal(t, tc.want, cfg.CredentialSource(), "the source in force")
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
		Host: "a.example", Port: config.DefaultEndpointPort, PathPrefix: "/api",
		Resource:   "https://a.example/",
		Credential: &credential.Placement{Kind: credential.KindHeader, Name: "X", Template: credential.Token},
	}, endpoints[1], "the second endpoint, normalized and defaulted")
	assert.Nil(t, endpoints[0].Credential, "pypi.org names no credential")
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
