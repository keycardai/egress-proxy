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

const minimal = "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - url: https://pypi.org/\n"

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
		{"listen.admin", cfg.Listen.Admin, "/run/egress/admin/admin.sock"},
		// Zero disables the transparent frontend.
		{"listen.transparent_port", cfg.Listen.TransparentPort, 0},
		// Zero runs no resolver.
		{"listen.dns_port", cfg.Listen.DNSPort, 0},
		{"listen.cleartext_ports", cfg.Listen.CleartextPorts, []int{80}},
		{"netsetup.receipt", cfg.Netsetup.Receipt, "/run/egress/netsetup/netsetup.json"},
		{"ca.out_dir", cfg.CA.OutDir, "/shared-ca/out"},
		{"ca.state_dir", cfg.CA.StateDir, ""},
		{"ca.leaf_ttl", cfg.CA.LeafTTL.Duration(), 24 * time.Hour},
		{"ca.cache_size", cfg.CA.CacheSize, 1024},
		{"limits.max_connections", cfg.Limits.MaxConnections, 1024},
		{"limits.max_dns_connections", cfg.Limits.MaxDNSConnections, 128},
		{"limits.idle_timeout", cfg.Limits.IdleTimeout.Duration(), 5 * time.Minute},
		{"limits.response_header_timeout", cfg.Limits.ResponseHeaderTimeout.Duration(), 30 * time.Second},
		// Zero means the setting was not named, as it does for the limits
		// and the cache size. A document cannot ask for port 0.
		{"endpoint port", cfg.Endpoints[0].Port, 443},
		{"endpoint path_prefix", cfg.Endpoints[0].PathPrefix, "/"},
		{"endpoint resource", cfg.Endpoints[0].Resource, "https://pypi.org"},
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
		// One trailing dot is the root label. A second one is an empty
		// label, which a name cannot hold. Normalization drops a single dot,
		// so the host still holds the empty label when it is validated.
		{name: "with two trailing dots", host: "pypi.org..", wantErr: "must be a DNS name"},
		{name: "with three trailing dots", host: "pypi.org...", wantErr: "must be a DNS name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - url: \"https://" + tc.host + "/\"\n"
			cfg, err := config.Parse([]byte(doc), config.Overrides{})
			if tc.wantErr != "" {
				require.Error(t, err, "Parse")
				assert.Contains(t, err.Error(), tc.wantErr, "refusal")
				return
			}
			require.NoError(t, err, "Parse")
			assert.Equal(t, tc.wantHost, cfg.Endpoints[0].Host, "host")
			// The resource is built from the normalized host, so two
			// spellings of one name produce one resource.
			assert.Equal(t, "https://"+tc.wantHost, cfg.Endpoints[0].Resource, "resource")
		})
	}
}

func TestDigestIsOverTheDocumentAsWritten(t *testing.T) {
	t.Parallel()
	yamlForm, err := config.Parse([]byte(minimal), config.Overrides{})
	require.NoError(t, err)
	// The same document as JSON, keys in another order, extra whitespace.
	jsonForm, err := config.Parse([]byte(`{"endpoints": [{"url": "https://pypi.org/"}],
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

// transparentDoc returns a listen section with a transparent frontend. A
// case appends its own cleartext_ports field.
const transparentDoc = "listen:\n  transparent_port: 1015\n"

// twoEndpointsReversed lists the endpoints of minimal plus
// files.pythonhosted.org in the opposite document order.
const twoEndpointsReversed = "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n" +
	"  - url: https://files.pythonhosted.org/\n  - url: https://pypi.org/\n"

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
				Connect: "127.0.0.1:9", Admin: "/other/admin.sock",
				NetsetupReceipt: "/other/netsetup.json", CAOutDir: "/other/ca",
				CacheSize: 7, MaxConnections: 3, MaxDNSConnections: 5, SandboxID: "another-sandbox",
				// The resolver's port decides no answer. Which names
				// resolve comes from the endpoints and the zone, which the
				// digest already covers, so the forward targets decide no
				// answer either: the proxy re-resolves a name on the dial,
				// and a forward target that lies steers no connection.
				DNSPort: 53, DNSForwardTo: []string{"10.43.0.10"},
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
			doc:     minimal + "  - url: https://files.pythonhosted.org/\n" + identityDoc,
			against: twoEndpointsReversed + identityDoc,
			// Compile sorts each host's prefixes and refuses a repeated
			// host and prefix pair, so document order decides nothing.
			wantSame: true,
		},
		{
			name: "the same two prefixes on one host in either order",
			doc: strings.Replace(minimal, "- url: https://pypi.org/",
				"- url: https://pypi.org/simple/\n  - url: https://pypi.org/pypi/", 1) +
				identityDoc,
			against: strings.Replace(minimal, "- url: https://pypi.org/",
				"- url: https://pypi.org/pypi/\n  - url: https://pypi.org/simple/", 1) +
				identityDoc,
			wantSame: true,
		},
		{
			name:     "the same cleartext ports in either order",
			doc:      minimal + identityDoc + transparentDoc + "  cleartext_ports: [80, 8080]\n",
			against:  minimal + identityDoc + transparentDoc + "  cleartext_ports: [8080, 80, 80]\n",
			wantSame: true,
		},
		{
			name:    "another cleartext port, which decides what a captured connection is read as",
			doc:     minimal + identityDoc + transparentDoc + "  cleartext_ports: [8080]\n",
			against: minimal + identityDoc + transparentDoc,
		},
		{
			name:     "cleartext ports with no transparent frontend, where nothing is captured",
			doc:      minimal + identityDoc + "listen:\n  cleartext_ports: [8080]\n",
			wantSame: true,
		},
		{
			name:     "the transparent frontend on another port",
			doc:      minimal + identityDoc + transparentDoc,
			against:  minimal + identityDoc + "listen:\n  transparent_port: 1016\n",
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
			// A record names the source that answered. Two sidecars that read
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
			// The two mechanisms give the zone different authority.
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
			doc:      strings.Replace(minimal, "- url: https://pypi.org/", "- url: https://pypi.org:443/", 1) + identityDoc,
			wantSame: true,
		},
		{
			name: "another port on the same host",
			doc:  strings.Replace(minimal, "- url: https://pypi.org/", "- url: https://pypi.org:8443/", 1) + identityDoc,
		},
		{name: "another endpoint", doc: minimal + "  - url: https://files.pythonhosted.org/\n" + identityDoc},
		{
			name: "another path prefix",
			doc: strings.Replace(minimal, "- url: https://pypi.org/", "- url: https://pypi.org/simple/", 1) +
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

// TestDNSHostsAreDerivedFromTheDocument pins the allowlist the resolver
// answers for. config.DNS says why no setting names it.
func TestDNSHostsAreDerivedFromTheDocument(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		doc  string
		want []string
		port int
	}{
		{
			name: "the endpoint hosts alone when the document names no zone",
			doc:  minimal + "listen:\n  dns_port: 53\ndns:\n  forward_to: [\"10.43.0.10\"]\n",
			want: []string{"pypi.org"},
			port: 53,
		},
		{
			name: "the endpoint hosts and the zone host",
			doc:  minimal + identityDoc,
			want: []string{"pypi.org", "z"},
		},
		{
			name: "a host normalized the way the endpoint list holds it",
			doc:  strings.Replace(minimal, "- url: https://pypi.org/", "- url: https://PyPI.ORG/", 1),
			want: []string{"pypi.org"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Parse([]byte(tc.doc), config.Overrides{})
			require.NoError(t, err, "Parse:\n%s", tc.doc)
			assert.Equal(t, tc.want, cfg.DNSHosts(), "the names the resolver answers for")
			assert.Equal(t, tc.port, cfg.Listen.DNSPort, "the port the containment check compares")
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
			doc: "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - url: https://pypi.org/\n" +
				"    credential:\n      placement:\n        kind: header\n" +
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
		{
			name:    "a transparent port above 65535",
			doc:     minimal + "listen:\n  transparent_port: 99999\n",
			wantErr: "listen.transparent_port is 99999, outside 1-65535",
		},
		{
			name:    "a negative transparent port",
			doc:     minimal + "listen:\n  transparent_port: -1\n",
			wantErr: "listen.transparent_port is -1, outside 1-65535",
		},
		{
			// The frontend binds loopback alone, so the document names no
			// address for it.
			name:    "a transparent address",
			doc:     minimal + "listen:\n  transparent: \"0.0.0.0:1015\"\n",
			wantErr: `unknown field "transparent"`,
		},
		{
			name: "a cleartext port outside 1-65535",
			doc:  minimal + "listen:\n  cleartext_ports: [0]\n", wantErr: "listen.cleartext_ports[0] is 0",
		},
		{
			name:    "a transparent frontend with a relative receipt path",
			doc:     minimal + "listen:\n  transparent_port: 1015\nnetsetup:\n  receipt: netsetup.json\n",
			wantErr: "netsetup.receipt",
		},
		{name: "connect without a port", doc: minimal + "listen:\n  connect: 127.0.0.1\n", wantErr: "listen.connect"},
		{
			name:    "a resolver port of -1",
			doc:     minimal + "listen:\n  dns_port: -1\n",
			wantErr: "listen.dns_port is -1, outside 1-65535",
		},
		{
			name:    "a resolver port above 65535",
			doc:     minimal + "listen:\n  dns_port: 65536\n",
			wantErr: "listen.dns_port is 65536, outside 1-65535",
		},
		{
			// The resolver binds 127.0.0.1 and ::1 alone, so the document
			// names no address for it.
			name:    "a resolver address",
			doc:     minimal + "listen:\n  dns: \"127.0.0.1:53\"\n",
			wantErr: `unknown field "dns"`,
		},
		{
			name:    "a forward target that is a hostname",
			doc:     minimal + "listen:\n  dns_port: 53\ndns:\n  forward_to: [\"kube-dns\"]\n",
			wantErr: "dns.forward_to[0] \"kube-dns\" must be an IP address or address:port",
		},
		{
			name:    "forward targets with no resolver to read them",
			doc:     minimal + "dns:\n  forward_to: [\"10.43.0.10\"]\n",
			wantErr: "listen.dns_port is unset, so nothing reads them",
		},
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
			name:    "zero resolver connections",
			doc:     minimal + "limits:\n  max_dns_connections: -1\n",
			wantErr: "limits.max_dns_connections must be at least 1",
		},
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

// TestParseRefusesInvalidEndpoints covers the URL forms, hosts, ports and
// paths an endpoint can name. A host must be a DNS name, so every
// spelling of an address is refused here.
func TestParseRefusesInvalidEndpoints(t *testing.T) {
	t.Parallel()
	endpoint := func(fields string) string {
		return "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - " + fields + "\n"
	}
	runParseRefusals(t, []parseRefusal{
		{name: "endpoint without url", doc: endpoint(`url: ""`), wantErr: "must be an absolute http or https URL"},
		{name: "endpoint url without a scheme", doc: endpoint("url: pypi.org"), wantErr: "must be an absolute http"},
		{name: "endpoint url over ftp", doc: endpoint("url: ftp://pypi.org/"), wantErr: "must be an absolute http"},
		{
			name: "a credential on an http endpoint",
			doc: endpoint("url: http://pypi.org/\n    credential:\n" +
				"      placement: {kind: header, name: X, template: \"{credential}\"}"),
			wantErr: `url "http://pypi.org/" is http, and the proxy forwards nothing cleartext`,
		},
		{name: "endpoint wildcard", doc: endpoint(`url: "https://*.pypi.org/"`), wantErr: "must be a DNS name"},
		{name: "endpoint IP literal", doc: endpoint("url: https://93.184.216.34/"), wantErr: "is an IP literal"},
		{name: "endpoint IPv6 literal", doc: endpoint(`url: "https://[::1]/"`), wantErr: "is an IP literal"},
		{
			name:    "endpoint port above the range",
			doc:     endpoint("url: https://a.example:70000/"),
			wantErr: `must name a port between 1 and 65535, not "70000"`,
		},
		{name: "endpoint port zero", doc: endpoint("url: https://a.example:0/"), wantErr: `not "0"`},
		{name: "endpoint negative port", doc: endpoint("url: https://a.example:-1/"), wantErr: "is not a URL"},
		{name: "endpoint url with no host", doc: endpoint("url: https://:8443/"), wantErr: "names no host"},
		// An address netip does not read as one still resolves as an
		// address. The deny list never sees these as addresses either, so
		// the endpoint list is the only place to refuse them.
		{name: "endpoint octal IPv4", doc: endpoint("url: https://0177.0.0.1/"), wantErr: "must be a DNS name"},
		{
			name:    "endpoint IPv4 with a leading zero",
			doc:     endpoint("url: https://010.0.0.1/"),
			wantErr: "must be a DNS name",
		},
		{name: "endpoint IPv4 as one integer", doc: endpoint("url: https://2852039166/"), wantErr: "must be a DNS name"},
		{name: "endpoint host with an underscore", doc: endpoint("url: https://pypi_org/"), wantErr: "must be a DNS name"},
		{
			name:    "endpoint host with a leading hyphen",
			doc:     endpoint("url: https://-pypi.org/"),
			wantErr: "must be a DNS name",
		},
		{
			name:    "endpoint host with a trailing hyphen",
			doc:     endpoint("url: https://pypi-.org/"),
			wantErr: "must be a DNS name",
		},
		{
			name:    "endpoint host with an empty label",
			doc:     endpoint("url: https://pypi..org/"),
			wantErr: "must be a DNS name",
		},
		// The SNI is ASCII, so a host holding non-ASCII characters never
		// matches what arrives. The first character here is Cyrillic a,
		// which reads as Latin a and would otherwise stand in for it.
		{name: "endpoint host in Cyrillic", doc: endpoint("url: https://аpple.com/"), wantErr: "must be a DNS name"},
		{
			name:    "endpoint host with an ideographic full stop",
			doc:     endpoint("url: https://pypi.org。/"),
			wantErr: "must be a DNS name",
		},
		{
			name:    "endpoint host label over 63 characters",
			doc:     endpoint("url: https://" + strings.Repeat("a", 64) + ".org/"),
			wantErr: "must be a DNS name",
		},
		// The matcher compares a prefix against the escaped path, so a
		// prefix holding a character a client always escapes could never
		// match.
		{
			name:    "url path with a space",
			doc:     endpoint(`url: "https://a.example/my files/"`),
			wantErr: `url path "/my files/" must be an absolute path`,
		},
		{
			name:    "url path with a non-ASCII character",
			doc:     endpoint("url: https://a.example/caf\u00e9/"),
			wantErr: "must be an absolute path",
		},
		// Nothing unescapes a prefix, so a malformed escape would prefix
		// match by accident: "/a%" matches "/a%25b".
		{name: "url path with a malformed escape", doc: endpoint("url: https://a.example/a%zz"), wantErr: "is not a URL"},
		{name: "url path ending in a bare percent", doc: endpoint("url: https://a.example/a%"), wantErr: "is not a URL"},
		{name: "url path with dot segments", doc: endpoint("url: https://pypi.org/a/../b"), wantErr: "url path"},
		{name: "url path with an empty segment", doc: endpoint("url: https://pypi.org//a"), wantErr: "url path"},
		{name: "url with a query", doc: endpoint("url: https://pypi.org/a?x"), wantErr: "must not hold userinfo"},
		{name: "url with an empty query", doc: endpoint("url: https://pypi.org/a?"), wantErr: "must not hold userinfo"},
		{name: "url with a fragment", doc: endpoint("url: https://pypi.org/a#x"), wantErr: "must not hold userinfo"},
		{name: "url with userinfo", doc: endpoint("url: https://u@pypi.org/"), wantErr: "must not hold userinfo"},
		{name: "endpoint naming a host", doc: endpoint("host: pypi.org"), wantErr: `unknown field "host"`},
		{
			name:    "endpoint naming a resource",
			doc:     endpoint("url: https://github.com/\n    resource: https://api.github.com/"),
			wantErr: `unknown field "resource"`,
		},
	})
}

// TestParseReadsTheEndpointURL pins what an endpoint URL names: the host the
// policy matches, the port, the path prefix, and the canonical resource the
// exchange sends. Two spellings of one endpoint produce one resource.
func TestParseReadsTheEndpointURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, url    string
		host         string
		port         int
		prefix       string
		wantResource string
	}{
		{
			name: "no path", url: "https://github.com",
			host: "github.com", port: 443, prefix: "/", wantResource: "https://github.com",
		},
		{
			name: "another case and a trailing dot", url: "https://GitHub.com./",
			host: "github.com", port: 443, prefix: "/", wantResource: "https://github.com",
		},
		{
			name: "an upper-case scheme", url: "HTTPS://pypi.org/",
			host: "pypi.org", port: 443, prefix: "/", wantResource: "https://pypi.org",
		},
		{
			name: "padded", url: " https://pypi.org/ ",
			host: "pypi.org", port: 443, prefix: "/", wantResource: "https://pypi.org",
		},
		{
			name: "a path", url: "https://openrouter.ai/api/v1",
			host: "openrouter.ai", port: 443, prefix: "/api/v1", wantResource: "https://openrouter.ai/api/v1",
		},
		{
			name: "a path with a trailing slash", url: "https://a.example/api/",
			host: "a.example", port: 443, prefix: "/api/", wantResource: "https://a.example/api/",
		},
		{
			name: "a port", url: "https://localhost:8443/header/",
			host: "localhost", port: 8443, prefix: "/header/", wantResource: "https://localhost:8443/header/",
		},
		{
			name: "the default port written out", url: "https://pypi.org:443/simple/",
			host: "pypi.org", port: 443, prefix: "/simple/", wantResource: "https://pypi.org/simple/",
		},
		{
			name: "http takes port 80", url: "http://upstream.test/allowed/",
			host: "upstream.test", port: 80, prefix: "/allowed/", wantResource: "http://upstream.test/allowed/",
		},
		{
			name: "http with port 80 written out", url: "http://upstream.test:80/",
			host: "upstream.test", port: 80, prefix: "/", wantResource: "http://upstream.test",
		},
		{
			name: "https on port 80", url: "https://upstream.test:80/",
			host: "upstream.test", port: 80, prefix: "/", wantResource: "https://upstream.test:80",
		},
		{
			name: "http on port 443", url: "HTTP://upstream.test:443/",
			host: "upstream.test", port: 443, prefix: "/", wantResource: "http://upstream.test:443",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - url: \"" + tc.url + "\"\n"
			cfg, err := config.Parse([]byte(doc), config.Overrides{})
			require.NoError(t, err, "Parse")
			endpoint := cfg.Endpoints[0]
			assert.Equal(t, tc.host, endpoint.Host, "host")
			assert.Equal(t, tc.port, endpoint.Port, "port")
			assert.Equal(t, tc.prefix, endpoint.PathPrefix, "path prefix")
			assert.Equal(t, tc.wantResource, endpoint.Resource, "resource")
		})
	}
}

// TestParseEndpointIdentity pins what makes two entries one endpoint. The
// identity is the host, port, and path prefix that policy.Compile uses. A
// host reachable on two ports is two endpoints.
func TestParseEndpointIdentity(t *testing.T) {
	t.Parallel()
	doc := func(entries string) string {
		return "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n" + entries
	}
	type key struct {
		host   string
		port   int
		prefix string
	}
	tests := []struct {
		name    string
		doc     string
		wantErr string
		want    []key
	}{
		{
			name:    "same host and prefix on the default port",
			doc:     doc("  - url: https://pypi.org/\n  - url: https://PYPI.ORG./\n"),
			wantErr: `endpoints[1]: url "https://PYPI.ORG./" names the same endpoint as endpoints[0]`,
		},
		{
			name: "same host, port and prefix written out",
			doc: doc("  - url: https://pypi.org:8443/simple/\n" +
				"  - url: https://pypi.org:8443/simple/\n"),
			wantErr: `names the same endpoint as endpoints[0]`,
		},
		{
			// The default fills the omitted port, so both entries name the
			// same endpoint.
			name: "one entry naming the default port and one leaving it out",
			doc: doc("  - url: https://pypi.org/simple/\n" +
				"  - url: https://pypi.org:443/simple/\n"),
			wantErr: `names the same endpoint as endpoints[0]`,
		},
		{
			name: "same host and prefix on two ports",
			doc: doc("  - url: https://upstream.test/allowed/\n" +
				"  - url: http://upstream.test/allowed/\n"),
			want: []key{
				{host: "upstream.test", port: 443, prefix: "/allowed/"},
				{host: "upstream.test", port: 80, prefix: "/allowed/"},
			},
		},
		{
			name: "same host and port on two prefixes",
			doc: doc("  - url: https://upstream.test/allowed/\n" +
				"  - url: https://upstream.test/other/\n"),
			want: []key{
				{host: "upstream.test", port: 443, prefix: "/allowed/"},
				{host: "upstream.test", port: 443, prefix: "/other/"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Parse([]byte(tc.doc), config.Overrides{})
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr, "Parse:\n%s", tc.doc)
				return
			}
			require.NoError(t, err, "Parse:\n%s", tc.doc)
			got := make([]key, 0, len(cfg.Endpoints))
			for _, endpoint := range cfg.Endpoints {
				got = append(got, key{endpoint.Host, endpoint.Port, endpoint.PathPrefix})
			}
			assert.Equal(t, tc.want, got, "endpoints")
			// The matcher applies the same rule, so a parsed document must
			// also compile.
			deny, denyErr := policy.NewDenyList(nil, nil)
			require.NoError(t, denyErr, "policy.NewDenyList")
			_, compileErr := policy.Compile(cfg.PolicyEndpoints(), deny)
			assert.NoError(t, compileErr, "policy.Compile")
		})
	}
}

// TestParseRefusesInvalidCredentials covers the credential source and the
// placement that names it.
func TestParseRefusesInvalidCredentials(t *testing.T) {
	t.Parallel()
	endpoint := func(fields string) string {
		return "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - " + fields + "\n"
	}
	runParseRefusals(t, []parseRefusal{
		{
			name: "header placement without the token",
			doc: endpoint(
				"url: https://a.example/\n    credential:\n" +
					"      placement: {kind: header, name: X, template: Bearer}",
			),
			wantErr: "must contain {credential}",
		},
		{
			name: "header placement without a name",
			doc: endpoint(
				"url: https://a.example/\n    credential:\n" +
					"      placement: {kind: header, template: \"{credential}\"}",
			),
			wantErr: "header placement needs a name",
		},
		{
			name:    "query placement without a name",
			doc:     endpoint("url: https://a.example/\n    credential:\n      placement: {kind: query}"),
			wantErr: "query placement needs a name",
		},
		{
			name:    "basic placement without a user",
			doc:     endpoint("url: https://a.example/\n    credential:\n      placement: {kind: basic}"),
			wantErr: "basic placement needs a user",
		},
		{
			name: "basic placement whose user holds a colon",
			doc: endpoint("url: https://a.example/\n    credential:\n" +
				"      placement: {kind: basic, user: \"alice:hunter2\"}"),
			wantErr: "a basic placement user must not contain a colon or a control character",
		},
		{
			name: "basic placement whose user would split the request head",
			doc: endpoint("url: https://a.example/\n    credential:\n" +
				"      placement: {kind: basic, user: \"alice\\r\\nX-Injected: 1\"}"),
			wantErr: "a basic placement user must not contain a colon or a control character",
		},
		{
			name: "unknown placement kind",
			doc: endpoint(
				"url: https://a.example/\n    credential:\n      placement: {kind: cookie, name: x}",
			),
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
			doc: endpoint("url: https://a.example/\n    credential:\n" +
				"      placement: {kind: header, name: host, template: \"{credential}\"}"),
			wantErr: "endpoints[0]: a header placement cannot name host, " +
				"a header the connection, the proxy or the upstream's trust depends on",
		},
		{
			name: "a header placement naming a hop-by-hop header",
			doc: endpoint("url: https://a.example/\n    credential:\n" +
				"      placement: {kind: header, name: Connection, template: \"{credential}\"}"),
			wantErr: "endpoints[0]: a header placement cannot name Connection, ",
		},
		{
			name: "a header placement naming a body framing header",
			doc: endpoint("url: https://a.example/\n    credential:\n" +
				"      placement: {kind: header, name: Content-Length, template: \"{credential}\"}"),
			wantErr: "endpoints[0]: a header placement cannot name Content-Length, ",
		},
		{
			name: "a header placement in the x-forwarded- family",
			doc: endpoint("url: https://a.example/\n    credential:\n" +
				"      placement: {kind: header, name: X-Forwarded-For, template: \"{credential}\"}"),
			wantErr: "endpoints[0]: a header placement cannot name X-Forwarded-For, ",
		},
		{
			name: "a header placement in the sec- family",
			doc: endpoint("url: https://a.example/\n    credential:\n" +
				"      placement: {kind: header, name: Sec-Fetch-Site, template: \"{credential}\"}"),
			wantErr: "endpoints[0]: a header placement cannot name Sec-Fetch-Site, ",
		},
	})
}

// TestParseAcceptsAnAuthorizationPlacement keeps the common placement allowed.
func TestParseAcceptsAnAuthorizationPlacement(t *testing.T) {
	t.Parallel()
	doc := "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - url: https://a.example/\n    credential:\n" +
		"      placement: {kind: header, name: Authorization, template: \"Bearer {credential}\"}\n"
	cfg, err := config.Parse([]byte(doc), config.Overrides{})
	require.NoError(t, err, "Parse:\n%s", doc)
	require.Len(t, cfg.Endpoints, 1, "the document names one endpoint")
	require.NotNil(t, cfg.Endpoints[0].Credential, "the endpoint names a credential")
	assert.Equal(t, "Authorization", cfg.Endpoints[0].Credential.Placement.Name, "placement.name")
}

// TestParseAcceptsABasicPlacement checks that a basic placement parses and
// that the endpoint keeps its user.
func TestParseAcceptsABasicPlacement(t *testing.T) {
	t.Parallel()
	doc := "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - url: https://github.com/\n    credential:\n" +
		"      placement: {kind: basic, user: x-access-token}\n"
	cfg, err := config.Parse([]byte(doc), config.Overrides{})
	require.NoError(t, err, "Parse:\n%s", doc)
	require.Len(t, cfg.Endpoints, 1, "the document names one endpoint")
	require.NotNil(t, cfg.Endpoints[0].Credential, "the endpoint names a credential")
	assert.Equal(t, credential.KindBasic, cfg.Endpoints[0].Credential.Placement.Kind, "placement.kind")
	assert.Equal(t, "x-access-token", cfg.Endpoints[0].Credential.Placement.User, "placement.user")
	assert.Empty(t, cfg.Endpoints[0].Credential.Placement.Name, "placement.name")
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

// secretDoc is the identity section that authenticates with a client secret.
// It differs from identityDoc only in the authentication mechanism.
const secretDoc = "identity:\n  zone_url: https://z\n  client_id: c\n  client_secret_file: /s\n" +
	"  impersonate: {user: u}\n"

// TestCredentialSourceNamesTheSourceInForce checks the source that the process
// announces, reports at /info, and covers in the config digest.
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
			assert.Equal(t, tc.want, cfg.CredentialSource(), "the configured source")
		})
	}
}

func TestParseReportsEveryProblem(t *testing.T) {
	t.Parallel()
	_, err := config.Parse([]byte("version: 2\nsandbox:\n  id: \"\"\nendpoints:\n  - url: \"\"\n"), config.Overrides{})
	require.Error(t, err, "a document with three problems is refused")
	for _, want := range []string{"version is 2", "sandbox.id", "must be an absolute http or https URL"} {
		assert.ErrorContains(t, err, want, "one run names every problem")
	}
}

func TestPolicyEndpoints(t *testing.T) {
	t.Parallel()
	cfg, err := config.Parse([]byte(minimal+
		"  - url: https://A.Example./api\n    credential:\n"+
		"      placement: {kind: header, name: X, template: \"{credential}\"}\n"), config.Overrides{})
	require.NoError(t, err)
	endpoints := cfg.PolicyEndpoints()
	require.Len(t, endpoints, 2)
	assert.Equal(t, policy.Endpoint{
		Host: "a.example", Port: config.DefaultEndpointPort, PathPrefix: "/api",
		Resource:   "https://a.example/api",
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
