package policy_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/policy"
)

func prefixes(t *testing.T, raw ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(raw))
	for _, r := range raw {
		out = append(out, netip.MustParsePrefix(r))
	}
	return out
}

func TestDenyListAddresses(t *testing.T) {
	t.Parallel()
	deny, err := policy.NewDenyList(prefixes(t, "10.42.0.0/16"), prefixes(t, "127.0.0.0/8"))
	require.NoError(t, err, "NewDenyList")
	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "public address", host: "93.184.216.34", want: false},
		{name: "RFC 1918", host: "192.168.1.1", want: true},
		{name: "metadata address", host: "169.254.169.254", want: true},
		{name: "shared address space", host: "100.64.0.1", want: true},
		{name: "IPv6 unique local", host: "fd00::1", want: true},
		{name: "IPv6 link local", host: "fe80::1", want: true},
		{name: "IPv4-mapped IPv6 spelling of a private address", host: "::ffff:10.0.0.1", want: true},
		{name: "cluster range joined to the list", host: "10.42.3.4", want: true},
		{name: "loopback excepted", host: "127.0.0.1", want: false},
		{name: "IPv6 loopback stays denied", host: "::1", want: true},
		{name: "metadata name", host: "metadata.google.internal", want: true},
		{name: "metadata name with the root label", host: "Metadata.Google.Internal.", want: true},
		{name: "DoH resolver", host: "dns.google", want: true},
		{name: "DoH wildcard zone", host: "abc123.dns.nextdns.io", want: true},
		{name: "a longer name ending the same way", host: "notadguard-dns.com", want: false},
		{name: "ordinary name", host: "api.github.com", want: false},
		{name: "empty", host: "", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, deny.DeniesHost(tc.host), "DeniesHost(%q)", tc.host)
		})
	}
}

func TestDenyListRefusesAnExceptionCoveringTheMetadataAddress(t *testing.T) {
	t.Parallel()
	for _, exception := range []string{"169.254.169.254/32", "169.254.0.0/16", "0.0.0.0/0"} {
		t.Run(exception, func(t *testing.T) {
			t.Parallel()
			_, err := policy.NewDenyList(nil, prefixes(t, exception))
			require.ErrorContains(t, err, "metadata address", "NewDenyList with exception %s", exception)
		})
	}
}

func TestDenyListInvalidAddressIsDenied(t *testing.T) {
	t.Parallel()
	deny, err := policy.NewDenyList(nil, nil)
	require.NoError(t, err, "NewDenyList")
	assert.True(t, deny.DeniesAddr(netip.Addr{}), "an invalid address is denied")
}

func TestCompileRefusals(t *testing.T) {
	t.Parallel()
	deny, err := policy.NewDenyList(nil, nil)
	require.NoError(t, err, "NewDenyList")
	tests := []struct {
		name      string
		endpoints []policy.Endpoint
		wantErr   string
	}{
		{
			name:      "a host on the deny list",
			endpoints: []policy.Endpoint{{Host: "metadata.google.internal", Port: 443, PathPrefix: "/"}},
			wantErr:   "is on the platform deny list",
		},
		{
			name:      "an IP literal",
			endpoints: []policy.Endpoint{{Host: "93.184.216.34", Port: 443, PathPrefix: "/"}},
			wantErr:   "is an IP literal",
		},
		{
			name: "a repeated host and prefix",
			endpoints: []policy.Endpoint{
				{Host: "api.github.com", Port: 443, PathPrefix: "/"},
				{Host: "API.GITHUB.COM.", Port: 443, PathPrefix: "/"},
			},
			wantErr: "repeats endpoints[0]",
		},
		{
			name:      "a host the deny list covers by suffix",
			endpoints: []policy.Endpoint{{Host: "abc123.dns.nextdns.io", Port: 443, PathPrefix: "/"}},
			wantErr:   "is on the platform deny list",
		},
		// An empty prefix covers every path on its host, so Compile refuses
		// it rather than leaving the guarantee to the caller that built the
		// list.
		{
			name:      "an empty path prefix",
			endpoints: []policy.Endpoint{{Host: "api.github.com", Port: 443}},
			wantErr:   `path prefix "" must be an absolute path`,
		},
		{
			name:      "a relative path prefix",
			endpoints: []policy.Endpoint{{Host: "api.github.com", Port: 443, PathPrefix: "repos"}},
			wantErr:   `path prefix "repos" must be an absolute path`,
		},
		{
			name:      "a path prefix with dot segments",
			endpoints: []policy.Endpoint{{Host: "api.github.com", Port: 443, PathPrefix: "/repos/../admin"}},
			wantErr:   "must be an absolute path in its shortest form",
		},
		{
			name:      "a path prefix that escapes a letter",
			endpoints: []policy.Endpoint{{Host: "api.github.com", Port: 443, PathPrefix: "/%61dmin/"}},
			wantErr:   `path prefix "/%61dmin/" percent-encodes an unreserved character or uses lowercase hex`,
		},
		{
			name:      "a path prefix with a lowercase escape",
			endpoints: []policy.Endpoint{{Host: "gitlab.example", Port: 443, PathPrefix: "/group%2fproject/"}},
			wantErr:   `path prefix "/group%2fproject/" percent-encodes an unreserved character or uses lowercase hex`,
		},
		// A request has neither character: the request target's query
		// splits off before the path, and EscapedPath writes "#" as "%23".
		// A document is the only way either reaches the matcher.
		{
			name:      "a path prefix with a query",
			endpoints: []policy.Endpoint{{Host: "api.github.com", Port: 443, PathPrefix: "/repos?all=1"}},
			wantErr:   "must be an absolute path in its shortest form",
		},
		{
			name:      "a path prefix with a fragment",
			endpoints: []policy.Endpoint{{Host: "api.github.com", Port: 443, PathPrefix: "/repos#top"}},
			wantErr:   "must be an absolute path in its shortest form",
		},
		// Compile validates the port itself, so a list assembled outside
		// the document parser cannot express the zero value and match a
		// destination on no port at all.
		{
			name:      "no port",
			endpoints: []policy.Endpoint{{Host: "api.github.com", PathPrefix: "/"}},
			wantErr:   "port 0 is outside 1 to 65535",
		},
		{
			name:      "a port above the range",
			endpoints: []policy.Endpoint{{Host: "api.github.com", Port: 70000, PathPrefix: "/"}},
			wantErr:   "port 70000 is outside 1 to 65535",
		},
		{
			name:      "a negative port",
			endpoints: []policy.Endpoint{{Host: "api.github.com", Port: -1, PathPrefix: "/"}},
			wantErr:   "port -1 is outside 1 to 65535",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			matcher, err := policy.Compile(tc.endpoints, deny)
			require.ErrorContains(t, err, tc.wantErr, "Compile")
			assert.Nil(t, matcher, "a refused list compiles to no matcher")
		})
	}
}

// TestCompileAcceptsOnePrefixOnTwoPorts pins that the port is part of an
// endpoint's identity. The same host and prefix on two ports are two
// endpoints, so neither reads as a repeat of the other.
func TestCompileAcceptsOnePrefixOnTwoPorts(t *testing.T) {
	t.Parallel()
	deny, err := policy.NewDenyList(nil, nil)
	require.NoError(t, err, "NewDenyList")
	matcher, err := policy.Compile([]policy.Endpoint{
		{Host: "registry.internal", Port: 443, PathPrefix: "/v2/"},
		{Host: "registry.internal", Port: 5000, PathPrefix: "/v2/"},
	}, deny)
	require.NoError(t, err, "Compile")
	for _, port := range []int{443, 5000} {
		decision := matcher.Request("registry.internal", port, "/v2/manifest")
		require.True(t, decision.Allowed(), "port %d", port)
		require.NotNil(t, decision.Endpoint, "port %d names its endpoint", port)
		assert.Equal(t, fmt.Sprintf("registry.internal:%d/v2/", port), decision.Endpoint.ID(), "endpoint id")
	}
}

// TestCompileReportsEveryProblem pins what the doc comment promises: one run
// names everything wrong with the list, so an operator does not fix a
// document one error per restart.
func TestCompileReportsEveryProblem(t *testing.T) {
	t.Parallel()
	deny, err := policy.NewDenyList(nil, nil)
	require.NoError(t, err, "NewDenyList")
	_, err = policy.Compile([]policy.Endpoint{
		{Host: "metadata.google.internal", Port: 443, PathPrefix: "/"},
		{Host: "93.184.216.34", Port: 443, PathPrefix: "/"},
		{Host: "api.github.com", Port: 443, PathPrefix: "repos"},
	}, deny)
	require.Error(t, err, "Compile")
	for _, want := range []string{
		"endpoints[0]",
		"is on the platform deny list",
		"endpoints[1]",
		"is an IP literal",
		"endpoints[2]",
		"must be an absolute path",
	} {
		assert.ErrorContains(t, err, want, "the error names every problem")
	}
}

// headerPlacement is a credential an endpoint can name. The matcher passes
// it to the caller and reads nothing in it.
var headerPlacement = credential.Placement{ //nolint:gochecknoglobals // a fixture the table shares
	Kind: credential.KindHeader, Name: "Authorization", Template: "Bearer " + credential.Token,
}

func TestMatcherDecisions(t *testing.T) {
	t.Parallel()
	deny, err := policy.NewDenyList(nil, nil)
	require.NoError(t, err, "NewDenyList")
	matcher, err := policy.Compile([]policy.Endpoint{
		{Host: "api.github.com", Port: 443, PathPrefix: "/", Credential: &headerPlacement},
		{Host: "openrouter.ai", Port: 443, PathPrefix: "/api/v1/"},
		{Host: "openrouter.ai", Port: 443, PathPrefix: "/api/v1/models"},
		{Host: "pypi.org", Port: 443, PathPrefix: "/simple"},
		{Host: "registry.internal", Port: 443, PathPrefix: "/"},
		{Host: "registry.internal", Port: 5000, PathPrefix: "/v2/"},
	}, deny)
	require.NoError(t, err, "Compile")

	tests := []struct {
		name string
		host string
		// port is the port the destination names. Zero means 443, the port
		// an endpoint covers when it names none.
		port         int
		path         string
		wantVerdict  policy.Verdict
		wantReason   policy.Reason
		wantEndpoint string
		// wantCredential is the placement the matched endpoint names.
		wantCredential *credential.Placement
	}{
		{
			name: "connection to a listed host", host: "api.github.com",
			wantVerdict: "allow", wantReason: "endpoint_allowed",
		},
		{
			name: "a connection names no endpoint, whatever prefixes the host has", host: "openrouter.ai",
			wantVerdict: "allow", wantReason: "endpoint_allowed",
		},
		{
			name: "connection to an unlisted host", host: "example.com",
			wantVerdict: "deny", wantReason: "no_matching_endpoint",
		},
		{
			name: "connection to a denied name", host: "dns.google",
			wantVerdict: "deny", wantReason: "deny_always",
		},
		{
			name: "connection to a denied literal", host: "169.254.169.254",
			wantVerdict: "deny", wantReason: "deny_always",
		},
		{
			name: "connection with no name", host: "",
			wantVerdict: "deny", wantReason: "no_sni",
		},
		{
			name: "request under a slash prefix", host: "openrouter.ai", path: "/api/v1/chat/completions",
			wantVerdict: "allow", wantReason: "endpoint_allowed", wantEndpoint: "openrouter.ai:443/api/v1/",
		},
		{
			name: "request matching the longer prefix", host: "openrouter.ai", path: "/api/v1/models",
			wantVerdict: "allow", wantReason: "endpoint_allowed", wantEndpoint: "openrouter.ai:443/api/v1/models",
		},
		{
			name: "request outside every prefix", host: "openrouter.ai", path: "/api/v2/",
			wantVerdict: "deny", wantReason: "no_matching_endpoint",
		},
		{
			name: "request to the prefix without its slash", host: "openrouter.ai", path: "/api/v1",
			wantVerdict: "deny", wantReason: "no_matching_endpoint",
		},
		{
			name: "a prefix without a slash covers itself", host: "pypi.org", path: "/simple",
			wantVerdict: "allow", wantReason: "endpoint_allowed", wantEndpoint: "pypi.org:443/simple",
		},
		{
			name: "a prefix without a slash covers a segment under it", host: "pypi.org", path: "/simple/requests/",
			wantVerdict: "allow", wantReason: "endpoint_allowed", wantEndpoint: "pypi.org:443/simple",
		},
		{
			name: "a prefix without a slash does not cover a longer segment", host: "pypi.org", path: "/simpler",
			wantVerdict: "deny", wantReason: "no_matching_endpoint",
		},
		{
			name: "host is case-insensitive with the root label", host: "PyPI.org.", path: "/simple",
			wantVerdict: "allow", wantReason: "endpoint_allowed", wantEndpoint: "pypi.org:443/simple",
		},
		{
			name: "dot segments are refused", host: "openrouter.ai", path: "/api/v1/../v2/",
			wantVerdict: "deny", wantReason: "malformed_request",
		},
		{
			name: "a relative path is refused", host: "openrouter.ai", path: "api/v1/",
			wantVerdict: "deny", wantReason: "malformed_request",
		},
		{
			// An escaped question mark is an ordinary path character. The
			// upstream receives these bytes, so the prefix covers them.
			name: "an escaped question mark is a path character", host: "openrouter.ai", path: "/api/v1/a%3Fb",
			wantVerdict: "allow", wantReason: "endpoint_allowed", wantEndpoint: "openrouter.ai:443/api/v1/",
		},
		{
			// Cleaning these bytes changes nothing, so only the decoded
			// form shows the dot segments. An upstream that decodes first
			// would read this as /api/secret, outside the prefix.
			name: "dot segments behind escaped slashes are refused", host: "openrouter.ai",
			path:        "/api/v1/x/..%2F..%2Fsecret",
			wantVerdict: "deny", wantReason: "malformed_request",
		},
		{
			// An upstream that decodes reads /api/v1/models/x, which the
			// longer prefix covers. Byte for byte, only /api/v1/ covers it.
			name: "an escaped letter is refused", host: "openrouter.ai", path: "/api/v1/%6Dodels/x",
			wantVerdict: "deny", wantReason: "malformed_request",
		},
		{
			name: "an escaped dot is refused", host: "openrouter.ai", path: "/api/v1/%2E%2E/secret",
			wantVerdict: "deny", wantReason: "malformed_request",
		},
		{
			name: "an escaped tilde is refused", host: "openrouter.ai", path: "/api/v1/%7Euser",
			wantVerdict: "deny", wantReason: "malformed_request",
		},
		{
			name: "a lowercase escape is refused", host: "openrouter.ai", path: "/api/v1/a%3fb",
			wantVerdict: "deny", wantReason: "malformed_request",
		},
		{
			// GitLab names a project as group%2Fproject. An uppercase escape
			// of a reserved character is canonical, so it passes.
			name: "an uppercase escape of a reserved character passes", host: "openrouter.ai",
			path:        "/api/v1/projects/group%2Fproject",
			wantVerdict: "allow", wantReason: "endpoint_allowed", wantEndpoint: "openrouter.ai:443/api/v1/",
		},
		{
			// An escaped slash is not a separator. The upstream reads one
			// segment named "api/v1", which is not under /api/v1/, and the
			// matcher does not put it there either.
			name: "an escaped slash does not open a prefix", host: "openrouter.ai", path: "/api%2Fv1/models",
			wantVerdict: "deny", wantReason: "no_matching_endpoint",
		},
		{
			name: "the matched endpoint names its credential placement", host: "api.github.com", path: "/repos",
			wantVerdict: "allow", wantReason: "endpoint_allowed", wantEndpoint: "api.github.com:443/",
			wantCredential: &headerPlacement,
		},
		{
			name: "request to an unlisted host", host: "example.com", path: "/",
			wantVerdict: "deny", wantReason: "no_matching_endpoint",
		},
		{
			name: "connection to a listed host on a port no endpoint names",
			host: "api.github.com", port: 8443,
			wantVerdict: "deny", wantReason: "no_matching_endpoint",
		},
		{
			name: "connection to a listed host on its second port",
			host: "registry.internal", port: 5000,
			wantVerdict: "allow", wantReason: "endpoint_allowed",
		},
		{
			name: "a port decides alongside the path", host: "registry.internal", port: 5000, path: "/v2/manifest",
			wantVerdict: "allow", wantReason: "endpoint_allowed", wantEndpoint: "registry.internal:5000/v2/",
		},
		{
			// The prefix that covers this path belongs to the endpoint on
			// port 5000, so the same path on 443 falls to the "/" endpoint.
			name: "one host's ports have their own prefixes",
			host: "registry.internal", path: "/v2/manifest",
			wantVerdict: "allow", wantReason: "endpoint_allowed", wantEndpoint: "registry.internal:443/",
		},
		{
			name: "a request on a port no endpoint names", host: "registry.internal", port: 9000, path: "/v2/",
			wantVerdict: "deny", wantReason: "no_matching_endpoint",
		},
		{
			name: "request to a denied name", host: "metadata.google.internal", path: "/",
			wantVerdict: "deny", wantReason: "deny_always",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			port := tc.port
			if port == 0 {
				port = 443
			}
			var got policy.Decision
			if tc.path == "" {
				got = matcher.Connection(tc.host, port)
			} else {
				got = matcher.Request(tc.host, port, tc.path)
			}
			assert.Equal(t, tc.wantVerdict, got.Verdict, "verdict")
			assert.Equal(t, tc.wantReason, got.Reason, "reason")
			var gotEndpoint string
			var gotCredential *credential.Placement
			if got.Endpoint != nil {
				gotEndpoint = got.Endpoint.ID()
				gotCredential = got.Endpoint.Credential
			}
			assert.Equal(t, tc.wantEndpoint, gotEndpoint, "endpoint")
			assert.Equal(t, tc.wantCredential, gotCredential, "credential placement")
		})
	}
}

func TestMatcherHosts(t *testing.T) {
	t.Parallel()
	deny, err := policy.NewDenyList(nil, nil)
	require.NoError(t, err, "NewDenyList")
	matcher, err := policy.Compile([]policy.Endpoint{
		{Host: "pypi.org", Port: 443, PathPrefix: "/"},
		{Host: "api.github.com", Port: 443, PathPrefix: "/"},
		{Host: "api.github.com", Port: 443, PathPrefix: "/repos/"},
	}, deny)
	require.NoError(t, err, "Compile")
	assert.Equal(t, []string{"api.github.com", "pypi.org"}, matcher.Hosts(), "Hosts, sorted and deduplicated")
}

// TestCanonicalEscapes covers each class of escape: reserved and non-ASCII
// bytes in uppercase pass, and an unreserved character, lowercase hex or a
// malformed escape fails.
func TestCanonicalEscapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path string
		want bool
	}{
		{path: "", want: true},
		{path: "/api/v1/models", want: true},
		{path: "/projects/group%2Fproject", want: true},
		{path: "/a%20b", want: true},
		{path: "/a%3Ab", want: true},
		{path: "/caf%C3%A9", want: true},
		{path: "/%61dmin", want: false},
		{path: "/%41dmin", want: false},
		{path: "/v%30", want: false},
		{path: "/a%2Db", want: false},
		{path: "/a%2Eb", want: false},
		{path: "/a%5Fb", want: false},
		{path: "/%7Euser", want: false},
		{path: "/projects/group%2fproject", want: false},
		{path: "/caf%c3%a9", want: false},
		{path: "/a%2Fb%61", want: false},
		{path: "/a%zz", want: false},
		{path: "/a%2", want: false},
		{path: "/a%", want: false},
		{path: "/a%%2F", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, policy.CanonicalEscapes(tc.path), "CanonicalEscapes(%q)", tc.path)
		})
	}
}
