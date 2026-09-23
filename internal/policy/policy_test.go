package policy_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			wantErr:   `path_prefix "" must be an absolute path`,
		},
		{
			name:      "a relative path prefix",
			endpoints: []policy.Endpoint{{Host: "api.github.com", Port: 443, PathPrefix: "repos"}},
			wantErr:   `path_prefix "repos" must be an absolute path`,
		},
		{
			name:      "a path prefix carrying dot segments",
			endpoints: []policy.Endpoint{{Host: "api.github.com", Port: 443, PathPrefix: "/repos/../admin"}},
			wantErr:   "must be an absolute path in its shortest form",
		},
		{
			name:      "a path prefix carrying a query",
			endpoints: []policy.Endpoint{{Host: "api.github.com", Port: 443, PathPrefix: "/repos?all=1"}},
			wantErr:   "must be an absolute path in its shortest form",
		},
		// Compile validates the port itself, so a list assembled outside
		// the document parser cannot carry the zero value and match a
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

func TestMatcherDecisions(t *testing.T) {
	t.Parallel()
	deny, err := policy.NewDenyList(nil, nil)
	require.NoError(t, err, "NewDenyList")
	matcher, err := policy.Compile([]policy.Endpoint{
		{Host: "api.github.com", Port: 443, PathPrefix: "/", HasCredential: true},
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
			// Request takes a decoded path, so the proxy cannot hand it a
			// raw query. A "?" that does arrive is a path character, and
			// Request refuses it either way rather than guessing which one
			// the caller meant.
			name: "a question mark in the path is refused", host: "openrouter.ai", path: "/api/v1/?x=1",
			wantVerdict: "deny", wantReason: "malformed_request",
		},
		{
			name: "a fragment marker in the path is refused", host: "openrouter.ai", path: "/api/v1/#top",
			wantVerdict: "deny", wantReason: "malformed_request",
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
			name: "one host's ports carry their own prefixes",
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
			if got.Endpoint != nil {
				gotEndpoint = got.Endpoint.ID()
			}
			assert.Equal(t, tc.wantEndpoint, gotEndpoint, "endpoint")
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
