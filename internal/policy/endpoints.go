package policy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/keycardai/egress-proxy/internal/credential"
)

var errEndpoint = errors.New("invalid endpoint")

// maxPort is the highest TCP port an endpoint can name.
const maxPort = 65535

// Endpoint is one entry of the document's endpoint list, reduced to what the
// matcher needs.
type Endpoint struct {
	// Host is a DNS name, lowercase, without a port.
	Host string
	// Port is the one port this endpoint covers on that host. An endpoint
	// names a service, not a machine, so a host reachable on two ports is
	// two endpoints.
	Port int
	// PathPrefix is an absolute path. "/" covers every path on the host. A
	// prefix that ends in "/" covers everything under it. Any other prefix
	// covers itself and every path under it as a segment, so "/api" covers
	// "/api" and "/api/v1" but not "/apis".
	PathPrefix string
	// Resource is the resource identifier sent for this endpoint. The
	// credential source uses it to find the credential.
	Resource string
	// Credential is where a credential goes in a request to this endpoint.
	// Nil means the endpoint names none.
	Credential *credential.Placement
}

// ID names the endpoint on an audit record: the authority and the prefix.
// The port is always written, so one shape parses every id.
func (e Endpoint) ID() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) + e.PathPrefix
}

func coversPath(prefix, requestPath string) bool {
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(requestPath, prefix)
	}
	return requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/")
}

// Decision is a verdict and the reason for it. The zero value denies.
type Decision struct {
	Verdict Verdict
	Reason  Reason
	// Endpoint is the endpoint that matched. Request sets it on an allow.
	// Connection leaves it nil: that decision has no path in it, and a path
	// prefix on such a record would be misleading.
	Endpoint *Endpoint
	// Err is why the decision failed, when the denial came from a failure
	// rather than from a rule. The matcher never sets it.
	Err error
}

// Allowed reports whether the decision forwards.
func (d Decision) Allowed() bool {
	return d.Verdict == VerdictAllow
}

func deny(reason Reason) Decision {
	return Decision{Verdict: VerdictDeny, Reason: reason}
}

// Matcher answers the connection-scoped and request-scoped questions for one
// document.
type Matcher struct {
	byHost map[string][]Endpoint
	deny   *DenyList
	// any allows every host the deny list does not cover, with the
	// request's origin as the resource and placement as where the
	// credential goes. byHost is empty with it.
	any       bool
	placement *credential.Placement
}

// CompileAny builds a matcher for a document with any_endpoint: every host
// the deny list does not cover is allowed on any port, a request's
// resource is its origin, and placement, when not nil, is where its
// credential goes.
func CompileAny(deny *DenyList, placement *credential.Placement) *Matcher {
	return &Matcher{byHost: map[string][]Endpoint{}, deny: deny, any: true, placement: placement}
}

// AllowsAny reports whether the matcher was built with CompileAny.
func (m *Matcher) AllowsAny() bool {
	return m.any
}

// Origin is the resource a request to host and port names under
// any_endpoint: https://host, with the port when it is not 443. It is the
// canonical form of an endpoint URL with no path, so a zone resource
// created for the host matches it.
func Origin(host string, port int) string {
	host = NormalizeHost(host)
	if port == defaultEndpointPort {
		return "https://" + host
	}
	return "https://" + net.JoinHostPort(host, strconv.Itoa(port))
}

// defaultEndpointPort is the port https implies, which Origin leaves out.
const defaultEndpointPort = 443

// Compile validates the endpoint list against the deny list and builds the
// matcher. It reports every problem it finds, so one run tells an operator
// everything wrong with the document. It refuses a host the deny list
// covers, so no document can shadow platform policy.
//
// It validates each host and path prefix itself rather than trusting the
// caller, so an endpoint list assembled anywhere gets the same answer. An
// empty prefix would otherwise cover every path on its host.
func Compile(endpoints []Endpoint, deny *DenyList) (*Matcher, error) {
	var problems []string
	byHost := make(map[string][]Endpoint)
	seen := make(map[string]int, len(endpoints))
	for i, endpoint := range endpoints {
		endpoint.Host = NormalizeHost(endpoint.Host)
		if _, err := netip.ParseAddr(endpoint.Host); err == nil {
			problems = append(problems, fmt.Sprintf(
				"endpoints[%d]: host %q is an IP literal; a TLS client sends no SNI for one, so it can never match",
				i, endpoint.Host,
			))
			continue
		}
		if deny.DeniesHost(endpoint.Host) {
			problems = append(problems, fmt.Sprintf(
				"endpoints[%d]: host %q is on the platform deny list and no document may allow it",
				i, endpoint.Host,
			))
			continue
		}
		if problem := prefixProblem(endpoint.PathPrefix); problem != "" {
			problems = append(problems, fmt.Sprintf(
				"endpoints[%d]: path prefix %q %s", i, endpoint.PathPrefix, problem,
			))
			continue
		}
		if endpoint.Port < 1 || endpoint.Port > maxPort {
			problems = append(problems, fmt.Sprintf(
				"endpoints[%d]: port %d is outside 1 to %d", i, endpoint.Port, maxPort,
			))
			continue
		}
		if previous, ok := seen[endpoint.ID()]; ok {
			problems = append(problems, fmt.Sprintf(
				"endpoints[%d]: host %q on port %d with path prefix %q repeats endpoints[%d]",
				i, endpoint.Host, endpoint.Port, endpoint.PathPrefix, previous,
			))
			continue
		}
		seen[endpoint.ID()] = i
		byHost[endpoint.Host] = append(byHost[endpoint.Host], endpoint)
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%w:\n  %s", errEndpoint, strings.Join(problems, "\n  "))
	}
	// The longest prefix wins, so the most specific endpoint decides a path
	// two of them cover.
	for host := range byHost {
		sort.SliceStable(byHost[host], func(i, j int) bool {
			return len(byHost[host][i].PathPrefix) > len(byHost[host][j].PathPrefix)
		})
	}
	return &Matcher{byHost: byHost, deny: deny}, nil
}

// Connection makes the connection-scoped decision: whether the sandbox can
// reach this host on this port at all. The deny list answers first, then the
// endpoint list.
//
// A port no endpoint covers reads as no_matching_endpoint, the same code as
// a host no endpoint names. The endpoint is the unit a document declares.
func (m *Matcher) Connection(host string, port int) Decision {
	host = NormalizeHost(host)
	if host == "" {
		return deny(ReasonNoSNI)
	}
	if m.deny.DeniesHost(host) {
		return deny(ReasonDenyAlways)
	}
	if m.any {
		return Decision{Verdict: VerdictAllow, Reason: ReasonEndpointAllowed}
	}
	for _, endpoint := range m.byHost[host] {
		if endpoint.Port == port {
			return Decision{Verdict: VerdictAllow, Reason: ReasonEndpointAllowed}
		}
	}
	return deny(ReasonNoMatchingEndpoint)
}

// Request makes the request-scoped decision for a path on a host.
//
// requestPath is the escaped path forwarded upstream. It must use canonical
// escapes, and both its escaped and decoded forms must be absolute and in
// shortest form. The matched endpoint must remain the unique longest match
// after percent-decoding the path and every prefix once.
func (m *Matcher) Request(host string, port int, requestPath string) Decision {
	connection := m.Connection(host, port)
	if !connection.Allowed() {
		return connection
	}
	if !normalizedPath(requestPath) {
		return deny(ReasonMalformedRequest)
	}
	if m.any {
		endpoint := m.originEndpoint(NormalizeHost(host), port)
		return Decision{Verdict: VerdictAllow, Reason: ReasonEndpointAllowed, Endpoint: &endpoint}
	}
	for _, endpoint := range m.byHost[NormalizeHost(host)] {
		if endpoint.Port == port && coversPath(endpoint.PathPrefix, requestPath) {
			if m.decodedPathConflicts(endpoint, requestPath) {
				return deny(ReasonMalformedRequest)
			}
			return Decision{Verdict: VerdictAllow, Reason: ReasonEndpointAllowed, Endpoint: &endpoint}
		}
	}
	return deny(ReasonNoMatchingEndpoint)
}

// DenyList is the list this matcher holds. The upstream dialer checks
// every resolved address against it.
func (m *Matcher) DenyList() *DenyList {
	return m.deny
}

// Hosts lists the hosts the document allows, sorted, for the admin socket.
// It is empty under any_endpoint, which AllowsAny reports.
func (m *Matcher) Hosts() []string {
	hosts := make([]string, 0, len(m.byHost))
	for host := range m.byHost {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

// originEndpoint is the endpoint a request to host and port matches under
// any_endpoint.
func (m *Matcher) originEndpoint(host string, port int) Endpoint {
	return Endpoint{
		Host: host, Port: port, PathPrefix: "/", Resource: Origin(host, port), Credential: m.placement,
	}
}

func (m *Matcher) decodedPathConflicts(selected Endpoint, requestPath string) bool {
	decodedPath, pathErr := url.PathUnescape(requestPath)
	decodedPrefix, prefixErr := url.PathUnescape(selected.PathPrefix)
	if pathErr != nil || prefixErr != nil {
		return true
	}
	for _, endpoint := range m.byHost[selected.Host] {
		if endpoint.Port != selected.Port || endpoint.PathPrefix == selected.PathPrefix {
			continue
		}
		prefix, err := url.PathUnescape(endpoint.PathPrefix)
		if err != nil {
			return true
		}
		if len(prefix) >= len(decodedPrefix) && coversPath(prefix, decodedPath) {
			return true
		}
	}
	return false
}

// prefixProblem says what is wrong with a path prefix, or returns "" when
// nothing is.
func prefixProblem(prefix string) string {
	switch {
	case !CanonicalEscapes(prefix):
		return NonCanonicalEscape
	case !normalizedPath(prefix):
		return "must be an absolute path in its shortest form"
	}
	return ""
}

// normalizedPath reports whether requestPath is absolute and in its shortest
// form. It keeps a trailing slash, because "/api/" and "/api" are different
// paths.
//
// requestPath is the escaped path, the bytes that go upstream. Both that
// form and its decoded form must be in shortest form. Checking the escaped
// form alone would accept "/api/%2e%2e/secret", which no cleaning of those
// bytes changes and which an upstream that decodes first reads as
// "/secret".
func normalizedPath(requestPath string) bool {
	if requestPath == "" || !strings.HasPrefix(requestPath, "/") {
		return false
	}
	// This guards the path prefix a document declares. A request cannot
	// have either character: the request target's query splits off before
	// the path, and EscapedPath writes "#" as "%23".
	if strings.ContainsAny(requestPath, "?#") {
		return false
	}
	if !CanonicalEscapes(requestPath) || !shortestForm(requestPath) {
		return false
	}
	decoded, err := url.PathUnescape(requestPath)
	if err != nil {
		return false
	}
	return shortestForm(decoded)
}

// CanonicalEscapes reports whether every percent-escape in escaped uses
// uppercase hex digits and encodes a character outside the unreserved set of
// RFC 3986 section 2.3: a letter, a digit, "-", ".", "_" or "~". A malformed
// escape is not canonical.
func CanonicalEscapes(escaped string) bool {
	for i := 0; i < len(escaped); i++ {
		if escaped[i] != '%' {
			continue
		}
		if i+2 >= len(escaped) {
			return false
		}
		high := strings.IndexByte(upperHexDigits, escaped[i+1])
		low := strings.IndexByte(upperHexDigits, escaped[i+2])
		if high < 0 || low < 0 || unreserved(high<<4|low) {
			return false
		}
		i += 2
	}
	return true
}

// upperHexDigits are the hex digits a canonical escape uses, in value order.
const upperHexDigits = "0123456789ABCDEF"

// NonCanonicalEscape is the problem text for a path prefix that
// CanonicalEscapes refuses.
const NonCanonicalEscape = "percent-encodes an unreserved character or uses lowercase hex. " +
	"Write letters, digits and \"-._~\" unescaped, and every escape in uppercase"

// unreserved reports whether c is in the unreserved set of RFC 3986
// section 2.3.
func unreserved(c int) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// shortestForm reports whether cleaning the path leaves it alone, except for
// a trailing slash.
func shortestForm(requestPath string) bool {
	cleaned := path.Clean(requestPath)
	return cleaned == requestPath || cleaned+"/" == requestPath
}
