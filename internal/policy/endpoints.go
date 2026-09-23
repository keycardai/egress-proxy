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
	// Resource is the resource identifier the exchange sends for this
	// endpoint, and the key the credential source answers on.
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

// covers reports whether the endpoint's prefix covers a normalized path.
func (e Endpoint) covers(requestPath string) bool {
	if strings.HasSuffix(e.PathPrefix, "/") {
		return strings.HasPrefix(requestPath, e.PathPrefix)
	}
	return requestPath == e.PathPrefix || strings.HasPrefix(requestPath, e.PathPrefix+"/")
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
}

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
		if !normalizedPath(endpoint.PathPrefix) {
			problems = append(problems, fmt.Sprintf(
				"endpoints[%d]: path_prefix %q must be an absolute path in its shortest form",
				i, endpoint.PathPrefix,
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
				"endpoints[%d]: host %q on port %d with path_prefix %q repeats endpoints[%d]",
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
	for _, endpoint := range m.byHost[host] {
		if endpoint.Port == port {
			return Decision{Verdict: VerdictAllow, Reason: ReasonEndpointAllowed}
		}
	}
	return deny(ReasonNoMatchingEndpoint)
}

// Request makes the request-scoped decision for a path on a host.
//
// requestPath is the escaped path, exactly the bytes the upstream receives,
// so the decision and the forwarded request read one path.
//
// The path must be absolute and already in its shortest form, decoded as
// well as escaped. Request refuses a path carrying dot segments, which can
// match one endpoint here and reach another upstream.
func (m *Matcher) Request(host string, port int, requestPath string) Decision {
	connection := m.Connection(host, port)
	if !connection.Allowed() {
		return connection
	}
	if !normalizedPath(requestPath) {
		return deny(ReasonMalformedRequest)
	}
	for _, endpoint := range m.byHost[NormalizeHost(host)] {
		if endpoint.Port == port && endpoint.covers(requestPath) {
			return Decision{Verdict: VerdictAllow, Reason: ReasonEndpointAllowed, Endpoint: &endpoint}
		}
	}
	return deny(ReasonNoMatchingEndpoint)
}

// DenyList is the list this matcher carries. The upstream dialer checks
// every resolved address against it.
func (m *Matcher) DenyList() *DenyList {
	return m.deny
}

// Hosts lists the hosts the document allows, sorted, for the admin socket.
func (m *Matcher) Hosts() []string {
	hosts := make([]string, 0, len(m.byHost))
	for host := range m.byHost {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
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
	// carry either character: the request target's query splits off before
	// the path, and EscapedPath writes "#" as "%23".
	if strings.ContainsAny(requestPath, "?#") {
		return false
	}
	if !shortestForm(requestPath) {
		return false
	}
	decoded, err := url.PathUnescape(requestPath)
	if err != nil {
		return false
	}
	return shortestForm(decoded)
}

// shortestForm reports whether cleaning the path leaves it alone, except for
// a trailing slash.
func shortestForm(requestPath string) bool {
	cleaned := path.Clean(requestPath)
	return cleaned == requestPath || cleaned+"/" == requestPath
}
