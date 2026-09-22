package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strings"
)

var errEndpoint = errors.New("invalid endpoint")

// Endpoint is one entry of the document's endpoint list, reduced to what the
// matcher needs.
type Endpoint struct {
	// Host is a DNS name, lowercase, without a port.
	Host string
	// PathPrefix is an absolute path. "/" covers every path on the host. A
	// prefix that ends in "/" covers everything under it. Any other prefix
	// covers itself and every path under it as a segment, so "/api" covers
	// "/api" and "/api/v1" but not "/apis".
	PathPrefix string
	// Resource is the resource identifier the exchange sends for this
	// endpoint.
	Resource string
	// HasCredential says the endpoint names a credential to inject.
	HasCredential bool
}

// ID names the endpoint on an audit record: the host and the prefix.
func (e Endpoint) ID() string {
	return e.Host + e.PathPrefix
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
	// Endpoint is the endpoint that matched. Request sets it on an allow;
	// Host leaves it nil, because a host-scoped decision matches no path.
	Endpoint *Endpoint
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
		if previous, ok := seen[endpoint.ID()]; ok {
			problems = append(problems, fmt.Sprintf(
				"endpoints[%d]: host %q with path_prefix %q repeats endpoints[%d]",
				i, endpoint.Host, endpoint.PathPrefix, previous,
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

// Host makes the connection-scoped decision: whether the sandbox can reach this
// host at all. The deny list answers first, then the endpoint list.
//
// An allow here names no endpoint. The question has no path in it, so no
// endpoint has matched, and naming one would put a path prefix on a record
// that no path took part in. Request names the endpoint that matched.
func (m *Matcher) Host(host string) Decision {
	host = NormalizeHost(host)
	if host == "" {
		return deny(ReasonNoSNI)
	}
	if m.deny.DeniesHost(host) {
		return deny(ReasonDenyAlways)
	}
	if len(m.byHost[host]) == 0 {
		return deny(ReasonNoMatchingEndpoint)
	}
	return Decision{Verdict: VerdictAllow, Reason: ReasonEndpointAllowed}
}

// Request makes the request-scoped decision for a path on a host.
//
// The path must be absolute and already in its shortest form. A path that
// carries dot segments matches one endpoint here and reaches another
// upstream, so Request refuses it.
func (m *Matcher) Request(host, requestPath string) Decision {
	connection := m.Host(host)
	if !connection.Allowed() {
		return connection
	}
	if !normalizedPath(requestPath) {
		return deny(ReasonMalformedRequest)
	}
	for _, endpoint := range m.byHost[NormalizeHost(host)] {
		if endpoint.covers(requestPath) {
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
func normalizedPath(requestPath string) bool {
	if requestPath == "" || !strings.HasPrefix(requestPath, "/") {
		return false
	}
	if strings.ContainsAny(requestPath, "?#") {
		return false
	}
	cleaned := path.Clean(requestPath)
	return cleaned == requestPath || cleaned+"/" == requestPath
}
