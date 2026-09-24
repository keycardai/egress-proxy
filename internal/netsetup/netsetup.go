// Package netsetup generates and applies the iptables ruleset that sends a
// pod's outbound TCP traffic into the egress proxy and drops everything the
// proxy does not govern.
//
// The redirect routes traffic and the filter table's terminal DROP enforces.
// Capture on its own is not a security boundary: a workload that can call
// setuid to the proxy uid escapes both the redirect and the filter
// exclusion. The bypass is published against Istio
// (https://pulsesecurity.co.nz/advisories/istio-egress-bypass), and Istio
// states the same limit
// (https://istio.io/latest/docs/ops/best-practices/security/#understand-traffic-capture-limitations).
// The mitigation is the workload securityContext, and
// docs/security-model.md states it.
package netsetup

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Family is an IP address family. One Program covers one family, because
// iptables and ip6tables are separate rule sets with separate binaries.
type Family int

// The address families.
const (
	FamilyIPv4 Family = iota
	FamilyIPv6
)

func (f Family) String() string {
	if f == FamilyIPv6 {
		return "ipv6"
	}
	return "ipv4"
}

// Defaults for the pod contract this ruleset is written for.
const (
	// DefaultProxyUID is the uid the sidecar runs as.
	DefaultProxyUID = 1337
	// DefaultRedirectPort is the sidecar's transparent listener. It is below
	// 1024, so an unprivileged workload cannot bind it during a sidecar
	// restart and stand in for the proxy. The sidecar holds
	// NET_BIND_SERVICE and no other capability.
	DefaultRedirectPort = 1015
	// DefaultReceiptPath is where the init container writes what it
	// programmed and where the sidecar reads it. It is on an emptyDir with
	// medium Memory that the two containers share and the workload does not
	// mount.
	DefaultReceiptPath = "/run/egress/netsetup.json"
)

// maxMultiportPorts is the number of ports one multiport match accepts. The
// kernel's XT_MULTI_PORTS is 15, from linux
// include/uapi/linux/netfilter/xt_multiport.h.
const maxMultiportPorts = 15

// maxUID is the highest uid the owner match takes.
const maxUID = 0xFFFFFFF

// Config is the ruleset input. Program is a pure function of it, so the
// rendered ruleset tests rule generation and nothing about the host.
type Config struct {
	// ProxyUID is the uid the sidecar runs as. Its traffic is neither
	// redirected nor dropped, so the proxy can reach an upstream.
	ProxyUID int
	// RedirectPort is the sidecar's transparent listener.
	RedirectPort int
	// CapturePorts are the outbound TCP destination ports sent to that
	// listener. Everything else on TCP is dropped by the filter table. One
	// multiport match carries at most 15 of them.
	CapturePorts []int
	// PodCIDRs and ServiceCIDRs are cluster-internal ranges. Traffic to them
	// is not redirected, because the proxy governs HTTP to external
	// destinations and has nothing to say about a cluster-internal address.
	// The filter DROP still covers them, so they are unreachable rather than
	// unmediated.
	PodCIDRs     []netip.Prefix
	ServiceCIDRs []netip.Prefix
	// DNSServers are the resolvers outbound DNS is accepted to. DNS is
	// accepted by destination and to nowhere else: an accept with no
	// destination match is a tunnel, because any protocol to port 53 on any
	// host would then leave the pod without passing the proxy. At least one
	// server is required.
	DNSServers []netip.Addr
	// IPv6 says what the ip6tables ruleset does.
	IPv6 IPv6Mode
}

// IPv6Mode says what the ip6tables ruleset does.
//
// Every mode governs IPv6. If the kernel has IPv6 and no ip6tables ruleset
// is programmed, the pod reaches any IPv6 destination on any port. Nothing
// redirects that traffic and nothing drops it. The zero value programs
// nothing, so it is correct only on a kernel with no IPv6.
type IPv6Mode int

const (
	// IPv6None programs no ip6tables ruleset. NEVER choose it for a kernel
	// that has IPv6.
	IPv6None IPv6Mode = iota
	// IPv6Proxy redirects captured IPv6 TCP into the proxy and drops the
	// rest, which is what the IPv4 ruleset does.
	IPv6Proxy
	// IPv6Deny drops every IPv6 packet the pod sends. The pod stays
	// reachable over IPv6: replies to a connection opened into it are
	// accepted, as is neighbour discovery, so a dual-stack Service still
	// works.
	IPv6Deny
)

func (m IPv6Mode) String() string {
	switch m {
	case IPv6None:
		return "none"
	case IPv6Proxy:
		return "proxy"
	case IPv6Deny:
		return "deny"
	default:
		return "IPv6Mode(" + strconv.Itoa(int(m)) + ")"
	}
}

// DefaultConfig is the pod contract: the sidecar on uid 1337 with its
// transparent listener on 1015, capturing HTTP and HTTPS, on both address
// families.
//
// It carries no resolvers and therefore does not validate on its own. The
// init container fills them from /etc/resolv.conf.
func DefaultConfig() Config {
	return Config{
		ProxyUID:     DefaultProxyUID,
		RedirectPort: DefaultRedirectPort,
		CapturePorts: []int{80, 443},
		IPv6:         IPv6Proxy,
	}
}

// Families lists the address families to program. A denied family is
// programmed too: the rules that deny it have to go in the tables.
func (c Config) Families() []Family {
	if c.IPv6 == IPv6None {
		return []Family{FamilyIPv4}
	}
	return []Family{FamilyIPv4, FamilyIPv6}
}

// Validate reports every problem it finds, so one run tells an operator
// everything that is wrong with the configuration.
func (c Config) Validate() error {
	var found problems
	if c.ProxyUID < 0 || c.ProxyUID > maxUID {
		found.addf("proxy uid %d is out of range 0-%d", c.ProxyUID, maxUID)
	}
	if c.RedirectPort < 1 || c.RedirectPort > maxPort {
		found.addf("redirect port %d is out of range 1-%d", c.RedirectPort, maxPort)
	}
	found.add(c.capturePortProblems()...)
	found.add(prefixProblems("pod CIDR", c.PodCIDRs)...)
	found.add(prefixProblems("service CIDR", c.ServiceCIDRs)...)
	found.add(c.resolverProblems()...)
	switch c.IPv6 {
	case IPv6None, IPv6Proxy, IPv6Deny:
	default:
		found.addf("IPv6 mode %d is not one this package knows", c.IPv6)
	}
	if len(found) == 0 {
		return nil
	}
	return fmt.Errorf("%w:\n  %s", ErrInvalidConfig, strings.Join(found, "\n  "))
}

// maxPort is the highest TCP port a rule can name.
const maxPort = 65535

func (c Config) capturePortProblems() []string {
	var found problems
	if len(c.CapturePorts) == 0 {
		found.addf("no capture ports: nothing would reach the proxy")
	}
	if len(c.CapturePorts) > maxMultiportPorts {
		found.addf("%d capture ports: one multiport match carries at most %d",
			len(c.CapturePorts), maxMultiportPorts)
	}
	for _, port := range c.CapturePorts {
		if port < 1 || port > maxPort {
			found.addf("capture port %d is out of range 1-%d", port, maxPort)
		}
		if port == c.RedirectPort {
			found.addf("capture port %d is the redirect port, which would redirect the proxy's listener "+
				"to itself", port)
		}
	}
	return found
}

func (c Config) resolverProblems() []string {
	var found problems
	if len(c.DNSServers) == 0 {
		found.addf("no DNS servers: the filter table would drop every resolution. Name the resolvers")
	}
	for _, server := range c.DNSServers {
		switch {
		case !server.IsValid():
			found.addf("a DNS server is not a valid address")
		case server.Is4In6():
			found.addf("DNS server %s is IPv4 written as IPv6; write it as %s", server, server.Unmap())
		case server.Zone() != "":
			found.addf("DNS server %s carries a zone, which iptables cannot match", server)
		}
	}
	return found
}

// prefixProblems refuses a prefix that would go in the wrong family's
// ruleset. A 4-in-6 prefix reads as IPv6 and would emit a rule ip6tables
// cannot match while leaving the IPv4 range unnamed.
func prefixProblems(label string, prefixes []netip.Prefix) []string {
	var found problems
	for _, prefix := range prefixes {
		switch {
		case !prefix.IsValid():
			found.addf("%s is not a valid prefix", label)
		case prefix.Addr().Is4In6():
			found.addf("%s %s is IPv4 written as IPv6; write it as an IPv4 prefix", label, prefix)
		}
	}
	return found
}

// problems collects validation findings so one run reports all of them.
type problems []string

func (p *problems) addf(format string, args ...any) {
	*p = append(*p, fmt.Sprintf(format, args...))
}

func (p *problems) add(found ...string) {
	*p = append(*p, found...)
}

// ipv6ProcPath is the kernel's list of IPv6 interface addresses. The file
// exists exactly when the kernel has IPv6.
const ipv6ProcPath = "/proc/net/if_inet6"

// KernelHasIPv6 reports whether this kernel has IPv6. It picks the IPv6Mode
// a run uses, so read what that type says about an ungoverned family.
//
// NEVER read a failure here as a kernel without IPv6. Only the file being
// absent says that. Any other error means this process cannot tell.
func KernelHasIPv6() (bool, error) {
	return kernelHasIPv6At(ipv6ProcPath)
}

func kernelHasIPv6At(path string) (bool, error) {
	switch _, err := os.Stat(path); {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("%w: %s could not be read: %w", ErrIPv6Undetermined, path, err)
	}
}
