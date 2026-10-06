package netsetup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// The chains this package owns. Applying flushes and refills only these, so
// a rule another component installed is never touched.
const (
	natChain    = "EGRESS_PROXY_NAT_OUTPUT"
	filterChain = "EGRESS_PROXY_FILTER_OUTPUT"
)

// The tables the chains live in.
const (
	natTable    = "nat"
	filterTable = "filter"
)

// ndpTypes are the ICMPv6 message types the filter chain accepts from the
// kernel. The kernel sends Neighbour Discovery and MLD from its own sockets,
// so the proxy uid accept cannot match them. Conntrack marks them UNTRACKED,
// so the conntrack accept cannot match them either. Without these accepts
// every one of them reaches the terminal DROP, and IPv6 stops as soon as the
// kernel needs a neighbour's link-layer address.
//
// RFC 4890 section 4.4.1 lists all eight as traffic that must not be
// dropped. Redirect (137) is not among them: section 4.4.4 leaves it to
// policy, and this policy drops it.
func ndpTypes() []int {
	return []int{
		130, // multicast listener query
		131, // multicast listener report
		132, // multicast listener done
		133, // router solicitation
		134, // router advertisement
		135, // neighbour solicitation
		136, // neighbour advertisement
		143, // multicast listener report v2
	}
}

// Rule is one rule a program installs.
type Rule struct {
	Table string
	Chain string
	Spec  []string
}

// String names the rule in an error or a report.
func (r Rule) String() string {
	return "-t " + r.Table + " -A " + r.Chain + " " + strings.Join(r.Spec, " ")
}

// Program is the ruleset for one address family.
type Program struct {
	Family Family
	// Chains are the chains this package owns, each with its rules in the
	// order they run. Nothing else may hold a rule in one.
	Chains []Chain
	// Jumps attach the owned chains to OUTPUT. Each goes in at position 1,
	// ahead of any rule the rest of the system put there, and only when it
	// is absent. NEVER delete one: OUTPUT must hold the jump at every
	// instant, or its ACCEPT policy governs the pod.
	Jumps []Rule
}

// Chain is a chain this package owns and the rules it holds.
type Chain struct {
	Table string
	Name  string
	Rules [][]string
}

// Program builds the ruleset for one address family. A prefix or a resolver
// of the other family is left out, so one configuration covers both.
func (c Config) Program(family Family) (Program, error) {
	if err := c.Validate(); err != nil {
		return Program{}, err
	}
	program := Program{
		Family: family,
		Chains: []Chain{{Table: filterTable, Name: filterChain}, {Table: natTable, Name: natChain}},
		Jumps: []Rule{
			{Table: filterTable, Chain: "OUTPUT", Spec: []string{"-j", filterChain}},
			// The nat jump does not match on protocol, because the DNS
			// redirect covers UDP as well as TCP.
			{Table: natTable, Chain: "OUTPUT", Spec: []string{"-j", natChain}},
		},
	}
	if family == FamilyIPv6 && c.IPv6 == IPv6Deny {
		program.denyNat()
		program.denyFilter()
	} else {
		program.nat(c, family)
		program.filter(c, family)
	}
	return program, nil
}

// Rules lists every rule the program puts in an owned chain.
func (p *Program) Rules() []Rule {
	var out []Rule
	for _, chain := range p.Chains {
		for _, spec := range chain.Rules {
			out = append(out, Rule{Table: chain.Table, Chain: chain.Name, Spec: spec})
		}
	}
	return out
}

// String renders the program as the iptables-restore input a first run
// loads. It is what the init container's --dry-run prints and what the
// ruleset digest covers.
func (p *Program) String() string {
	return fmt.Sprintf("# %s ruleset\n", p.Family) + p.Restore(p.Jumps)
}

// Restore renders the program as iptables-restore --noflush input that also
// inserts the given jumps. Declaring an owned chain flushes it, so loading
// the input again replaces the chain's rules and adds no second copy.
//
// NEVER put the nat table first. The filter table commits first, so a nat
// table that fails to load leaves captured TCP dropped rather than accepted.
func (p *Program) Restore(jumps []Rule) string {
	var out strings.Builder
	for _, table := range []string{filterTable, natTable} {
		fmt.Fprintf(&out, "*%s\n", table)
		for _, chain := range p.Chains {
			if chain.Table == table {
				fmt.Fprintf(&out, ":%s - [0:0]\n", chain.Name)
			}
		}
		for _, chain := range p.Chains {
			if chain.Table != table {
				continue
			}
			for _, spec := range chain.Rules {
				fmt.Fprintf(&out, "-A %s %s\n", chain.Name, strings.Join(spec, " "))
			}
		}
		for _, jump := range jumps {
			if jump.Table == table {
				fmt.Fprintf(&out, "-I %s 1 %s\n", jump.Chain, strings.Join(jump.Spec, " "))
			}
		}
		out.WriteString("COMMIT\n")
	}
	return out.String()
}

// nat sends outbound TCP to the sidecar's transparent listener and returns
// early for the traffic that must not be intercepted.
func (p *Program) nat(cfg Config, family Family) {
	// The proxy's own traffic must reach an upstream, so it is excluded.
	// This exclusion is the setuid bypass the security model names, and the
	// workload securityContext closes it.
	p.add("-m", "owner", "--uid-owner", strconv.Itoa(cfg.ProxyUID), "-j", "RETURN")
	// The redirected connections and the explicit proxy listener go over
	// loopback. Redirecting it would loop.
	p.add("-o", "lo", "-j", "RETURN")
	// DNS goes to the sidecar's allowlist resolver on loopback, whatever
	// resolver the client named. This is ahead of the cluster ranges,
	// because the cluster resolver's own address is inside the service
	// range and a RETURN there would leave the query for the terminal
	// DROP. Both protocols are redirected: DNS falls back to TCP for an
	// answer that does not fit in a datagram, RFC 7766 section 5.
	if cfg.DNSPort > 0 {
		for _, protocol := range []string{"udp", "tcp"} {
			p.add("-p", protocol, "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(cfg.DNSPort))
		}
	}
	for _, prefix := range prefixesFor(family, cfg.PodCIDRs) {
		p.add("-d", prefix.String(), "-j", "RETURN")
	}
	for _, prefix := range prefixesFor(family, cfg.ServiceCIDRs) {
		p.add("-d", prefix.String(), "-j", "RETURN")
	}
	p.add("-p", "tcp", "-m", "multiport", "--dports", portList(cfg.CapturePorts),
		"-j", "REDIRECT", "--to-ports", strconv.Itoa(cfg.RedirectPort))
	// Everything else is left alone here. The filter DROP covers it.
	p.add("-j", "RETURN")
}

// filter accepts what the proxy needs and drops everything else.
func (p *Program) filter(cfg Config, family Family) {
	p.acceptReplies()
	// A REDIRECT rewrites the destination to loopback, and the reroute check
	// after the nat table sends the packet out through lo. Both the
	// interface and the destination are matched, so the accept does not
	// depend on which one the kernel presents to the filter table.
	p.accept("-o", "lo", "-j", "ACCEPT")
	p.accept("-d", loopbackFor(family), "-j", "ACCEPT")
	p.accept("-m", "owner", "--uid-owner", strconv.Itoa(cfg.ProxyUID), "-j", "ACCEPT")
	if family == FamilyIPv6 {
		p.acceptNeighbourDiscovery()
	}
	// NEVER accept DNS to a resolver here. The nat chain redirects every
	// query the workload sends to the sidecar's resolver on loopback,
	// which the loopback accepts above already cover, and the sidecar's
	// own forwarded queries leave under the owner accept. An accept by
	// destination would let a query the redirect missed leave the pod
	// unread.

	// UDP/443 falls here, so QUIC and HTTP/3 are dropped, along with ICMP,
	// every other non-TCP protocol, and every TCP port outside CapturePorts.
	p.accept("-j", "DROP")
}

// denyNat puts a single RETURN in the nat chain. IPv6Deny redirects
// nothing. The chain and its OUTPUT jump stay, so every family has the same
// shape in the tables.
func (p *Program) denyNat() {
	p.add("-j", "RETURN")
}

// denyFilter drops the IPv6 traffic the pod originates. Replies to
// connections opened into the pod still go out. A flow the pod starts never
// becomes ESTABLISHED, because its first packet meets the DROP.
func (p *Program) denyFilter() {
	p.acceptReplies()
	p.accept("-o", "lo", "-j", "ACCEPT")
	p.accept("-d", loopbackFor(FamilyIPv6), "-j", "ACCEPT")
	p.acceptNeighbourDiscovery()
	p.accept("-j", "DROP")
}

// acceptNeighbourDiscovery accepts the ndpTypes the kernel sends, and no
// ICMPv6 a process sends.
//
// xt_owner matches a packet from no socket, or from a kernel socket, only
// when every uid condition in the rule is negated. It matches a process's
// socket by the process's uid (linux net/netfilter/xt_owner.c, owner_mt).
// The negated range covers every valid uid, so a process with CAP_NET_RAW
// cannot send these types past the DROP, whatever its uid. The kernel sends
// neighbour discovery from its own socket (linux net/ipv6/ndisc.c,
// ndisc_alloc_skb).
func (p *Program) acceptNeighbourDiscovery() {
	for _, icmpType := range ndpTypes() {
		p.accept("-p", "ipv6-icmp", "-m", "owner", "!", "--uid-owner", kernelOnly,
			"-m", "icmp6", "--icmpv6-type", strconv.Itoa(icmpType), "-j", "ACCEPT")
	}
}

// kernelOnly is every valid uid. 4294967295 is (uid_t)-1, which no process
// can hold.
const kernelOnly = "0-4294967294"

// acceptReplies accepts the replies on connections opened into the pod.
// They leave through OUTPUT from a socket owned by any uid, and nothing
// else in the chain matches them.
//
// The accept matches the reply direction only. Conntrack keys a flow on its
// addresses, ports and protocol, not on the socket that sent it. A workload
// socket that sends from a tuple the proxy uid used is in the original
// direction of the proxy's flow. That packet must pass the owner or
// loopback accept like any other, and the DROP takes it.
//
// The second accept passes the packets on an established flow that no
// process socket sends. Once a process closes a TCP socket, the kernel
// detaches it from the process (linux include/net/sock.h, sock_orphan), and
// it still sends its unsent data and its retransmits. The kernel answers
// for a TIME_WAIT socket from a socket of its own. The proxy uid accept
// does not match either, and without them an upstream the proxy closed
// first loses data or waits in LAST_ACK. The negated range matches no
// process socket, as in acceptNeighbourDiscovery. A workload socket has no
// established flow to send on in the original direction, outside loopback.
//
// NEVER add RELATED. It matches a new flow that a conntrack helper expects,
// so the ruleset would hold only while no helper is assigned. Without it the
// pod sends no ICMP error about inbound traffic, such as port unreachable
// for a closed UDP port.
func (p *Program) acceptReplies() {
	p.accept("-m", "conntrack", "--ctstate", "ESTABLISHED", "--ctdir", "REPLY", "-j", "ACCEPT")
	p.accept("-m", "conntrack", "--ctstate", "ESTABLISHED", "-m", "owner", "!", "--uid-owner", kernelOnly,
		"-j", "ACCEPT")
}

// add appends a rule to the nat chain.
func (p *Program) add(spec ...string) {
	p.appendTo(natTable, spec)
}

// accept appends a rule to the filter chain.
func (p *Program) accept(spec ...string) {
	p.appendTo(filterTable, spec)
}

func (p *Program) appendTo(table string, spec []string) {
	for i := range p.Chains {
		if p.Chains[i].Table == table {
			p.Chains[i].Rules = append(p.Chains[i].Rules, spec)
			return
		}
	}
}

// RulesetDigest is a SHA-256 over the rendered programs, in the order they
// are applied. It identifies the ruleset and nothing about the host.
func RulesetDigest(programs []Program) string {
	sum := sha256.New()
	for i := range programs {
		_, _ = sum.Write([]byte(programs[i].String()))
	}
	return "sha256:" + hex.EncodeToString(sum.Sum(nil))
}

func loopbackFor(family Family) string {
	if family == FamilyIPv6 {
		return "::1/128"
	}
	return "127.0.0.0/8"
}

// prefixesFor keeps the prefixes of one family. Validate refuses a 4-in-6
// prefix, so the address form says which family it belongs to.
func prefixesFor(family Family, prefixes []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() == (family == FamilyIPv4) {
			out = append(out, prefix)
		}
	}
	return out
}

func portList(ports []int) string {
	parts := make([]string, len(ports))
	for i, port := range ports {
		parts[i] = strconv.Itoa(port)
	}
	return strings.Join(parts, ",")
}
