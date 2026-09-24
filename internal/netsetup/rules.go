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

// ndpTypes are the ICMPv6 message types the filter chain accepts. Neighbour
// Discovery and MLD have no socket, so the owner match cannot match them,
// and conntrack marks them UNTRACKED, so the conntrack accept cannot match
// them either. Without these accepts every one of them reaches the terminal
// DROP and IPv6 egress stops as soon as a neighbour entry goes stale.
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

// Step is one rule a program installs.
type Step struct {
	Table string
	Chain string
	Spec  []string
	// At is the position an insert puts the rule at. Zero appends.
	At int
	// Existing says the chain belongs to the rest of the system rather than
	// to this package. Such a rule is inserted at At only when no identical
	// rule is anywhere in the chain. It is never deleted: a delete followed
	// by an insert leaves an instant in which OUTPUT has no jump and its
	// ACCEPT policy governs the pod. A rule already present at another
	// position stays there, and Verify refuses it.
	Existing bool
	// Seal says this rule holds the chain closed while the rest of it is
	// filled. Apply appends it in the same pair of invocations that clears
	// the chain, before it touches anything else.
	Seal bool
}

// String renders a step as the iptables arguments it performs.
func (s Step) String() string {
	verb := "-A"
	position := ""
	if s.At > 0 {
		verb, position = "-I", " "+strconv.Itoa(s.At)
	}
	return fmt.Sprintf("-t %s %s %s%s %s", s.Table, verb, s.Chain, position, strings.Join(s.Spec, " "))
}

// Program is the ruleset for one address family. Two properties hold at
// every point in the sequence.
//
// Re-running is idempotent. Each chain this package owns is flushed before
// it is refilled, and each OUTPUT jump is appended only when it is absent.
//
// The chains are never less strict than they were before the run. The
// filter chain is flushed and its terminal DROP installed before any other
// chain is touched, and every accept is inserted above that DROP. A run that
// dies part way leaves a chain that drops what it has not yet been told to
// accept.
type Program struct {
	Family Family
	// Chains are the chains this program creates and flushes, in the order
	// it fills them. Nothing else may hold a rule in one.
	Chains []Chain
	Steps  []Step
	// accepts counts the rules inserted above the filter chain's DROP, which
	// is the position the next one goes in at.
	accepts int
}

// Chain is a chain this package owns and how many rules the program puts in
// it.
type Chain struct {
	Table string
	Name  string
	Rules int
}

// Program builds the ruleset for one address family. A prefix or a resolver
// of the other family is left out, so one configuration carries both.
func (c Config) Program(family Family) (Program, error) {
	if err := c.Validate(); err != nil {
		return Program{}, err
	}
	program := Program{
		Family: family,
		Chains: []Chain{{Table: natTable, Name: natChain}, {Table: filterTable, Name: filterChain}},
	}
	if family == FamilyIPv6 && c.IPv6 == IPv6Deny {
		program.denyNat()
		program.denyFilter()
	} else {
		program.nat(c, family)
		program.filter(c, family)
	}
	// The jumps attach the chains. They go in last, so the chains are full
	// before anything reaches them. Each is the first rule in its OUTPUT
	// chain, ahead of any rule the rest of the system put there.
	program.Steps = append(program.Steps,
		Step{Table: natTable, Chain: "OUTPUT", At: 1, Existing: true, Spec: []string{"-p", "tcp", "-j", natChain}},
		Step{Table: filterTable, Chain: "OUTPUT", At: 1, Existing: true, Spec: []string{"-j", filterChain}},
	)
	program.count()
	return program, nil
}

// String renders the program as the iptables invocations it performs, in the
// order it performs them. It is what the init container's --dry-run prints.
func (p *Program) String() string {
	var out strings.Builder
	fmt.Fprintf(&out, "# %s ruleset, %d rules\n", p.Family, len(p.Steps))
	flush := func(table, chain string) {
		fmt.Fprintf(&out, "-t %s -N %s\n-t %s -F %s\n", table, chain, table, chain)
	}
	for _, step := range p.sealSteps() {
		flush(step.Table, step.Chain)
		fmt.Fprintln(&out, step.String())
	}
	for _, chain := range p.unsealedChains() {
		flush(chain.Table, chain.Name)
	}
	for _, step := range p.fillSteps() {
		fmt.Fprintln(&out, step.String())
	}
	return out.String()
}

// sealSteps are the rules that hold a chain closed while the rest of it is
// filled. Each goes in right after its own chain is flushed, before any
// other chain is touched, which is the first part of the order Apply and
// String both walk.
//
// The OUTPUT jump an earlier run installed is never deleted, so between the
// flush and the seal that jump would reach an empty chain and the OUTPUT
// policy, ACCEPT in a pod, would govern every protocol and port.
func (p *Program) sealSteps() []Step {
	return p.stepsWhere(true)
}

// fillSteps are every other rule, in the order they go in.
func (p *Program) fillSteps() []Step {
	return p.stepsWhere(false)
}

func (p *Program) stepsWhere(seal bool) []Step {
	out := make([]Step, 0, len(p.Steps))
	for _, step := range p.Steps {
		if step.Seal == seal {
			out = append(out, step)
		}
	}
	return out
}

// unsealedChains are the owned chains no seal flushed, which are flushed
// once every seal is in place.
func (p *Program) unsealedChains() []Chain {
	sealed := make(map[string]bool, len(p.Chains))
	for _, step := range p.sealSteps() {
		sealed[step.Table+" "+step.Chain] = true
	}
	out := make([]Chain, 0, len(p.Chains))
	for _, chain := range p.Chains {
		if !sealed[chain.Table+" "+chain.Name] {
			out = append(out, chain)
		}
	}
	return out
}

// nat sends outbound TCP to the sidecar's transparent listener and returns
// early for the traffic that must not be intercepted.
func (p *Program) nat(cfg Config, family Family) {
	// The proxy's own traffic must reach an upstream, so it is excluded.
	// This exclusion is the setuid bypass the security model names, and the
	// workload securityContext closes it.
	p.add("-m", "owner", "--uid-owner", strconv.Itoa(cfg.ProxyUID), "-j", "RETURN")
	// Loopback carries the redirected connections themselves and the
	// explicit proxy listener. Redirecting it would loop.
	p.add("-o", "lo", "-j", "RETURN")
	for _, prefix := range prefixesFor(family, cfg.PodCIDRs) {
		p.add("-d", prefix.String(), "-j", "RETURN")
	}
	for _, prefix := range prefixesFor(family, cfg.ServiceCIDRs) {
		p.add("-d", prefix.String(), "-j", "RETURN")
	}
	p.add("-p", "tcp", "-m", "multiport", "--dports", portList(cfg.CapturePorts),
		"-j", "REDIRECT", "--to-ports", strconv.Itoa(cfg.RedirectPort))
	// Everything else is left alone here and handled by the filter table. A
	// nat chain that is empty part way through a run redirects nothing, and
	// the filter DROP covers what it does not redirect.
	p.add("-j", "RETURN")
}

// filter seals the chain with the terminal DROP, then inserts the accepts
// the proxy needs above it.
func (p *Program) filter(cfg Config, family Family) {
	// The DROP is the chain's seal, so Apply installs it in the invocation
	// straight after the flush. UDP/443 falls here, so QUIC and HTTP/3 are
	// dropped, along with ICMP, every other non-TCP protocol, and every TCP
	// port outside CapturePorts.
	p.Steps = append(p.Steps, Step{
		Table: filterTable, Chain: filterChain, Spec: []string{"-j", "DROP"}, Seal: true,
	})
	// Replies to connections opened into the pod leave through OUTPUT, and
	// nothing else in the chain matches them: the owner match matches the
	// socket owner, and a reply from a socket owned by any uid but the
	// proxy's reaches the terminal DROP. This does not widen what the
	// workload may initiate: an outbound flow becomes ESTABLISHED only after
	// its own first packet was accepted.
	p.accept("-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	// A REDIRECT rewrites the destination to loopback, and the reroute check
	// after the nat table sends the packet out through lo. Both the
	// interface and the destination are matched, so the accept does not
	// depend on which one the kernel presents to the filter table.
	p.accept("-o", "lo", "-j", "ACCEPT")
	p.accept("-d", loopbackFor(family), "-j", "ACCEPT")
	p.accept("-m", "owner", "--uid-owner", strconv.Itoa(cfg.ProxyUID), "-j", "ACCEPT")
	if family == FamilyIPv6 {
		for _, icmpType := range ndpTypes() {
			p.accept("-p", "ipv6-icmp", "-m", "icmp6", "--icmpv6-type", strconv.Itoa(icmpType), "-j", "ACCEPT")
		}
	}
	// DNS falls back to TCP for a response that does not fit in a datagram,
	// RFC 7766 section 5, so both protocols are accepted to each resolver.
	for _, protocol := range []string{"udp", "tcp"} {
		for _, server := range addrsFor(family, cfg.DNSServers) {
			p.accept("-d", server.String(), "-p", protocol, "--dport", "53", "-j", "ACCEPT")
		}
	}
}

// denyNat puts a single RETURN in the nat chain. IPv6Deny redirects
// nothing. The chain and its OUTPUT jump stay, so every family has the same
// shape in the tables.
func (p *Program) denyNat() {
	p.add("-j", "RETURN")
}

// denyFilter drops the IPv6 traffic the pod originates, and leaves the pod
// reachable over IPv6. A reply to a connection opened into the pod is
// ESTABLISHED, so it is accepted. A flow the pod starts never becomes
// ESTABLISHED, because its first packet meets the DROP.
//
// NEVER add RELATED here. A conntrack helper can use it to admit a new
// outbound flow to any address and port.
func (p *Program) denyFilter() {
	p.Steps = append(p.Steps, Step{
		Table: filterTable, Chain: filterChain, Spec: []string{"-j", "DROP"}, Seal: true,
	})
	p.accept("-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT")
	p.accept("-o", "lo", "-j", "ACCEPT")
	p.accept("-d", loopbackFor(FamilyIPv6), "-j", "ACCEPT")
	for _, icmpType := range ndpTypes() {
		p.accept("-p", "ipv6-icmp", "-m", "icmp6", "--icmpv6-type", strconv.Itoa(icmpType), "-j", "ACCEPT")
	}
}

// add appends a rule to the nat chain.
func (p *Program) add(spec ...string) {
	p.Steps = append(p.Steps, Step{Table: natTable, Chain: natChain, Spec: spec})
}

// accept inserts one rule above the filter chain's terminal DROP, keeping
// the accepts in the order they are written.
func (p *Program) accept(spec ...string) {
	p.accepts++
	p.Steps = append(p.Steps, Step{Table: filterTable, Chain: filterChain, At: p.accepts, Spec: spec})
}

// count fills in how many rules each owned chain holds, which is what
// Verify compares the tables against.
func (p *Program) count() {
	for i := range p.Chains {
		for _, step := range p.Steps {
			if step.Table == p.Chains[i].Table && step.Chain == p.Chains[i].Name {
				p.Chains[i].Rules++
			}
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

func addrsFor(family Family, addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if addr.Is4() == (family == FamilyIPv4) {
			out = append(out, addr)
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
