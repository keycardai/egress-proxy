package netsetup_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// denying is the same configuration with IPv6 denied rather than proxied.
func denying(cfg netsetup.Config) netsetup.Config {
	cfg.IPv6 = netsetup.IPv6Deny
	return cfg
}

func build(t *testing.T, cfg netsetup.Config, family netsetup.Family) netsetup.Program {
	t.Helper()
	program, err := cfg.Program(family)
	require.NoError(t, err, "build the %s ruleset", family)
	return program
}

// The expected iptables-restore input for each ruleset. Each is pinned
// whole, so a rule that is added, dropped or moved fails the test.
//
// The DNS redirect is ahead of the cluster ranges. The cluster resolver's
// address is inside the service range, and a RETURN there would leave the
// query for the DROP instead of the sidecar's resolver. The filter chain
// does not accept DNS to any resolver. The nat jump does not match on
// protocol, so UDP reaches the redirect. The ESTABLISHED accept matches the
// reply direction, so a workload packet on a tuple the proxy uid used
// reaches the DROP.
const (
	wantIPv4 = `# ipv4 ruleset
*filter
:EGRESS_PROXY_FILTER_OUTPUT - [0:0]
-A EGRESS_PROXY_FILTER_OUTPUT -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -m conntrack --ctstate ESTABLISHED -m owner ! --uid-owner 0-4294967294 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -o lo -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -d 127.0.0.0/8 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -m owner --uid-owner 1337 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -j DROP
-I OUTPUT 1 -j EGRESS_PROXY_FILTER_OUTPUT
COMMIT
*nat
:EGRESS_PROXY_NAT_OUTPUT - [0:0]
-A EGRESS_PROXY_NAT_OUTPUT -m owner --uid-owner 1337 -j RETURN
-A EGRESS_PROXY_NAT_OUTPUT -o lo -j RETURN
-A EGRESS_PROXY_NAT_OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
-A EGRESS_PROXY_NAT_OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53
-A EGRESS_PROXY_NAT_OUTPUT -d 10.42.0.0/16 -j RETURN
-A EGRESS_PROXY_NAT_OUTPUT -d 10.43.0.0/16 -j RETURN
-A EGRESS_PROXY_NAT_OUTPUT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 1015
-A EGRESS_PROXY_NAT_OUTPUT -j RETURN
-I OUTPUT 1 -j EGRESS_PROXY_NAT_OUTPUT
COMMIT
`
	wantIPv6 = `# ipv6 ruleset
*filter
:EGRESS_PROXY_FILTER_OUTPUT - [0:0]
-A EGRESS_PROXY_FILTER_OUTPUT -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -m conntrack --ctstate ESTABLISHED -m owner ! --uid-owner 0-4294967294 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -o lo -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -d ::1/128 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -m owner --uid-owner 1337 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 130 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 131 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 132 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 133 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 134 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 135 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 136 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 143 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -j DROP
-I OUTPUT 1 -j EGRESS_PROXY_FILTER_OUTPUT
COMMIT
*nat
:EGRESS_PROXY_NAT_OUTPUT - [0:0]
-A EGRESS_PROXY_NAT_OUTPUT -m owner --uid-owner 1337 -j RETURN
-A EGRESS_PROXY_NAT_OUTPUT -o lo -j RETURN
-A EGRESS_PROXY_NAT_OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
-A EGRESS_PROXY_NAT_OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53
-A EGRESS_PROXY_NAT_OUTPUT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 1015
-A EGRESS_PROXY_NAT_OUTPUT -j RETURN
-I OUTPUT 1 -j EGRESS_PROXY_NAT_OUTPUT
COMMIT
`
	// With DNSPort 0 nothing redirects DNS and nothing accepts it, so every
	// query the workload sends anywhere but loopback reaches the DROP.
	wantIPv4NoDNS = `# ipv4 ruleset
*filter
:EGRESS_PROXY_FILTER_OUTPUT - [0:0]
-A EGRESS_PROXY_FILTER_OUTPUT -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -m conntrack --ctstate ESTABLISHED -m owner ! --uid-owner 0-4294967294 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -o lo -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -d 127.0.0.0/8 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -m owner --uid-owner 1337 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -j DROP
-I OUTPUT 1 -j EGRESS_PROXY_FILTER_OUTPUT
COMMIT
*nat
:EGRESS_PROXY_NAT_OUTPUT - [0:0]
-A EGRESS_PROXY_NAT_OUTPUT -m owner --uid-owner 1337 -j RETURN
-A EGRESS_PROXY_NAT_OUTPUT -o lo -j RETURN
-A EGRESS_PROXY_NAT_OUTPUT -d 10.42.0.0/16 -j RETURN
-A EGRESS_PROXY_NAT_OUTPUT -d 10.43.0.0/16 -j RETURN
-A EGRESS_PROXY_NAT_OUTPUT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 1015
-A EGRESS_PROXY_NAT_OUTPUT -j RETURN
-I OUTPUT 1 -j EGRESS_PROXY_NAT_OUTPUT
COMMIT
`
	// The denied family redirects nothing and accepts no egress: no owner
	// exemption, no resolver and no cluster range.
	wantIPv6Deny = `# ipv6 ruleset
*filter
:EGRESS_PROXY_FILTER_OUTPUT - [0:0]
-A EGRESS_PROXY_FILTER_OUTPUT -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -m conntrack --ctstate ESTABLISHED -m owner ! --uid-owner 0-4294967294 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -o lo -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -d ::1/128 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 130 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 131 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 132 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 133 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 134 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 135 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 136 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -p ipv6-icmp -m owner ! --uid-owner 0-4294967294 -m icmp6 --icmpv6-type 143 -j ACCEPT
-A EGRESS_PROXY_FILTER_OUTPUT -j DROP
-I OUTPUT 1 -j EGRESS_PROXY_FILTER_OUTPUT
COMMIT
*nat
:EGRESS_PROXY_NAT_OUTPUT - [0:0]
-A EGRESS_PROXY_NAT_OUTPUT -j RETURN
-I OUTPUT 1 -j EGRESS_PROXY_NAT_OUTPUT
COMMIT
`
)

// TestProgramRules pins the rules each family gets. Program is a pure
// function of the configuration, so these cases test rule generation and
// nothing about the host. The acceptance scenario proves what the kernel
// does with them.
func TestProgramRules(t *testing.T) {
	t.Parallel()
	cluster := valid()
	cluster.PodCIDRs = []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}
	cluster.ServiceCIDRs = []netip.Prefix{netip.MustParsePrefix("10.43.0.0/16")}
	cluster.DNSServers = []netip.Addr{netip.MustParseAddr("10.43.0.10"), netip.MustParseAddr("fd00::a")}
	noResolver := cluster
	noResolver.DNSPort = 0

	tests := []struct {
		name   string
		cfg    netsetup.Config
		family netsetup.Family
		want   string
	}{
		{name: "the IPv4 ruleset", cfg: cluster, family: netsetup.FamilyIPv4, want: wantIPv4},
		// The pod and service CIDRs in the configuration are IPv4, so the
		// IPv6 nat chain returns early for none of them.
		{name: "the IPv6 ruleset", cfg: cluster, family: netsetup.FamilyIPv6, want: wantIPv6},
		{name: "the IPv6 ruleset under IPv6Deny", cfg: denying(cluster), family: netsetup.FamilyIPv6, want: wantIPv6Deny},
		{name: "the IPv4 ruleset under IPv6Deny", cfg: denying(cluster), family: netsetup.FamilyIPv4, want: wantIPv4},
		{name: "no resolver, so no DNS is redirected", cfg: noResolver, family: netsetup.FamilyIPv4, want: wantIPv4NoDNS},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			program := build(t, tc.cfg, tc.family)
			assert.Equal(t, tc.want, program.String(), "the iptables-restore input")
		})
	}
}

// TestTheTerminalDropIsLast checks the property Verify relies on in every
// ruleset: the filter chain holds one DROP and it is the last rule.
func TestTheTerminalDropIsLast(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		cfg    netsetup.Config
		family netsetup.Family
	}{
		{name: "IPv4", cfg: valid(), family: netsetup.FamilyIPv4},
		{name: "IPv6", cfg: valid(), family: netsetup.FamilyIPv6},
		{name: "IPv6 under IPv6Deny", cfg: denying(valid()), family: netsetup.FamilyIPv6},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			program := build(t, tc.cfg, tc.family)
			var filter [][]string
			for _, chain := range program.Chains {
				if chain.Table == "filter" {
					filter = chain.Rules
				}
			}
			require.NotEmpty(t, filter, "the filter chain holds rules")
			drops := 0
			for _, spec := range filter {
				if strings.Join(spec, " ") == "-j DROP" {
					drops++
				}
			}
			assert.Equal(t, 1, drops, "the filter chain holds one DROP")
			assert.Equal(t, []string{"-j", "DROP"}, filter[len(filter)-1], "the DROP is the last rule")
		})
	}
}

// TestRestoreInsertsOnlyTheJumpsItIsGiven proves a re-run leaves out a jump
// that is already in OUTPUT, and that the filter table is committed before
// the nat table whichever jumps go in.
func TestRestoreInsertsOnlyTheJumpsItIsGiven(t *testing.T) {
	t.Parallel()
	program := build(t, valid(), netsetup.FamilyIPv4)
	filterJump, natJump := program.Jumps[0], program.Jumps[1]
	tests := []struct {
		name  string
		jumps []netsetup.Rule
		want  []string
	}{
		{name: "no jump, as on a re-run", jumps: nil, want: nil},
		{
			name:  "the nat jump alone",
			jumps: []netsetup.Rule{natJump},
			want:  []string{"-I OUTPUT 1 -j EGRESS_PROXY_NAT_OUTPUT"},
		},
		{
			name:  "both jumps, as on a first run",
			jumps: []netsetup.Rule{filterJump, natJump},
			want:  []string{"-I OUTPUT 1 -j EGRESS_PROXY_FILTER_OUTPUT", "-I OUTPUT 1 -j EGRESS_PROXY_NAT_OUTPUT"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := program.Restore(tc.jumps)
			var inserts []string
			for line := range strings.Lines(input) {
				if strings.HasPrefix(line, "-I ") {
					inserts = append(inserts, strings.TrimSpace(line))
				}
			}
			assert.Equal(t, tc.want, inserts, "the jumps the input inserts")
			filter, nat := strings.Index(input, "*filter\n"), strings.Index(input, "*nat\n")
			require.GreaterOrEqual(t, filter, 0, "the input loads the filter table")
			assert.Less(t, filter, nat, "the filter table commits before the nat table")
		})
	}
}

// TestRulesetDigestCoversTheRules proves two rulesets that differ are
// identified apart, so a sidecar comparing digests compares what is in the
// tables.
func TestRulesetDigestCoversTheRules(t *testing.T) {
	t.Parallel()
	other := valid()
	other.RedirectPort = 1016
	first := build(t, valid(), netsetup.FamilyIPv4)
	same := build(t, valid(), netsetup.FamilyIPv4)
	changed := build(t, other, netsetup.FamilyIPv4)
	assert.Equal(t, netsetup.RulesetDigest([]netsetup.Program{first}),
		netsetup.RulesetDigest([]netsetup.Program{same}), "one configuration digests the same twice")
	assert.NotEqual(t, netsetup.RulesetDigest([]netsetup.Program{first}),
		netsetup.RulesetDigest([]netsetup.Program{changed}), "another redirect port digests differently")
}

// TestProgramRefusesAnInvalidConfiguration proves no ruleset is built from a
// configuration that does not validate.
func TestProgramRefusesAnInvalidConfiguration(t *testing.T) {
	t.Parallel()
	cfg := valid()
	cfg.DNSServers = nil
	_, err := cfg.Program(netsetup.FamilyIPv4)
	require.ErrorIs(t, err, netsetup.ErrInvalidConfig, "the error the caller keys on")
}
