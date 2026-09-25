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

// render builds one family's ruleset and returns it as the iptables
// invocations it performs.
func render(t *testing.T, cfg netsetup.Config, family netsetup.Family) string {
	t.Helper()
	program, err := cfg.Program(family)
	require.NoError(t, err, "build the %s ruleset", family)
	return program.String()
}

// TestProgramRules pins the rules each family gets. Program is a pure
// function of the configuration, so these cases test rule generation and
// nothing about the host.
func TestProgramRules(t *testing.T) {
	t.Parallel()
	cluster := valid()
	cluster.PodCIDRs = []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}
	cluster.ServiceCIDRs = []netip.Prefix{netip.MustParsePrefix("10.43.0.0/16")}
	cluster.DNSServers = []netip.Addr{netip.MustParseAddr("10.43.0.10"), netip.MustParseAddr("fd00::a")}

	tests := []struct {
		name   string
		cfg    netsetup.Config
		family netsetup.Family
		want   []string
		// absent are rules this family's ruleset must not carry.
		absent []string
	}{
		{
			name: "the IPv4 ruleset", cfg: cluster, family: netsetup.FamilyIPv4,
			want: []string{
				// The proxy's own traffic is excluded, so it can reach an
				// upstream. This is the setuid bypass the security model names.
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -m owner --uid-owner 1337 -j RETURN",
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -o lo -j RETURN",
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -d 10.42.0.0/16 -j RETURN",
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -d 10.43.0.0/16 -j RETURN",
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -p tcp -m multiport --dports 80,443 " +
					"-j REDIRECT --to-ports 1015",
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -j RETURN",
				// The DROP is appended before any accept, so a run that dies
				// part way leaves the chain dropping what it was not yet told
				// to accept.
				"-t filter -A EGRESS_PROXY_FILTER_OUTPUT -j DROP",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 1 -m conntrack --ctstate ESTABLISHED -j ACCEPT",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 2 -o lo -j ACCEPT",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 3 -d 127.0.0.0/8 -j ACCEPT",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 4 -m owner --uid-owner 1337 -j ACCEPT",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 5 -d 10.43.0.10 -p udp --dport 53 -j ACCEPT",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 6 -d 10.43.0.10 -p tcp --dport 53 -j ACCEPT",
				"-t nat -I OUTPUT 1 -p tcp -j EGRESS_PROXY_NAT_OUTPUT",
				"-t filter -I OUTPUT 1 -j EGRESS_PROXY_FILTER_OUTPUT",
			},
			absent: []string{"fd00::a", "::1/128", "ipv6-icmp", "RELATED"},
		},
		{
			name: "the IPv6 ruleset", cfg: cluster, family: netsetup.FamilyIPv6,
			want: []string{
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 3 -d ::1/128 -j ACCEPT",
				// Neighbour Discovery and MLD have no socket, so the owner
				// match cannot match them and conntrack marks them UNTRACKED.
				// Without these accepts IPv6 egress stops as soon as a
				// neighbour entry goes stale.
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 5 -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j ACCEPT",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 12 -p ipv6-icmp -m icmp6 --icmpv6-type 143 -j ACCEPT",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 13 -d fd00::a -p udp --dport 53 -j ACCEPT",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 14 -d fd00::a -p tcp --dport 53 -j ACCEPT",
			},
			// RFC 4890 section 4.4.4 leaves Redirect to policy, and this
			// policy drops it.
			absent: []string{"10.43.0.10", "127.0.0.0/8", "--icmpv6-type 137", "--icmpv6-type 128", "RELATED"},
		},
		{
			name: "the IPv6 ruleset under IPv6Deny", cfg: denying(cluster), family: netsetup.FamilyIPv6,
			want: []string{
				"-t filter -A EGRESS_PROXY_FILTER_OUTPUT -j DROP",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 1 -m conntrack --ctstate ESTABLISHED -j ACCEPT",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 2 -o lo -j ACCEPT",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 3 -d ::1/128 -j ACCEPT",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 4 -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j ACCEPT",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 11 -p ipv6-icmp -m icmp6 --icmpv6-type 143 -j ACCEPT",
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -j RETURN",
				"-t nat -I OUTPUT 1 -p tcp -j EGRESS_PROXY_NAT_OUTPUT",
				"-t filter -I OUTPUT 1 -j EGRESS_PROXY_FILTER_OUTPUT",
			},
			// Each of these would let the pod originate IPv6.
			absent: []string{
				"REDIRECT", "--uid-owner", "--dport 53", "fd00::a", "RELATED",
				"10.42.0.0/16", "10.43.0.0/16",
			},
		},
		{
			// The IPv6 mode does not change the IPv4 ruleset.
			name: "the IPv4 ruleset under IPv6Deny", cfg: denying(cluster), family: netsetup.FamilyIPv4,
			want: []string{
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -p tcp -m multiport --dports 80,443 " +
					"-j REDIRECT --to-ports 1015",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 5 -d 10.43.0.10 -p udp --dport 53 -j ACCEPT",
			},
			absent: []string{"fd00::a", "ipv6-icmp"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rendered := render(t, tc.cfg, tc.family)
			for _, rule := range tc.want {
				mustContainOnce(t, rendered, rule)
			}
			for _, rule := range tc.absent {
				assert.NotContains(t, rendered, rule, "the %s ruleset names nothing of the other family", tc.family)
			}
		})
	}
}

// TestTheTerminalDropIsLast proves the ordering the whole ruleset rests on:
// the DROP is appended first and every accept goes in above it, so no accept
// is ever ordered after the DROP.
func TestTheTerminalDropIsLast(t *testing.T) {
	t.Parallel()
	program, err := valid().Program(netsetup.FamilyIPv4)
	require.NoError(t, err, "build the ruleset")
	var filter []netsetup.Step
	for _, step := range program.Steps {
		if step.Table == "filter" && strings.HasPrefix(step.Chain, "EGRESS_PROXY_") {
			filter = append(filter, step)
		}
	}
	require.NotEmpty(t, filter, "the filter chain holds rules")
	assert.Equal(t, []string{"-j", "DROP"}, filter[0].Spec, "the DROP is the first rule installed")
	assert.Zero(t, filter[0].At, "the DROP is appended, not inserted")
	for i, step := range filter[1:] {
		assert.Equal(t, i+1, step.At, "accept %d is inserted above the DROP at position %d", i, i+1)
	}
}

// TestTheDryRunPrintsTheOrderTheRunPerforms proves --dry-run shows the seal
// going in before any other chain is flushed, so a manifest review reads the
// order the tables are changed in rather than a listing by chain.
func TestTheDryRunPrintsTheOrderTheRunPerforms(t *testing.T) {
	t.Parallel()
	program, err := valid().Program(netsetup.FamilyIPv4)
	require.NoError(t, err, "build the ruleset")
	rendered := program.String()
	drop := strings.Index(rendered, "-t filter -A EGRESS_PROXY_FILTER_OUTPUT -j DROP")
	natFlush := strings.Index(rendered, "-t nat -F EGRESS_PROXY_NAT_OUTPUT")
	require.Positive(t, drop, "the terminal DROP is printed")
	require.Positive(t, natFlush, "the nat chain flush is printed")
	assert.Less(t, drop, natFlush, "the filter chain is sealed before any other chain is touched")
}

// TestProgramCountsItsOwnChains pins what Verify compares the tables
// against. A chain that holds more rules than the program installs holds a
// rule this ruleset did not put there.
func TestProgramCountsItsOwnChains(t *testing.T) {
	t.Parallel()
	program, err := valid().Program(netsetup.FamilyIPv4)
	require.NoError(t, err, "build the ruleset")
	counted := 0
	for _, chain := range program.Chains {
		assert.Positive(t, chain.Rules, "the %s chain holds rules", chain.Name)
		counted += chain.Rules
	}
	// Everything the program installs goes in an owned chain except the two
	// OUTPUT jumps, which attach them.
	assert.Equal(t, len(program.Steps)-2, counted, "every step but the two jumps goes in an owned chain")
}

// TestRulesetDigestCoversTheRules proves two rulesets that differ are
// identified apart, so a sidecar comparing digests compares what is in the
// tables.
func TestRulesetDigestCoversTheRules(t *testing.T) {
	t.Parallel()
	base := valid()
	other := valid()
	other.RedirectPort = 1016
	first, err := base.Program(netsetup.FamilyIPv4)
	require.NoError(t, err)
	same, err := base.Program(netsetup.FamilyIPv4)
	require.NoError(t, err)
	changed, err := other.Program(netsetup.FamilyIPv4)
	require.NoError(t, err)
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
