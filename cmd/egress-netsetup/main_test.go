package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// resolvConf writes a resolv.conf the command reads its resolvers from.
func resolvConf(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolv.conf")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// dryRunArgs is the command line every case starts from: the rules are
// printed and nothing touches the tables, so the test needs no capability.
func dryRunArgs(resolv string) []string {
	return []string{"egress-netsetup", "--dry-run", "--ipv6", "off", "--resolv-conf", resolv}
}

// TestDryRunPrintsTheRuleset proves the command turns its flags into the
// ruleset it would apply, and that it applies nothing while it does.
func TestDryRunPrintsTheRuleset(t *testing.T) {
	t.Parallel()
	resolv := resolvConf(t, "nameserver 10.43.0.10\n")
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "the defaults, with the resolvers read from resolv.conf",
			args: nil,
			want: []string{
				"# resolvers from " + resolv + ": 10.43.0.10",
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -m owner --uid-owner 1337 -j RETURN",
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 1015",
				"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 5 -d 10.43.0.10 -p udp --dport 53 -j ACCEPT",
			},
		},
		{
			name: "another uid, redirect port and capture port set",
			args: []string{"--proxy-uid", "2000", "--redirect-port", "1016", "--capture-ports", "443,8443"},
			want: []string{
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -m owner --uid-owner 2000 -j RETURN",
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -p tcp -m multiport --dports 443,8443 " +
					"-j REDIRECT --to-ports 1016",
			},
		},
		{
			name: "cluster ranges, which are returned from the nat chain and still covered by the DROP",
			args: []string{"--pod-cidrs", "10.42.0.0/16", "--service-cidrs", "10.43.0.0/16"},
			want: []string{
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -d 10.42.0.0/16 -j RETURN",
				"-t nat -A EGRESS_PROXY_NAT_OUTPUT -d 10.43.0.0/16 -j RETURN",
			},
		},
		{
			name: "resolvers named explicitly, which are not read from resolv.conf",
			args: []string{"--dns-servers", "10.96.0.10"},
			want: []string{"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 5 -d 10.96.0.10 -p udp --dport 53 -j ACCEPT"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := command(&out).Run(context.Background(), append(dryRunArgs(resolv), tc.args...))
			require.NoError(t, err, "the dry run")
			for _, want := range tc.want {
				assert.Contains(t, out.String(), want, "the printed ruleset")
			}
			assert.NotContains(t, out.String(), "receipt", "a dry run writes no receipt")
		})
	}
}

// TestIPv6OffPrintsOneFamilyAndSaysSo proves --ipv6 off renders the iptables
// ruleset alone and announces what it gives up. A kernel with IPv6 that this
// ruleset does not program is a pod that reaches any IPv6 destination on any
// port, so the run says so rather than leaving it to be noticed.
func TestIPv6OffPrintsOneFamilyAndSaysSo(t *testing.T) {
	t.Parallel()
	resolv := resolvConf(t, "nameserver 10.43.0.10\nnameserver fd00::a\n")
	var out bytes.Buffer
	args := []string{"egress-netsetup", "--dry-run", "--resolv-conf", resolv, "--ipv6", "off"}
	require.NoError(t, command(&out).Run(context.Background(), args), "the IPv4 dry run")
	assert.Contains(t, out.String(), "# ipv4 ruleset", "the IPv4 ruleset is printed")
	assert.NotContains(t, out.String(), "# ipv6 ruleset", "--ipv6 off leaves IPv6 out")
	assert.Contains(t, out.String(), "IPv6 is left ungoverned", "--ipv6 off says what it gives up")
}

// TestBothFamiliesArePrinted proves --ipv6 on renders the ip6tables ruleset
// alongside the iptables one, each holding only its own family's resolver.
// --ipv6 on requires a kernel with IPv6, which is what the skip reads.
func TestBothFamiliesArePrinted(t *testing.T) {
	t.Parallel()
	if !netsetup.KernelHasIPv6() {
		t.Skip("--ipv6 on refuses a kernel with no IPv6")
	}
	resolv := resolvConf(t, "nameserver 10.43.0.10\nnameserver fd00::a\n")
	var out bytes.Buffer
	args := []string{"egress-netsetup", "--dry-run", "--resolv-conf", resolv, "--ipv6", "on"}
	require.NoError(t, command(&out).Run(context.Background(), args), "the dry run for both families")
	for _, want := range []string{
		"# ipv4 ruleset",
		"# ipv6 ruleset",
		"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 5 -d 10.43.0.10 -p udp --dport 53 -j ACCEPT",
		"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 13 -d fd00::a -p udp --dport 53 -j ACCEPT",
		"-t filter -I EGRESS_PROXY_FILTER_OUTPUT 5 -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j ACCEPT",
	} {
		assert.Contains(t, out.String(), want, "the printed ruleset")
	}
}

func TestCommandRefusals(t *testing.T) {
	t.Parallel()
	resolv := resolvConf(t, "nameserver 10.43.0.10\n")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "a capture port that is not a number", args: []string{"--capture-ports", "http"}, want: "not a port"},
		{
			name: "a pod CIDR that is not a prefix",
			args: []string{"--pod-cidrs", "10.42.0.0"}, want: "not a CIDR prefix",
		},
		{name: "a resolver that is not an address", args: []string{"--dns-servers", "dns"}, want: "not an address"},
		{name: "an --ipv6 mode that is not one", args: []string{"--ipv6", "maybe"}, want: "not auto, on or off"},
		{
			name: "a redirect port among the capture ports",
			args: []string{"--capture-ports", "80,1015"}, want: "is the redirect port",
		},
		{name: "an argument the command takes none of", args: []string{"extra"}, want: `unexpected argument "extra"`},
		{
			name: "a resolv.conf that is not there",
			args: []string{"--resolv-conf", filepath.Join(t.TempDir(), "missing")},
			want: "Name the resolvers with --dns-servers",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := command(&out).Run(context.Background(), append(dryRunArgs(resolv), tc.args...))
			require.Error(t, err, "the command refuses")
			assert.Contains(t, err.Error(), tc.want, "the refusal says why")
			assert.NotContains(t, out.String(), "-t nat -A", "nothing is printed for a refused run")
		})
	}
}
