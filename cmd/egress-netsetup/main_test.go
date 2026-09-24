package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
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
			err := command(&out, nil).Run(context.Background(), append(dryRunArgs(resolv), tc.args...))
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
	require.NoError(t, command(&out, nil).Run(context.Background(), args), "the IPv4 dry run")
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
	require.NoError(t, command(&out, nil).Run(context.Background(), args), "the dry run for both families")
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
			err := command(&out, nil).Run(context.Background(), append(dryRunArgs(resolv), tc.args...))
			require.Error(t, err, "the command refuses")
			assert.Contains(t, err.Error(), tc.want, "the refusal says why")
			assert.NotContains(t, out.String(), "-t nat -A", "nothing is printed for a refused run")
		})
	}
}

// appliedTables answers every read the way the tables read back once this
// ruleset was applied, so netsetup.Verify passes against it. It records
// every call that would change the tables, which is what proves a --verify
// run changed none.
type appliedTables struct {
	rules  map[string][]string
	writes []string
}

func chainKey(table, chain string) string { return table + " " + chain }

// tablesHolding renders what the tables hold once the programs are applied.
// An insert at position n lands at index n-1, which is how the accepts end
// up above the DROP that was appended first.
func tablesHolding(programs ...netsetup.Program) *appliedTables {
	rules := make(map[string][]string)
	for _, program := range programs {
		for _, step := range program.Steps {
			at := chainKey(step.Table, step.Chain)
			rule := "-A " + step.Chain + " " + strings.Join(step.Spec, " ")
			if step.At > 0 {
				rules[at] = slices.Insert(rules[at], step.At-1, rule)
				continue
			}
			rules[at] = append(rules[at], rule)
		}
	}
	return &appliedTables{rules: rules}
}

func (f *appliedTables) ClearChain(table, chain string) error {
	f.writes = append(f.writes, "-t "+table+" -F "+chain)
	return nil
}

func (f *appliedTables) Append(table, chain string, spec ...string) error {
	f.writes = append(f.writes, "-t "+table+" -A "+chain+" "+strings.Join(spec, " "))
	return nil
}

func (f *appliedTables) AppendUnique(table, chain string, spec ...string) error {
	return f.Append(table, chain, spec...)
}

func (f *appliedTables) Insert(table, chain string, pos int, spec ...string) error {
	f.writes = append(f.writes, "-t "+table+" -I "+chain+" "+strconv.Itoa(pos)+" "+strings.Join(spec, " "))
	return nil
}

func (f *appliedTables) Exists(table, chain string, spec ...string) (bool, error) {
	return slices.Contains(f.rules[chainKey(table, chain)], "-A "+chain+" "+strings.Join(spec, " ")), nil
}

func (f *appliedTables) List(table, chain string) ([]string, error) {
	return append([]string{"-N " + chain}, f.rules[chainKey(table, chain)]...), nil
}

// verifyFixture is a --verify command line and tables that hold exactly the
// ruleset it describes. Verify passes, so what the run wrote is all that is
// left to assert.
func verifyFixture(t *testing.T, receipt string) ([]string, *appliedTables) {
	t.Helper()
	opts := settings{
		proxyUID:     1337,
		redirectPort: 1015,
		capturePorts: []string{"80,443"},
		dnsServers:   []string{"10.43.0.10"},
		ipv6:         "off",
	}
	var sink bytes.Buffer
	cfg, err := opts.config(&sink)
	require.NoError(t, err, "build the configuration the command line describes")
	programs := make([]netsetup.Program, 0, len(cfg.Families()))
	for _, family := range cfg.Families() {
		built, err := cfg.Program(family)
		require.NoError(t, err, "build the %s ruleset", family)
		programs = append(programs, built)
	}
	args := []string{
		"egress-netsetup", "--verify",
		"--proxy-uid", "1337", "--redirect-port", "1015", "--capture-ports", "80,443",
		"--dns-servers", "10.43.0.10", "--ipv6", "off", "--receipt", receipt,
	}
	return args, tablesHolding(programs...)
}

// keptCapabilityReceipt is what the init container writes when it was given
// --keep-net-admin: the rules are in force and the process that programmed
// them can still change them, so the sidecar refuses it.
const keptCapabilityReceipt = `{
  "version": 1,
  "verified_at": "2026-01-02T03:04:05Z",
  "verified": true,
  "proxy_uid": 1337,
  "redirect_port": 1015,
  "capture_ports": [80, 443],
  "families": ["ipv4"],
  "ruleset_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "capabilities_dropped": false
}
`

// TestVerifyWritesNothing proves --verify is read-only. It reads the tables
// back and reports, and it never mints the evidence of containment that only
// a run which programmed the rules may write.
//
// The receipt is the sidecar's sole check on its own containment. A --verify
// run that wrote one would launder the case this test's second row pins: an
// init container that kept CAP_NET_ADMIN leaves a receipt the sidecar
// refuses, and a later --verify must not replace it with one that says the
// capability went.
func TestVerifyWritesNothing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// before is the receipt already on disk, empty for none.
		before string
	}{
		{name: "no receipt is there to begin with", before: ""},
		{name: "a receipt says the init container kept CAP_NET_ADMIN", before: keptCapabilityReceipt},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			receipt := filepath.Join(t.TempDir(), "netsetup.json")
			if tc.before != "" {
				require.NoError(t, os.WriteFile(receipt, []byte(tc.before), 0o644), "the receipt already on disk")
			}
			args, tables := verifyFixture(t, receipt)
			var out bytes.Buffer
			open := func(context.Context, netsetup.Family, string) (netsetup.Tables, netsetup.Tool, error) {
				return tables, netsetup.Tool{Path: "/sbin/iptables", Version: "v1.8.9 (legacy)"}, nil
			}
			require.NoError(t, command(&out, open).Run(context.Background(), args), "the verify run")

			assert.Empty(t, tables.writes, "--verify changes no rule")
			assert.Contains(t, out.String(), "Nothing was written", "the run says it wrote nothing")
			body, err := os.ReadFile(receipt)
			if tc.before == "" {
				require.ErrorIs(t, err, os.ErrNotExist, "--verify writes no receipt where there was none")
				return
			}
			require.NoError(t, err, "the receipt is still there")
			assert.Equal(t, tc.before, string(body), "--verify leaves the receipt byte for byte as it found it")
		})
	}
}

// TestVerifyRefusesFlagsItWouldIgnore proves the command line refuses a
// combination that asks for two different runs, rather than silently
// honouring one of them.
func TestVerifyRefusesFlagsItWouldIgnore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "--dry-run and --verify together",
			args: []string{"--dry-run", "--verify"},
			want: "--dry-run prints the ruleset and --verify reads the tables back",
		},
		{
			name: "--keep-net-admin with a run that drops nothing",
			args: []string{"--verify", "--keep-net-admin"},
			want: "--verify drops no capability",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			args := append([]string{"egress-netsetup", "--ipv6", "off", "--dns-servers", "10.43.0.10"}, tc.args...)
			open := func(context.Context, netsetup.Family, string) (netsetup.Tables, netsetup.Tool, error) {
				t.Error("a refused command line opens no iptables handle")
				return nil, netsetup.Tool{}, nil
			}
			err := command(&out, open).Run(context.Background(), args)
			require.Error(t, err, "the command refuses")
			assert.Contains(t, err.Error(), tc.want, "the refusal says why")
		})
	}
}
