package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
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
				"-A EGRESS_PROXY_NAT_OUTPUT -m owner --uid-owner 1337 -j RETURN",
				"-A EGRESS_PROXY_NAT_OUTPUT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 1015",
				"-A EGRESS_PROXY_FILTER_OUTPUT -d 10.43.0.10 -p udp --dport 53 -j ACCEPT",
			},
		},
		{
			name: "another uid, redirect port and capture port set",
			args: []string{"--proxy-uid", "2000", "--redirect-port", "1016", "--capture-ports", "443,8443"},
			want: []string{
				"-A EGRESS_PROXY_NAT_OUTPUT -m owner --uid-owner 2000 -j RETURN",
				"-A EGRESS_PROXY_NAT_OUTPUT -p tcp -m multiport --dports 443,8443 " +
					"-j REDIRECT --to-ports 1016",
			},
		},
		{
			name: "cluster ranges, which are returned from the nat chain and still covered by the DROP",
			args: []string{"--pod-cidrs", "10.42.0.0/16", "--service-cidrs", "10.43.0.0/16"},
			want: []string{
				"-A EGRESS_PROXY_NAT_OUTPUT -d 10.42.0.0/16 -j RETURN",
				"-A EGRESS_PROXY_NAT_OUTPUT -d 10.43.0.0/16 -j RETURN",
			},
		},
		{
			name: "resolvers named explicitly, which are not read from resolv.conf",
			args: []string{"--dns-servers", "10.96.0.10"},
			want: []string{"-A EGRESS_PROXY_FILTER_OUTPUT -d 10.96.0.10 -p udp --dport 53 -j ACCEPT"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			receipt := filepath.Join(t.TempDir(), "netsetup.json")
			args := append(dryRunArgs(resolv), append(tc.args, "--receipt", receipt)...)
			require.NoError(t, command(&out, nil).Run(context.Background(), args), "the dry run")
			for _, want := range tc.want {
				assert.Contains(t, out.String(), want, "the printed ruleset")
			}
			_, err := os.Stat(receipt)
			require.ErrorIs(t, err, os.ErrNotExist, "a dry run writes no receipt")
		})
	}
}

// TestIPv6Modes drives every --ipv6 mode against each answer the kernel
// probe can give. The probe is a stub, so every row runs on every host.
func TestIPv6Modes(t *testing.T) {
	t.Parallel()
	has := func() (bool, error) { return true, nil }
	hasNot := func() (bool, error) { return false, nil }
	fails := func() (bool, error) { return false, errProbe }
	tests := []struct {
		name  string
		mode  string
		probe ipv6Probe
		// wantIPv6 is what the ip6tables ruleset does: "proxy", "deny", or
		// "" for none printed.
		wantIPv6 string
		wantOut  string
		wantErr  string
	}{
		{name: "auto on a kernel with IPv6", mode: "auto", probe: has, wantIPv6: "proxy"},
		{
			name: "auto on a kernel without IPv6", mode: "auto", probe: hasNot,
			wantOut: "this kernel has no IPv6, so no ip6tables ruleset is programmed",
		},
		{name: "on with IPv6", mode: "on", probe: has, wantIPv6: "proxy"},
		{
			name: "on without IPv6, which refuses rather than leave the mode unmet", mode: "on", probe: hasNot,
			wantErr: "on was asked for and this kernel has no IPv6",
		},
		{
			name: "off with IPv6, which programs a ruleset that drops what the pod sends", mode: "off", probe: has,
			wantIPv6: "deny", wantOut: "every IPv6 packet this pod sends is dropped",
		},
		{
			name: "off without IPv6", mode: "off", probe: hasNot,
			wantOut: "this kernel has no IPv6, so no ip6tables ruleset is programmed",
		},
		{
			name: "auto when the probe cannot tell", mode: "auto", probe: fails,
			wantErr: "Name --ipv6 on or --ipv6 off rather than auto",
		},
		{
			name: "off when the probe cannot tell, which still refuses", mode: "off", probe: fails,
			wantErr: "permission denied",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := settings{
				proxyUID: 1337, redirectPort: 1015, capturePorts: []string{"80,443"},
				dnsServers: []string{"10.43.0.10", "fd00::a"}, ipv6: tc.mode,
			}
			var out bytes.Buffer
			cfg, err := opts.config(&out, tc.probe)
			if tc.wantErr != "" {
				require.Error(t, err, "the configuration is refused")
				assert.Contains(t, err.Error(), tc.wantErr, "the refusal says why")
				return
			}
			require.NoError(t, err, "build the configuration")
			require.NoError(t, dryRun(cfg, &out), "the dry run")
			printed := out.String()
			if tc.wantOut != "" {
				assert.Contains(t, printed, tc.wantOut, "the run says what it chose")
			}
			assert.Contains(t, printed, "# ipv4 ruleset", "the IPv4 ruleset is always printed")
			start := strings.Index(printed, "# ipv6 ruleset")
			switch tc.wantIPv6 {
			case "":
				assert.Negative(t, start, "no ip6tables ruleset is printed")
			case "proxy":
				require.GreaterOrEqual(t, start, 0, "an ip6tables ruleset is printed")
				assert.Contains(t, printed[start:], "-j REDIRECT --to-ports 1015", "IPv6 TCP is redirected")
				assert.Contains(t, printed[start:], "-d fd00::a -p udp --dport 53 -j ACCEPT", "the IPv6 resolver is accepted")
				assert.NotContains(t, printed, "every IPv6 packet this pod sends is dropped", "IPv6 is not denied")
			case "deny":
				require.GreaterOrEqual(t, start, 0, "an ip6tables ruleset is printed")
				for _, absent := range []string{"REDIRECT", "fd00::a", "--dport 53", "--uid-owner 1337"} {
					assert.NotContains(t, printed[start:], absent, "the denied family redirects nothing and accepts no egress")
				}
				assert.Contains(t, printed[start:], "-A EGRESS_PROXY_FILTER_OUTPUT -j DROP", "the family is dropped")
			}
		})
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
		{name: "root as the proxy uid", args: []string{"--proxy-uid", "0"}, want: "proxy uid 0 is root"},
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
			assert.NotContains(t, out.String(), "-A EGRESS_PROXY_", "nothing is printed for a refused run")
		})
	}
}

// appliedTables answers every read the way the tables read back once this
// ruleset was applied, so netsetup.Verify passes against it. It records
// every Restore, which is what proves a --verify run changed nothing.
type appliedTables struct {
	rules  map[string][]string
	writes []string
	// fail makes a Restore whose input contains it return errWrite.
	fail string
}

var (
	errWrite = errors.New("iptables-restore: line refused")
	errOpen  = errors.New("no iptables binary with the legacy backend")
	errProbe = errors.New("read /proc/net/if_inet6: permission denied")
)

func chainKey(table, chain string) string { return table + " " + chain }

// tablesHolding renders what one family's tables hold once its program is
// applied.
func tablesHolding(program netsetup.Program) *appliedTables {
	rules := make(map[string][]string)
	for _, rule := range slices.Concat(program.Rules(), program.Jumps) {
		at := chainKey(rule.Table, rule.Chain)
		rules[at] = append(rules[at], "-A "+rule.Chain+" "+strings.Join(rule.Spec, " "))
	}
	return &appliedTables{rules: rules}
}

// familyTables holds each family's tables apart, as iptables and ip6tables
// do. A family it does not name gets empty tables.
type familyTables map[netsetup.Family]*appliedTables

// open is an opener that hands out each family's own tables.
//
//nolint:ireturn // it stands in for the opener, which returns the interface
func (f familyTables) open(
	_ context.Context, family netsetup.Family, _ string,
) (netsetup.Tables, netsetup.Tool, error) {
	tables, ok := f[family]
	if !ok {
		tables = &appliedTables{rules: map[string][]string{}}
		f[family] = tables
	}
	return tables, netsetup.Tool{Path: "/sbin/iptables", Version: "v1.8.9 (legacy)"}, nil
}

// writes lists every Restore input across the families.
func (f familyTables) writes() []string {
	var out []string
	for _, tables := range f {
		out = append(out, tables.writes...)
	}
	return out
}

func (f *appliedTables) ChainExists(table, chain string) (bool, error) {
	_, ok := f.rules[chainKey(table, chain)]
	return ok, nil
}

func (f *appliedTables) Exists(table, chain string, spec ...string) (bool, error) {
	return slices.Contains(f.rules[chainKey(table, chain)], "-A "+chain+" "+strings.Join(spec, " ")), nil
}

func (f *appliedTables) List(table, chain string) ([]string, error) {
	return append([]string{"-N " + chain}, f.rules[chainKey(table, chain)]...), nil
}

func (f *appliedTables) Restore(_ context.Context, input string) error {
	f.writes = append(f.writes, input)
	if f.fail != "" && strings.Contains(input, f.fail) {
		return errWrite
	}
	return nil
}

// verifyFixture is a --verify command line and tables that hold exactly the
// ruleset it describes. Verify passes, so what the run wrote is all that is
// left to assert.
func verifyFixture(t *testing.T, receipt string) ([]string, familyTables) {
	t.Helper()
	opts := settings{
		proxyUID:     1337,
		redirectPort: 1015,
		capturePorts: []string{"80,443"},
		dnsServers:   []string{"10.43.0.10"},
		ipv6:         "off",
	}
	var sink bytes.Buffer
	cfg, err := opts.config(&sink, netsetup.KernelHasIPv6)
	require.NoError(t, err, "build the configuration the command line describes")
	tables := make(familyTables, len(cfg.Families()))
	for _, family := range cfg.Families() {
		built, err := cfg.Program(family)
		require.NoError(t, err, "build the %s ruleset", family)
		tables[family] = tablesHolding(built)
	}
	args := []string{
		"egress-netsetup", "--verify",
		"--proxy-uid", "1337", "--redirect-port", "1015", "--capture-ports", "80,443",
		"--dns-servers", "10.43.0.10", "--ipv6", "off", "--receipt", receipt,
	}
	return args, tables
}

// keptCapabilityReceipt is what the init container writes when it was given
// --keep-net-admin: the rules are in force and the process that programmed
// them can still change them.
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
// The second row pins the case a written receipt would hide: an init
// container that kept CAP_NET_ADMIN leaves a receipt that says so, and a
// later --verify must not replace it with one that says the capability went.
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
			require.NoError(t, command(&out, tables.open).Run(context.Background(), args), "the verify run")

			assert.Empty(t, tables.writes(), "--verify changes no rule")
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

// TestKeepNetAdminIsRecorded proves a run given --keep-net-admin writes a
// receipt that says the capability was kept. The drop itself needs
// CAP_NET_ADMIN, so netsetup_ruleset.txtar covers it.
func TestKeepNetAdminIsRecorded(t *testing.T) {
	t.Parallel()
	receipt := filepath.Join(t.TempDir(), "netsetup.json")
	_, tables := verifyFixture(t, receipt)
	args := []string{
		"egress-netsetup", "--keep-net-admin",
		"--dns-servers", "10.43.0.10", "--ipv6", "off", "--receipt", receipt,
	}
	var out bytes.Buffer
	require.NoError(t, command(&out, tables.open).Run(context.Background(), args), "the run")

	body, err := os.ReadFile(receipt)
	require.NoError(t, err, "the run writes a receipt")
	var got netsetup.Receipt
	require.NoError(t, json.Unmarshal(body, &got), "the receipt parses")
	assert.True(t, got.Verified, "the rules read back")
	assert.False(t, got.CapabilitiesDropped, "the receipt says CAP_NET_ADMIN was kept")
	assert.Contains(t, out.String(), "CAP_NET_ADMIN is still held", "the run says it kept the capability")
}

// TestAFailedRunLeavesNoReceipt starts each run with a receipt an earlier
// run left, then makes the run fail. The stale receipt says the rules are in
// force, so every failure must leave no receipt. The last row makes the
// unlink itself fail, which stops the run before any table is opened.
func TestAFailedRunLeavesNoReceipt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// openErr fails the open. Otherwise the run gets tables.
		openErr error
		// tables is what the run applies to and reads back.
		tables func(t *testing.T, receipt string) familyTables
		// receiptIsDir puts a non-empty directory at the receipt path, which
		// os.Remove cannot unlink.
		receiptIsDir bool
		// noResolvers names no --dns-servers and a resolv.conf that is not
		// there, so the configuration fails before any table is opened.
		noResolvers bool
		want        []string
	}{
		{
			name:    "the iptables binary cannot be opened",
			openErr: errOpen,
			want:    []string{"no iptables binary with the legacy backend"},
		},
		{
			name: "the ruleset cannot be loaded",
			tables: func(t *testing.T, receipt string) familyTables {
				t.Helper()
				_, tables := verifyFixture(t, receipt)
				tables[netsetup.FamilyIPv4].fail = "-j REDIRECT"
				return tables
			},
			want: []string{"load the ipv4 ruleset", "iptables-restore: line refused"},
		},
		{
			name:   "the tables do not read back as the ruleset",
			tables: func(*testing.T, string) familyTables { return familyTables{} },
			want:   []string{"the ruleset is not in force", "not in the tables"},
		},
		{
			name:        "the configuration cannot be built",
			tables:      untouched,
			noResolvers: true,
			want:        []string{"Name the resolvers with --dns-servers"},
		},
		{
			name:         "the stale receipt cannot be removed, which stops the run before any table is opened",
			tables:       untouched,
			receiptIsDir: true,
			want:         []string{"remove the stale netsetup receipt"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			receipt := filepath.Join(t.TempDir(), "netsetup.json")
			if tc.receiptIsDir {
				require.NoError(t, os.MkdirAll(filepath.Join(receipt, "entry"), 0o755)) //nolint:gosec // G301: a fixture
			} else {
				require.NoError(t, os.WriteFile(receipt, []byte(keptCapabilityReceipt), 0o644), "an earlier run's receipt")
			}
			open := func(ctx context.Context, family netsetup.Family, override string) (netsetup.Tables, netsetup.Tool, error) {
				if tc.openErr != nil {
					return nil, netsetup.Tool{}, tc.openErr
				}
				return tc.tables(t, receipt).open(ctx, family, override)
			}
			resolvers := []string{"--dns-servers", "10.43.0.10"}
			if tc.noResolvers {
				resolvers = []string{"--resolv-conf", filepath.Join(t.TempDir(), "missing")}
			}
			args := append([]string{"egress-netsetup", "--keep-net-admin", "--ipv6", "off", "--receipt", receipt},
				resolvers...)
			var out bytes.Buffer
			err := command(&out, open).Run(context.Background(), args)

			require.Error(t, err, "the run fails")
			for _, want := range tc.want {
				assert.Contains(t, err.Error(), want, "the error names this failure")
			}
			if tc.receiptIsDir {
				return
			}
			_, err = os.Stat(receipt)
			require.ErrorIs(t, err, os.ErrNotExist, "the earlier run's receipt is gone")
		})
	}
}

// untouched fails the test if the run opens any table.
func untouched(t *testing.T, _ string) familyTables {
	t.Helper()
	t.Error("the run opened a table")
	return familyTables{}
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
