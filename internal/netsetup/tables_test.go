package netsetup_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// fakeTables stands in for a Handle. Restore follows iptables-restore
// --noflush: declaring a chain flushes it, and each table's changes reach
// the chain listing only at its COMMIT line. Every read answers from that
// listing, so a test drives Verify against tables that hold whatever the
// case or an earlier Apply put there.
type fakeTables struct {
	// writes records every Restore input, in order.
	writes []string
	// rules is what List answers, keyed by table and chain, in the order
	// iptables -S prints them.
	rules map[string][]string
	// listErr is returned by List for the chain it names, keyed the same
	// way. chainErr is returned by ChainExists.
	listErr  map[string]error
	chainErr error
	// fail makes Restore stop at the first input line that contains it and
	// return errWrite. Tables committed before that line keep the change.
	fail string
}

var errWrite = errors.New("iptables-restore: line refused")

func key(table, chain string) string { return table + " " + chain }

func rule(chain string, spec []string) string { return "-A " + chain + " " + strings.Join(spec, " ") }

func (f *fakeTables) ChainExists(table, chain string) (bool, error) {
	if f.chainErr != nil {
		return false, f.chainErr
	}
	_, ok := f.rules[key(table, chain)]
	return ok, nil
}

func (f *fakeTables) Exists(table, chain string, spec ...string) (bool, error) {
	return slices.Contains(f.rules[key(table, chain)], rule(chain, spec)), nil
}

func (f *fakeTables) List(table, chain string) ([]string, error) {
	if err := f.listErr[key(table, chain)]; err != nil {
		return nil, err
	}
	return append([]string{"-N " + chain}, f.rules[key(table, chain)]...), nil
}

func (f *fakeTables) Restore(_ context.Context, input string) error {
	f.writes = append(f.writes, input)
	var table string
	var staged map[string][]string
	for line := range strings.Lines(input) {
		line = strings.TrimSpace(line)
		if f.fail != "" && strings.Contains(line, f.fail) {
			return errWrite
		}
		fields := strings.Fields(line)
		switch {
		case strings.HasPrefix(line, "*"):
			table, staged = line[1:], make(map[string][]string)
			for k, rules := range f.rules {
				if strings.HasPrefix(k, table+" ") {
					staged[k] = slices.Clone(rules)
				}
			}
		case strings.HasPrefix(line, ":"):
			staged[key(table, fields[0][1:])] = []string{}
		case fields[0] == "-A":
			staged[key(table, fields[1])] = append(staged[key(table, fields[1])], rule(fields[1], fields[2:]))
		case fields[0] == "-I" && fields[2] == "1":
			staged[key(table, fields[1])] = slices.Insert(staged[key(table, fields[1])], 0, rule(fields[1], fields[3:]))
		case line == "COMMIT":
			for k, rules := range staged {
				f.set(k, rules)
			}
		default:
			return fmt.Errorf("the fake does not read %q", line) //nolint:err113 // a test fixture
		}
	}
	return nil
}

func (f *fakeTables) set(k string, rules []string) {
	if f.rules == nil {
		f.rules = make(map[string][]string)
	}
	f.rules[k] = rules
}

// listing renders what the tables hold once a program has been applied to
// empty OUTPUT chains.
func listing(program netsetup.Program) map[string][]string {
	out := make(map[string][]string, len(program.Chains)+2)
	for _, r := range program.Rules() {
		out[key(r.Table, r.Chain)] = append(out[key(r.Table, r.Chain)], rule(r.Chain, r.Spec))
	}
	for _, jump := range program.Jumps {
		out[key(jump.Table, jump.Chain)] = []string{rule(jump.Chain, jump.Spec)}
	}
	return out
}

func programFor(t *testing.T) netsetup.Program {
	t.Helper()
	program, err := valid().Program(netsetup.FamilyIPv4)
	require.NoError(t, err, "build the ruleset")
	return program
}

const (
	filterKey  = "filter EGRESS_PROXY_FILTER_OUTPUT"
	natKey     = "nat EGRESS_PROXY_NAT_OUTPUT"
	filterJump = "-A OUTPUT -j EGRESS_PROXY_FILTER_OUTPUT"
	natJump    = "-A OUTPUT -p tcp -j EGRESS_PROXY_NAT_OUTPUT"
	drop       = "-A EGRESS_PROXY_FILTER_OUTPUT -j DROP"
	// Rules of the kind Docker's embedded resolver puts in a container's
	// OUTPUT chains.
	filterOther = "-A OUTPUT -d 127.0.0.11/32 -j ACCEPT"
	natOther    = "-A OUTPUT -d 127.0.0.11/32 -j DOCKER_OUTPUT"
	// A rule an earlier ruleset left in an owned chain.
	stale = "-A EGRESS_PROXY_FILTER_OUTPUT -p udp -j ACCEPT"
)

// TestApply drives Apply against tables in each state a run starts from,
// and against a Restore that refuses a line. Apply writes the tables with
// one Restore and nothing else, so no state between two writes is ever
// visible. Where the load fails, the case pins what each table holds after.
func TestApply(t *testing.T) {
	t.Parallel()
	program := programFor(t)
	applied := listing(program)
	tests := []struct {
		name string
		// before is what the tables hold when Apply starts.
		before map[string][]string
		// fail is the input line Restore refuses. Empty loads everything.
		fail string
		// wantJumps are the OUTPUT jumps the input inserts.
		wantJumps []string
		// want is what the tables hold after, for the keys it names.
		want map[string][]string
	}{
		{
			name:      "a first run on empty OUTPUT chains",
			wantJumps: []string{filterJump, natJump},
			want:      applied,
		},
		{
			name:      "OUTPUT chains that hold rules the rest of the system put there",
			before:    map[string][]string{"filter OUTPUT": {filterOther}, "nat OUTPUT": {natOther}},
			wantJumps: []string{filterJump, natJump},
			want: map[string][]string{
				"filter OUTPUT": {filterJump, filterOther},
				"nat OUTPUT":    {natJump, natOther},
				filterKey:       applied[filterKey],
				natKey:          applied[natKey],
			},
		},
		{
			name: "a re-run over an earlier ruleset, whose jumps stay and whose chain rules are replaced",
			before: map[string][]string{
				"filter OUTPUT": {filterJump, filterOther},
				"nat OUTPUT":    {natJump},
				filterKey:       {stale, drop},
				natKey:          {"-A EGRESS_PROXY_NAT_OUTPUT -j RETURN"},
			},
			want: map[string][]string{
				"filter OUTPUT": {filterJump, filterOther},
				"nat OUTPUT":    {natJump},
				filterKey:       applied[filterKey],
				natKey:          applied[natKey],
			},
		},
		{
			name: "a re-run whose filter table fails to load, which keeps the earlier filter chain whole",
			before: map[string][]string{
				"filter OUTPUT": {filterJump},
				"nat OUTPUT":    {natJump},
				filterKey:       {stale, drop},
				natKey:          {"-A EGRESS_PROXY_NAT_OUTPUT -j RETURN"},
			},
			fail: "--uid-owner 1337 -j ACCEPT",
			want: map[string][]string{
				"filter OUTPUT": {filterJump},
				filterKey:       {stale, drop},
				natKey:          {"-A EGRESS_PROXY_NAT_OUTPUT -j RETURN"},
			},
		},
		{
			name:      "a first run whose nat table fails to load, which leaves the filter table in force",
			fail:      "-j REDIRECT",
			wantJumps: []string{filterJump, natJump},
			want: map[string][]string{
				"filter OUTPUT": {filterJump},
				filterKey:       applied[filterKey],
				"nat OUTPUT":    nil,
				natKey:          nil,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			handle := &fakeTables{fail: tc.fail}
			for k, rules := range tc.before {
				handle.set(k, slices.Clone(rules))
			}
			var progress strings.Builder
			err := netsetup.Apply(context.Background(), handle, program, &progress)

			if tc.fail == "" {
				require.NoError(t, err, "apply the ruleset")
			} else {
				require.ErrorIs(t, err, errWrite, "the load error reaches the caller")
				assert.Contains(t, err.Error(), "load the ipv4 ruleset", "the error names the family")
			}
			require.Len(t, handle.writes, 1, "Apply writes the tables with one Restore")
			assert.Equal(t, handle.writes[0], progress.String(), "the progress is the input Restore loads")
			var jumps []string
			for line := range strings.Lines(handle.writes[0]) {
				if fields := strings.Fields(line); fields[0] == "-I" {
					jumps = append(jumps, rule(fields[1], fields[3:]))
				}
			}
			assert.Equal(t, tc.wantJumps, jumps, "the jumps the input inserts")
			for k, want := range tc.want {
				assert.Equal(t, want, handle.rules[k], "the %s chain", k)
			}
		})
	}
}

// TestApplyWritesNothingWhenItCannotReadTheJumps proves Apply stops before
// Restore when it cannot tell whether a jump is present.
func TestApplyWritesNothingWhenItCannotReadTheJumps(t *testing.T) {
	t.Parallel()
	handle := &fakeTables{chainErr: assert.AnError}
	err := netsetup.Apply(context.Background(), handle, programFor(t), nil)
	require.ErrorIs(t, err, assert.AnError, "the read error reaches the caller")
	assert.Contains(t, err.Error(), "look for the EGRESS_PROXY_FILTER_OUTPUT chain in the filter table",
		"the error names the chain")
	assert.Empty(t, handle.writes, "nothing is loaded")
}

// TestVerifyProblems drives Verify against tables that hold something other
// than the ruleset. Each case is the negative fixture for one check: without
// one, a check that never fires reads as passing.
func TestVerifyProblems(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// edit changes what the tables hold before Verify reads them.
		edit func(rules map[string][]string)
		// listErr makes one chain unreadable.
		listErr map[string]error
		want    []string
	}{
		{name: "the tables hold the whole ruleset and nothing else"},
		{
			name: "a rule the rest of the system put in OUTPUT after the jumps",
			edit: func(rules map[string][]string) {
				rules["filter OUTPUT"] = append(rules["filter OUTPUT"], filterOther)
				rules["nat OUTPUT"] = append(rules["nat OUTPUT"], natOther)
			},
		},
		{
			name: "a rule this ruleset did not install, above the terminal DROP",
			edit: func(rules map[string][]string) {
				rules[filterKey] = slices.Insert(rules[filterKey], 0, "-A EGRESS_PROXY_FILTER_OUTPUT -j ACCEPT")
			},
			want: []string{"holds a rule this ruleset did not put there"},
		},
		{
			name: "a terminal DROP that is no longer last",
			edit: func(rules map[string][]string) {
				chain := rules[filterKey]
				rules[filterKey] = append([]string{drop}, chain[:len(chain)-1]...)
			},
			want: []string{"not the terminal DROP"},
		},
		{
			name: "a filter chain that holds two DROP rules",
			edit: func(rules map[string][]string) {
				chain := rules[filterKey]
				rules[filterKey] = append(append([]string{drop}, chain[1:len(chain)-1]...), drop)
			},
			want: []string{"holds 2 DROP rules"},
		},
		{
			name: "a chain whose terminal DROP was replaced by an accept",
			edit: func(rules map[string][]string) {
				rules[filterKey][len(rules[filterKey])-1] = "-A EGRESS_PROXY_FILTER_OUTPUT -o eth0 -j ACCEPT"
			},
			want: []string{"has no terminal DROP"},
		},
		{
			name: "a rule ahead of the filter OUTPUT jump, which decides the packet before the jump does",
			edit: func(rules map[string][]string) {
				rules["filter OUTPUT"] = slices.Insert(rules["filter OUTPUT"], 0, "-A OUTPUT -j ACCEPT")
			},
			want: []string{
				`the first rule in the OUTPUT chain in the filter table is not "` + filterJump + `"`,
				"Those rules are:\n    -A OUTPUT -j ACCEPT",
			},
		},
		{
			name: "a rule ahead of the nat OUTPUT jump, which rewrites the destination before the REDIRECT",
			edit: func(rules map[string][]string) {
				rules["nat OUTPUT"] = slices.Insert(rules["nat OUTPUT"], 0,
					"-A OUTPUT -p tcp -j DNAT --to-destination 10.0.0.1:443")
			},
			want: []string{`the first rule in the OUTPUT chain in the nat table is not "` + natJump + `"`},
		},
		{
			// The first rule jumps to the owned chain for one interface only,
			// and the ACCEPT after it decides everything else.
			name: "a narrower jump to the owned chain first, then an ACCEPT, then the jump",
			edit: func(rules map[string][]string) {
				rules["filter OUTPUT"] = []string{
					"-A OUTPUT -o eth1 -j EGRESS_PROXY_FILTER_OUTPUT",
					"-A OUTPUT -j ACCEPT",
					filterJump,
				}
			},
			want: []string{
				`the first rule in the OUTPUT chain in the filter table is not "` + filterJump + `"`,
				"Those rules are:\n    -A OUTPUT -o eth1 -j EGRESS_PROXY_FILTER_OUTPUT\n    -A OUTPUT -j ACCEPT",
			},
		},
		{
			name: "a rule the ruleset installs that is not in the tables",
			edit: func(rules map[string][]string) {
				rules[filterKey] = rules[filterKey][1:]
			},
			want: []string{"not in the tables"},
		},
		{
			name:    "a chain that cannot be read at all",
			listErr: map[string]error{filterKey: assert.AnError},
			want:    []string{"read the EGRESS_PROXY_FILTER_OUTPUT chain in the filter table"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			program := programFor(t)
			rules := listing(program)
			if tc.edit != nil {
				tc.edit(rules)
			}
			err := netsetup.Verify(&fakeTables{rules: rules, listErr: tc.listErr}, program, nil)
			if len(tc.want) == 0 {
				require.NoError(t, err, "the ruleset is in force")
				return
			}
			require.ErrorIs(t, err, netsetup.ErrRulesMissing, "the error the caller keys on")
			for _, want := range tc.want {
				assert.Contains(t, err.Error(), want, "the refusal names this problem")
			}
		})
	}
}

// fakeBinary writes an executable that prints version and exits with code,
// standing in for an iptables binary's --version.
func fakeBinary(t *testing.T, dir, name, version string, code int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' %q\nexit %d\n", version, code)
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path
}

// legacyRestore is the version a legacy restore binary prints.
const legacyRestore = "iptables-restore v1.8.9 (legacy)"

// TestOpenAssertsTheLegacyBackend drives Open against binaries that name
// each backend, and no backend. The backend is read from the version string
// because modern images point the generic name at the nft variant, whose
// rules the sandbox runtimes never apply. The restore binary writes the
// rules, so its backend is asserted too.
func TestOpenAssertsTheLegacyBackend(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		family  netsetup.Family
		version string
		code    int
		// restore is what the restore binary beside it prints. Empty puts no
		// restore binary there.
		restore string
		// wantBackend is the backend Open reports. Empty means Open refuses.
		wantBackend netsetup.Backend
		want        string
	}{
		{
			name: "an IPv4 binary on the legacy backend", family: netsetup.FamilyIPv4,
			version: "iptables v1.8.9 (legacy)", restore: legacyRestore, wantBackend: netsetup.BackendLegacy,
		},
		{
			name: "an IPv6 binary on the legacy backend", family: netsetup.FamilyIPv6,
			version: "ip6tables v1.8.10 (legacy)", restore: "ip6tables-restore v1.8.10 (legacy)",
			wantBackend: netsetup.BackendLegacy,
		},
		{
			name: "a binary on the nft backend", family: netsetup.FamilyIPv4,
			version: "iptables v1.8.9 (nf_tables)", restore: legacyRestore, want: "uses the nf_tables backend",
		},
		{
			name: "an IPv4 binary given for the IPv6 family", family: netsetup.FamilyIPv6,
			version: "iptables v1.8.9 (legacy)", restore: legacyRestore,
			want: `reports "iptables v1.8.9 (legacy)", which is not ip6tables, so it does not program ipv6`,
		},
		{
			name: "an IPv6 binary whose restore binary is the IPv4 one", family: netsetup.FamilyIPv6,
			version: "ip6tables v1.8.9 (legacy)", restore: legacyRestore,
			want: `which is not ip6tables, so it does not program ipv6`,
		},
		{
			name: "a legacy binary with no restore binary beside it", family: netsetup.FamilyIPv4,
			version: "iptables v1.8.9 (legacy)", want: "iptables-restore is not on PATH",
		},
		{
			name: "a legacy binary whose restore binary is on the nft backend", family: netsetup.FamilyIPv4,
			version: "iptables v1.8.9 (legacy)", restore: "iptables-restore v1.8.9 (nf_tables)",
			want: "iptables-restore uses the nf_tables backend",
		},
		{
			name: "a binary older than 1.8, which names no backend", family: netsetup.FamilyIPv4,
			version: "iptables v1.6.1", want: "the iptables version names no backend",
		},
		{
			name: "a version string from some other program", family: netsetup.FamilyIPv4,
			version: "nft v1.0.6 (Lester Gooch #5)", want: "the iptables version names no backend",
		},
		{
			name: "a binary whose --version fails", family: netsetup.FamilyIPv4,
			version: "iptables v1.8.9 (legacy)", code: 3, want: "--version: exit status 3",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := fakeBinary(t, dir, "iptables", tc.version, tc.code)
			if tc.restore != "" {
				fakeBinary(t, dir, "iptables-restore", tc.restore, 0)
			}
			handle, tool, err := netsetup.Open(context.Background(), tc.family, path)
			if tc.wantBackend == "" {
				require.ErrorIs(t, err, netsetup.ErrNoLegacyBackend, "the error the caller keys on")
				assert.Contains(t, err.Error(), tc.want, "the refusal says why")
				assert.Nil(t, handle, "a refused binary gets no handle")
				return
			}
			require.NoError(t, err, "open the binary")
			assert.NotNil(t, handle, "the handle")
			assert.Equal(t, tc.wantBackend, tool.Backend, "the backend")
			assert.Equal(t, path, tool.Path, "the binary")
			assert.Equal(t, tc.version, tool.Version, "the first line of --version")
			assert.Equal(t, path+"-restore", tool.Restore, "the restore binary beside it")
		})
	}
}

// TestOpenSearchesPathForTheLegacyName proves the search order with no
// override: the legacy-specific name first, then the generic name. It sets
// PATH, so it does not run in parallel.
func TestOpenSearchesPathForTheLegacyName(t *testing.T) {
	tests := []struct {
		name string
		// binaries maps a name on PATH to the version it prints.
		binaries map[string]string
		wantPath string
		want     string
	}{
		{
			name: "both names, where the generic one is the nft variant",
			binaries: map[string]string{
				"iptables-legacy": "iptables v1.8.9 (legacy)",
				"iptables":        "iptables v1.8.9 (nf_tables)",
			},
			wantPath: "iptables-legacy",
		},
		{
			name:     "the generic name alone, on the legacy backend",
			binaries: map[string]string{"iptables": "iptables v1.8.9 (legacy)"},
			wantPath: "iptables",
		},
		{
			name:     "the generic name alone, on the nft backend",
			binaries: map[string]string{"iptables": "iptables v1.8.9 (nf_tables)"},
			want:     "iptables-legacy is not on PATH",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, version := range tc.binaries {
				fakeBinary(t, dir, name, version, 0)
				fakeBinary(t, dir, name+"-restore", legacyRestore, 0)
			}
			t.Setenv("PATH", dir)
			_, tool, err := netsetup.Open(context.Background(), netsetup.FamilyIPv4, "")
			if tc.wantPath == "" {
				require.ErrorIs(t, err, netsetup.ErrNoLegacyBackend, "the error the caller keys on")
				assert.Contains(t, err.Error(), tc.want, "the refusal names every name it tried")
				assert.Contains(t, err.Error(), "uses the nf_tables backend", "the refusal names the backend it found")
				return
			}
			require.NoError(t, err, "open the binary")
			assert.Equal(t, filepath.Join(dir, tc.wantPath), tool.Path, "the binary Open chose")
		})
	}
}
