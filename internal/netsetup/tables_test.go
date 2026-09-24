package netsetup_test

import (
	"context"
	"errors"
	"fmt"
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

// fakeTables stands in for an iptables binary. It records every invocation
// in order, so a test reads the sequence Apply performs. Every write also
// changes the chain listing it holds, and every read answers from that
// listing, so a test drives Verify against tables that hold whatever the
// case or an earlier Apply put there.
type fakeTables struct {
	calls []string
	// rules is what List answers, keyed by table and chain, in the order
	// iptables -S prints them.
	rules map[string][]string
	// listErr is returned by List for the chain it names, keyed the same
	// way.
	listErr map[string]error
	// fail makes the first write whose invocation contains it return
	// errWrite and change nothing.
	fail string
}

var errWrite = errors.New("iptables: write refused")

var errInsertPosition = errors.New("index of insertion too big")

func key(table, chain string) string { return table + " " + chain }

func rule(chain string, spec []string) string { return "-A " + chain + " " + strings.Join(spec, " ") }

func (f *fakeTables) ClearChain(table, chain string) error {
	if err := f.record("-t " + table + " -F " + chain); err != nil {
		return err
	}
	f.set(table, chain, nil)
	return nil
}

func (f *fakeTables) Append(table, chain string, spec ...string) error {
	if err := f.record("-t " + table + " -A " + chain + " " + strings.Join(spec, " ")); err != nil {
		return err
	}
	f.set(table, chain, append(f.rules[key(table, chain)], rule(chain, spec)))
	return nil
}

// Insert refuses a position past the end of the chain plus one, as
// iptables does.
func (f *fakeTables) Insert(table, chain string, pos int, spec ...string) error {
	call := "-t " + table + " -I " + chain + " " + strconv.Itoa(pos) + " " + strings.Join(spec, " ")
	if err := f.record(call); err != nil {
		return err
	}
	rules := f.rules[key(table, chain)]
	if pos < 1 || pos > len(rules)+1 {
		return fmt.Errorf("%w: %d", errInsertPosition, pos)
	}
	f.set(table, chain, slices.Insert(rules, pos-1, rule(chain, spec)))
	return nil
}

func (f *fakeTables) InsertUnique(table, chain string, pos int, spec ...string) error {
	if present, _ := f.Exists(table, chain, spec...); present {
		return nil
	}
	return f.Insert(table, chain, pos, spec...)
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

// record logs an invocation and reports whether the case makes it fail.
func (f *fakeTables) record(call string) error {
	f.calls = append(f.calls, call)
	if f.fail != "" && strings.Contains(call, f.fail) {
		return errWrite
	}
	return nil
}

func (f *fakeTables) set(table, chain string, rules []string) {
	if f.rules == nil {
		f.rules = make(map[string][]string)
	}
	f.rules[key(table, chain)] = rules
}

// listing renders what the tables hold once a program has been applied. An
// insert at position n lands at index n-1, which is how the accepts end up
// above the DROP that was appended first.
func listing(program netsetup.Program) map[string][]string {
	out := make(map[string][]string, len(program.Chains)+2)
	for _, step := range program.Steps {
		at := key(step.Table, step.Chain)
		installed := rule(step.Chain, step.Spec)
		if step.At > 0 {
			out[at] = slices.Insert(out[at], step.At-1, installed)
			continue
		}
		out[at] = append(out[at], installed)
	}
	return out
}

func programFor(t *testing.T) netsetup.Program {
	t.Helper()
	program, err := valid().Program(netsetup.FamilyIPv4)
	require.NoError(t, err, "build the ruleset")
	return program
}

// TestApplySealsTheFilterChainFirst pins the order Apply drives the tables
// in. Each invocation takes and releases the xtables lock, so between the
// flush of the filter chain and its terminal DROP the OUTPUT jump an earlier
// run left in place reaches an empty chain and the OUTPUT policy, ACCEPT in
// a pod, governs every protocol and port. The flush and the DROP are
// therefore the first two invocations of the whole run.
func TestApplySealsTheFilterChainFirst(t *testing.T) {
	t.Parallel()
	program := programFor(t)
	handle := &fakeTables{}
	require.NoError(t, netsetup.Apply(handle, program, nil), "apply the ruleset")

	require.GreaterOrEqual(t, len(handle.calls), 2, "the run makes at least the flush and the seal")
	assert.Equal(t, "-t filter -F EGRESS_PROXY_FILTER_OUTPUT", handle.calls[0],
		"the filter chain is flushed first")
	assert.Equal(t, "-t filter -A EGRESS_PROXY_FILTER_OUTPUT -j DROP", handle.calls[1],
		"the terminal DROP goes in before anything else changes")
	assert.Equal(t, 1, strings.Count(strings.Join(handle.calls, "\n"), " -A EGRESS_PROXY_FILTER_OUTPUT -j DROP"),
		"the DROP is installed once, so the chain holds one")
	natFlush := slices.Index(handle.calls, "-t nat -F EGRESS_PROXY_NAT_OUTPUT")
	require.Positive(t, natFlush, "the nat chain is flushed after the filter chain is sealed")
	for i, call := range handle.calls {
		if strings.Contains(call, "EGRESS_PROXY_FILTER_OUTPUT") && strings.Contains(call, "ACCEPT") {
			assert.Greater(t, i, 1, "accept %q is inserted after the DROP is in place", call)
		}
	}
}

// TestApplyStopsAtTheFirstFailure makes one invocation fail and checks that
// Apply stops there, names it, and leaves the filter chain ending in its
// DROP. The order puts the DROP in first, so a run cut short at any point is
// stricter than the finished ruleset.
func TestApplyStopsAtTheFirstFailure(t *testing.T) {
	t.Parallel()
	const drop = "-A EGRESS_PROXY_FILTER_OUTPUT -j DROP"
	tests := []struct {
		name string
		// fail is the invocation that fails, as the fake renders it.
		fail string
		// want is what the error names.
		want string
		// sealed says the terminal DROP went in before the failure.
		sealed bool
	}{
		{
			name: "the flush of the filter chain",
			fail: "-t filter -F EGRESS_PROXY_FILTER_OUTPUT",
			want: "clear the EGRESS_PROXY_FILTER_OUTPUT chain in the filter table",
		},
		{
			name: "the terminal DROP",
			fail: "-t filter -A EGRESS_PROXY_FILTER_OUTPUT -j DROP",
			want: "-t filter -A EGRESS_PROXY_FILTER_OUTPUT -j DROP",
		},
		{
			name:   "the nat REDIRECT",
			fail:   "-j REDIRECT",
			want:   "-t nat -A EGRESS_PROXY_NAT_OUTPUT -p tcp -m multiport --dports 80,443 -j REDIRECT",
			sealed: true,
		},
		{
			name:   "an accept above the DROP",
			fail:   "--uid-owner 1337 -j ACCEPT",
			want:   "-t filter -I EGRESS_PROXY_FILTER_OUTPUT 4 -m owner --uid-owner 1337 -j ACCEPT",
			sealed: true,
		},
		{
			name:   "the filter OUTPUT jump",
			fail:   "-I OUTPUT 1 -j EGRESS_PROXY_FILTER_OUTPUT",
			want:   "-t filter -I OUTPUT 1 -j EGRESS_PROXY_FILTER_OUTPUT",
			sealed: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			handle := &fakeTables{fail: tc.fail}
			err := netsetup.Apply(handle, programFor(t), nil)

			require.ErrorIs(t, err, errWrite, "the write error reaches the caller")
			assert.Contains(t, err.Error(), tc.want, "the error names the invocation that failed")
			require.NotEmpty(t, handle.calls, "the run made the failing call")
			assert.Contains(t, handle.calls[len(handle.calls)-1], tc.fail, "nothing runs after the failure")
			filter := handle.rules["filter EGRESS_PROXY_FILTER_OUTPUT"]
			if !tc.sealed {
				assert.Empty(t, filter, "no rule went in ahead of the DROP")
				return
			}
			require.NotEmpty(t, filter, "the filter chain holds its DROP")
			assert.Equal(t, drop, filter[len(filter)-1], "the filter chain still ends in the DROP")
		})
	}
}

// TestApplyPutsEachJumpFirst applies the ruleset to OUTPUT chains that
// already hold rules, then verifies it against the tables Apply left. A rule
// ahead of a jump decides the packet first, so the ruleset is in force only
// when each jump is rule 1.
func TestApplyPutsEachJumpFirst(t *testing.T) {
	t.Parallel()
	const (
		filterJump = "-A OUTPUT -j EGRESS_PROXY_FILTER_OUTPUT"
		natJump    = "-A OUTPUT -p tcp -j EGRESS_PROXY_NAT_OUTPUT"
		// Rules of the kind Docker's embedded resolver puts in a
		// container's OUTPUT chains.
		filterOther = "-A OUTPUT -d 127.0.0.11/32 -j ACCEPT"
		natOther    = "-A OUTPUT -d 127.0.0.11/32 -j DOCKER_OUTPUT"
	)
	tests := []struct {
		name string
		// beforeFilter and beforeNat are what each OUTPUT chain holds when
		// Apply starts.
		beforeFilter, beforeNat []string
		wantFilter, wantNat     []string
		// wantRefusal is empty when Verify passes after Apply.
		wantRefusal string
	}{
		{
			name:       "empty OUTPUT chains",
			wantFilter: []string{filterJump},
			wantNat:    []string{natJump},
		},
		{
			name:         "OUTPUT chains that hold a rule the rest of the system put there",
			beforeFilter: []string{filterOther},
			beforeNat:    []string{natOther},
			wantFilter:   []string{filterJump, filterOther},
			wantNat:      []string{natJump, natOther},
		},
		{
			name:         "a re-run, which leaves the jumps an earlier run put first",
			beforeFilter: []string{filterJump, filterOther},
			beforeNat:    []string{natJump, natOther},
			wantFilter:   []string{filterJump, filterOther},
			wantNat:      []string{natJump, natOther},
		},
		{
			name:         "a re-run after a rule went in ahead of the filter jump",
			beforeFilter: []string{filterOther, filterJump},
			beforeNat:    []string{natJump},
			wantFilter:   []string{filterOther, filterJump},
			wantNat:      []string{natJump},
			wantRefusal:  "jumps to EGRESS_PROXY_FILTER_OUTPUT only at position 2",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			program := programFor(t)
			handle := &fakeTables{}
			handle.set("filter", "OUTPUT", slices.Clone(tc.beforeFilter))
			handle.set("nat", "OUTPUT", slices.Clone(tc.beforeNat))

			require.NoError(t, netsetup.Apply(handle, program, nil), "apply the ruleset")
			assert.Equal(t, tc.wantFilter, handle.rules["filter OUTPUT"], "the filter OUTPUT chain")
			assert.Equal(t, tc.wantNat, handle.rules["nat OUTPUT"], "the nat OUTPUT chain")

			err := netsetup.Verify(handle, program, nil)
			if tc.wantRefusal == "" {
				require.NoError(t, err, "the ruleset is in force")
				return
			}
			require.ErrorIs(t, err, netsetup.ErrRulesMissing, "the error the caller keys on")
			assert.Contains(t, err.Error(), tc.wantRefusal, "the refusal names the rule ahead of the jump")
		})
	}
}

// TestVerifyProblems drives Verify against tables that hold something other
// than the ruleset. Each case is the negative fixture for one check: without
// one, a check that never fires reads as passing.
func TestVerifyProblems(t *testing.T) {
	t.Parallel()
	const (
		filterKey = "filter EGRESS_PROXY_FILTER_OUTPUT"
		jumpKey   = "filter OUTPUT"
		natJump   = "nat OUTPUT"
		drop      = "-A EGRESS_PROXY_FILTER_OUTPUT -j DROP"
	)
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
			name: "a chain the ruleset was applied to twice, so it holds two DROP rules",
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
				rules[jumpKey] = slices.Insert(rules[jumpKey], 0, "-A OUTPUT -j ACCEPT")
			},
			want: []string{
				"jumps to EGRESS_PROXY_FILTER_OUTPUT only at position 2",
				"-A OUTPUT -j ACCEPT",
			},
		},
		{
			name: "a rule ahead of the nat OUTPUT jump, which rewrites the destination before the REDIRECT",
			edit: func(rules map[string][]string) {
				rules[natJump] = slices.Insert(rules[natJump], 0,
					"-A OUTPUT -p tcp -j DNAT --to-destination 10.0.0.1:443")
			},
			want: []string{"jumps to EGRESS_PROXY_NAT_OUTPUT only at position 2"},
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

// TestOpenAssertsTheLegacyBackend drives Open against binaries that name
// each backend, and no backend. The backend is read from the version string
// because modern images point the generic name at the nft variant, whose
// rules the sandbox runtimes never apply.
func TestOpenAssertsTheLegacyBackend(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		family  netsetup.Family
		version string
		code    int
		// wantBackend is the backend Open reports. Empty means Open refuses.
		wantBackend netsetup.Backend
		want        string
	}{
		{
			name: "an IPv4 binary on the legacy backend", family: netsetup.FamilyIPv4,
			version: "iptables v1.8.9 (legacy)", wantBackend: netsetup.BackendLegacy,
		},
		{
			name: "an IPv6 binary on the legacy backend", family: netsetup.FamilyIPv6,
			version: "ip6tables v1.8.10 (legacy)", wantBackend: netsetup.BackendLegacy,
		},
		{
			name: "a binary on the nft backend", family: netsetup.FamilyIPv4,
			version: "iptables v1.8.9 (nf_tables)", want: "uses the nf_tables backend",
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
			path := fakeBinary(t, t.TempDir(), "iptables", tc.version, tc.code)
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
