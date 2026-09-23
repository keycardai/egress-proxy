package netsetup_test

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// fakeTables stands in for an iptables binary. It records every invocation
// in order, so a test reads the sequence Apply performs, and it answers
// every read from a chain listing the case supplies, so a test drives Verify
// against tables that hold whatever it wants them to hold.
type fakeTables struct {
	calls []string
	// rules is what List answers, keyed by table and chain, in the order
	// iptables -S prints them.
	rules map[string][]string
	// listErr is returned by List for the chain it names, keyed the same
	// way.
	listErr map[string]error
}

func key(table, chain string) string { return table + " " + chain }

func (f *fakeTables) ClearChain(table, chain string) error {
	f.calls = append(f.calls, "-t "+table+" -F "+chain)
	return nil
}

func (f *fakeTables) Append(table, chain string, spec ...string) error {
	f.calls = append(f.calls, "-t "+table+" -A "+chain+" "+strings.Join(spec, " "))
	return nil
}

func (f *fakeTables) AppendUnique(table, chain string, spec ...string) error {
	return f.Append(table, chain, spec...)
}

func (f *fakeTables) Insert(table, chain string, pos int, spec ...string) error {
	f.calls = append(f.calls, "-t "+table+" -I "+chain+" "+strconv.Itoa(pos)+" "+strings.Join(spec, " "))
	return nil
}

func (f *fakeTables) Exists(table, chain string, spec ...string) (bool, error) {
	return slices.Contains(f.rules[key(table, chain)], "-A "+chain+" "+strings.Join(spec, " ")), nil
}

func (f *fakeTables) List(table, chain string) ([]string, error) {
	if err := f.listErr[key(table, chain)]; err != nil {
		return nil, err
	}
	return append([]string{"-N " + chain}, f.rules[key(table, chain)]...), nil
}

// listing renders what the tables hold once a program has been applied. An
// insert at position n lands at index n-1, which is how the accepts end up
// above the DROP that was appended first.
func listing(program netsetup.Program) map[string][]string {
	out := make(map[string][]string, len(program.Chains)+2)
	for _, step := range program.Steps {
		at := key(step.Table, step.Chain)
		rule := "-A " + step.Chain + " " + strings.Join(step.Spec, " ")
		if step.At > 0 {
			out[at] = slices.Insert(out[at], step.At-1, rule)
			continue
		}
		out[at] = append(out[at], rule)
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
