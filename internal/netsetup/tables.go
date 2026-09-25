package netsetup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
)

// waitSeconds is how long each invocation waits for the xtables lock. Two
// programs holding CAP_NET_ADMIN in one network namespace is ordinary.
const waitSeconds = 5

// Backend is the rule engine an iptables binary talks to.
type Backend string

// The backends an iptables binary names in its version string.
const (
	// BackendLegacy is the x_tables interface, which this package requires.
	BackendLegacy Backend = "legacy"
	// BackendNFTables is the nftables translation layer, which this package
	// refuses.
	BackendNFTables Backend = "nf_tables"
)

// The errors this package returns.
var (
	// ErrInvalidConfig is returned by Config.Validate.
	ErrInvalidConfig = errors.New("invalid netsetup configuration")
	// ErrNoLegacyBackend is returned when no iptables binary on PATH speaks
	// the legacy backend.
	ErrNoLegacyBackend = errors.New("no iptables binary with the legacy backend")
	// ErrRulesMissing is returned when the tables do not hold the whole
	// ruleset.
	ErrRulesMissing = errors.New("the ruleset is not in force")
	// ErrIPv6Undetermined is returned when this process cannot tell whether
	// the kernel has IPv6. Choosing a mode from a guess can leave IPv6
	// ungoverned, so the caller names one instead.
	ErrIPv6Undetermined = errors.New("whether this kernel has IPv6 could not be determined")
	// ErrNoBackendNamed is returned for a version string with no
	// parenthesised backend. Assuming a backend is how a pod ends up with
	// rules the kernel never applied.
	ErrNoBackendNamed = errors.New("the iptables version names no backend")
)

// versionTimeout bounds the --version run that identifies a binary.
const versionTimeout = 10 * time.Second

// restoreTimeout bounds one iptables-restore run, including its wait for the
// xtables lock.
const restoreTimeout = 30 * time.Second

// legacyBinaries are the binaries this package resolves for a family, most
// specific name first. The generic name is the image that ships one binary
// under it.
func legacyBinaries(family Family) []string {
	if family == FamilyIPv6 {
		return []string{"ip6tables-legacy", "ip6tables"}
	}
	return []string{"iptables-legacy", "iptables"}
}

// versionPattern reads the backend out of a version string. iptables 1.8 and
// later name it in parentheses, as in "iptables v1.8.10 (legacy)" and
// "iptables-restore v1.8.10 (legacy)".
var versionPattern = regexp.MustCompile(`^ip6?tables(?:-restore)? v[^ ]+ \((legacy|nf_tables)\)`)

// restoreSuffix names a family's restore binary: iptables-legacy has
// iptables-legacy-restore beside it, and iptables has iptables-restore.
const restoreSuffix = "-restore"

// Tool is an iptables binary that has identified itself.
type Tool struct {
	// Path is the resolved absolute path.
	Path string
	// Version is the first line of --version, kept for the error messages
	// and the acceptance record.
	Version string
	Backend Backend
	// Restore is the resolved path of the restore binary that writes the
	// rules. Its version names the same backend.
	Restore string
}

// detectTool runs a binary's --version and reports which backend it uses.
// A version that names no backend is refused, because assuming one is how a
// pod ends up with rules the kernel never applied.
//
// NEVER take the backend from go-iptables. It reports legacy when the
// version names none (extractIptablesVersion in iptables/iptables.go).
func detectTool(ctx context.Context, name string) (Tool, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return Tool{}, fmt.Errorf("%s is not on PATH: %w", name, err)
	}
	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	//nolint:gosec // G204: the name comes from this command's own flags and is resolved through PATH
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil {
		return Tool{}, fmt.Errorf("%s --version: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	version, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	match := versionPattern.FindStringSubmatch(version)
	if match == nil {
		return Tool{}, fmt.Errorf("%w: %s reports %q", ErrNoBackendNamed, path, version)
	}
	return Tool{Path: path, Version: version, Backend: Backend(match[1])}, nil
}

// Open resolves the iptables binary for a family and the restore binary
// beside it, asserts that both use the legacy backend, and returns a handle
// bound to them.
//
// NEVER relax this to accept the nft backend. Modern base images symlink
// iptables to the nft variant, which is why the backend is asserted rather
// than inferred from the binary's name, and the sandbox runtimes this proxy
// targets have x_tables and not nftables.
//
// override names a binary explicitly and nothing else is tried. With no
// override the legacy-specific name comes first and the generic name second,
// which is the image that ships one binary under the generic name.
func Open(ctx context.Context, family Family, override string) (*Handle, Tool, error) {
	candidates := legacyBinaries(family)
	if override != "" {
		candidates = []string{override}
	}
	reasons := make([]string, 0, len(candidates))
	for _, name := range candidates {
		tool, err := legacyTool(ctx, family, name)
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		restore, err := legacyTool(ctx, family, tool.Path+restoreSuffix)
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		tool.Restore = restore.Path
		ipt, err := iptables.New(iptables.Path(tool.Path), iptables.IPFamily(protocol(family)),
			iptables.Timeout(waitSeconds))
		if err != nil {
			return nil, Tool{}, fmt.Errorf("open %s: %w", tool.Path, err)
		}
		return &Handle{IPTables: ipt, restore: restore.Path}, tool, nil
	}
	return nil, Tool{}, fmt.Errorf("%w for %s: %s. Install a legacy iptables binary in this image",
		ErrNoLegacyBackend, family, strings.Join(reasons, "; "))
}

// legacyTool identifies a binary and refuses one on another backend or for
// the other family. The version names the program: iptables writes the IPv4
// tables and ip6tables the IPv6 tables.
func legacyTool(ctx context.Context, family Family, name string) (Tool, error) {
	tool, err := detectTool(ctx, name)
	if err != nil {
		return Tool{}, err
	}
	program := "iptables"
	if family == FamilyIPv6 {
		program = "ip6tables"
	}
	if !strings.HasPrefix(tool.Version, program+" ") && !strings.HasPrefix(tool.Version, program+restoreSuffix+" ") {
		//nolint:err113 // a reason Open joins under ErrNoLegacyBackend
		return Tool{}, fmt.Errorf("%s reports %q, which is not %s, so it does not program %s", tool.Path,
			tool.Version, program, family)
	}
	if tool.Backend != BackendLegacy {
		//nolint:err113 // a reason Open joins under ErrNoLegacyBackend
		return Tool{}, fmt.Errorf("%s uses the %s backend (%s)", tool.Path, tool.Backend, tool.Version)
	}
	return tool, nil
}

// Handle drives one family's tables. go-iptables reads them and the
// family's restore binary writes them.
type Handle struct {
	*iptables.IPTables

	restore string
}

// Restore loads input with iptables-restore --noflush. The kernel replaces
// each table in one operation at its COMMIT line, so a table that fails to
// load keeps the rules it held.
func (h *Handle) Restore(ctx context.Context, input string) error {
	ctx, cancel := context.WithTimeout(ctx, restoreTimeout)
	defer cancel()
	//nolint:gosec // G204: the path was resolved and its backend asserted by Open
	cmd := exec.CommandContext(ctx, h.restore, "--noflush", "--wait="+strconv.Itoa(waitSeconds))
	cmd.Stdin = strings.NewReader(input)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", h.restore, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func protocol(family Family) iptables.Protocol {
	if family == FamilyIPv6 {
		return iptables.ProtocolIPv6
	}
	return iptables.ProtocolIPv4
}

// Tables is the part of a Handle this package drives. Apply and Verify take
// it, so a test drives them against a recorded ruleset.
type Tables interface {
	ChainExists(table, chain string) (bool, error)
	Exists(table, chain string, rulespec ...string) (bool, error)
	List(table, chain string) ([]string, error)
	Restore(ctx context.Context, input string) error
}

// Apply loads the program in one iptables-restore run, writing the input to
// progress first.
//
// Each table is replaced in one kernel operation, so a chain holds either
// its old rules or the whole new set and never sits empty under a live
// jump. Re-running installs the same rules and no second copy. A failed run
// leaves each table as it was, except that the filter table commits before
// the nat table, so a failure in the nat table leaves the new filter chain
// in force.
func Apply(ctx context.Context, handle Tables, program Program, progress io.Writer) error {
	jumps, err := missingJumps(handle, program)
	if err != nil {
		return err
	}
	input := program.Restore(jumps)
	if progress != nil {
		fmt.Fprint(progress, input)
	}
	if err := handle.Restore(ctx, input); err != nil {
		return fmt.Errorf("load the %s ruleset: %w", program.Family, err)
	}
	return nil
}

// missingJumps lists the OUTPUT jumps not in the tables. A jump whose chain
// does not exist yet is missing: iptables -C refuses a jump to a chain it
// cannot find, rather than reporting it absent.
func missingJumps(handle Tables, program Program) ([]Rule, error) {
	var missing []Rule
	for _, jump := range program.Jumps {
		target := jumpTarget(jump.Spec)
		exists, err := handle.ChainExists(jump.Table, target)
		if err != nil {
			return nil, fmt.Errorf("look for the %s chain in the %s table: %w", target, jump.Table, err)
		}
		if exists {
			if exists, err = handle.Exists(jump.Table, jump.Chain, jump.Spec...); err != nil {
				return nil, fmt.Errorf("look for %s: %w", jump, err)
			}
		}
		if !exists {
			missing = append(missing, jump)
		}
	}
	return missing, nil
}

// Verify reports whether the tables hold this ruleset and nothing else.
//
// It answers the question the sidecar cannot answer for itself: are the
// rules that make this pod's egress unavoidable in the kernel, and is
// anything else in the way. Three checks together pin the ruleset.
//
// Every rule the program installs is present. The kernel answers this with
// -C, because iptables prints a rule back in its own normalised form and
// that text does not match this package's spelling.
//
// Each owned chain holds exactly as many rules as the program puts in it.
// With every expected rule present, a matching count means the chain holds
// no other rule, such as an ACCEPT above the terminal DROP. The filter
// chain's terminal DROP is checked by position as well, because a DROP that
// is not last leaves the rules after it accepting.
//
// Each OUTPUT jump is the first rule in its OUTPUT chain. A rule ahead of
// the filter jump accepts what the terminal DROP would drop, and one ahead
// of the nat jump rewrites the destination before the REDIRECT sees it.
func Verify(handle Tables, program Program, progress io.Writer) error {
	var found problems
	rules := program.Rules()
	for _, rule := range slices.Concat(rules, program.Jumps) {
		present, err := handle.Exists(rule.Table, rule.Chain, rule.Spec...)
		switch {
		case err != nil:
			found.addf("%s: %v", rule, err)
		case !present:
			found.addf("not in the tables: %s", rule)
		}
	}
	for _, jump := range program.Jumps {
		found.add(jumpProblems(handle, jump)...)
	}
	for _, chain := range program.Chains {
		found.add(chainProblems(handle, chain)...)
	}
	if len(found) > 0 {
		return fmt.Errorf("%w for %s:\n  %s", ErrRulesMissing, program.Family, strings.Join(found, "\n  "))
	}
	if progress != nil {
		fmt.Fprintf(progress, "# %s verified: %d rules present, no rule this ruleset did not install, "+
			"the terminal DROP is last, each OUTPUT jump is first\n", program.Family, len(rules)+len(program.Jumps))
	}
	return nil
}

// jumpProblems reports an OUTPUT chain whose first rule is not the jump.
// Whatever runs first decides the packet, so a jump that is not the first
// rule governs only what the rules ahead of it passed on.
//
// The first rule must be the jump exactly, as iptables -S prints it. Another
// rule to the same chain, such as one that matches a single interface,
// governs less than the jump does.
func jumpProblems(handle Tables, jump Rule) []string {
	rules, err := chainRules(handle, jump.Table, jump.Chain)
	if err != nil {
		return []string{err.Error()}
	}
	want := "-A " + jump.Chain + " " + strings.Join(jump.Spec, " ")
	if len(rules) > 0 && rules[0] == want {
		return nil
	}
	ahead := rules
	if i := slices.Index(rules, want); i >= 0 {
		ahead = rules[:i]
	}
	return []string{fmt.Sprintf("the first rule in the %s chain in the %s table is not %q, so the rules "+
		"ahead of it decide the packet first. Those rules are:\n    %s",
		jump.Chain, jump.Table, want, strings.Join(ahead, "\n    "))}
}

// jumpTarget is the chain a rule jumps to, empty for a rule that names no
// target.
func jumpTarget(spec []string) string {
	for i := range spec {
		if spec[i] == "-j" && i+1 < len(spec) {
			return spec[i+1]
		}
	}
	return ""
}

// chainProblems reports a chain that holds a rule this ruleset did not
// install, and a filter chain whose terminal DROP is not last.
func chainProblems(handle Tables, chain Chain) []string {
	var found problems
	rules, err := chainRules(handle, chain.Table, chain.Name)
	if err != nil {
		return []string{err.Error()}
	}
	if len(rules) != len(chain.Rules) {
		found.addf("the %s chain in the %s table holds %d rules and this ruleset installs %d, so it holds a "+
			"rule this ruleset did not put there. A rule above the terminal DROP accepts what the DROP would "+
			"drop. The chain is:\n    %s",
			chain.Name, chain.Table, len(rules), len(chain.Rules), strings.Join(rules, "\n    "))
	}
	if chain.Name == filterChain {
		found.add(terminalDropProblems(rules)...)
	}
	return found
}

// chainRules returns the rules a chain holds, in order, as iptables -S
// prints them. The -N line that creates the chain is not a rule.
func chainRules(handle Tables, table, chain string) ([]string, error) {
	listed, err := handle.List(table, chain)
	if err != nil {
		return nil, fmt.Errorf("read the %s chain in the %s table: %w", chain, table, err)
	}
	rules := make([]string, 0, len(listed))
	for _, line := range listed {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "-A ") {
			rules = append(rules, line)
		}
	}
	return rules, nil
}

// terminalDropProblems asserts the filter chain ends in the DROP and holds
// exactly one.
func terminalDropProblems(rules []string) []string {
	drop := "-A " + filterChain + " -j DROP"
	count := 0
	for _, rule := range rules {
		if rule == drop {
			count++
		}
	}
	var found problems
	switch {
	case count == 0:
		found.addf("the %s chain has no terminal DROP, so it enforces nothing", filterChain)
	case count > 1:
		found.addf("the %s chain holds %d DROP rules and this ruleset installs one", filterChain, count)
	case rules[len(rules)-1] != drop:
		found.addf("the last rule in the %s chain is %q, not the terminal DROP. A DROP that is not last "+
			"leaves the rules after it accepting", filterChain, rules[len(rules)-1])
	}
	return found
}
