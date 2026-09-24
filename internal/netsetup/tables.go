package netsetup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
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
// later name it in parentheses, as in "iptables v1.8.10 (legacy)".
var versionPattern = regexp.MustCompile(`^ip6?tables v[^ ]+ \((legacy|nf_tables)\)`)

// Tool is an iptables binary that has identified itself.
type Tool struct {
	// Path is the resolved absolute path.
	Path string
	// Version is the first line of --version, kept for the error messages
	// and the acceptance record.
	Version string
	Backend Backend
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

// Open resolves the iptables binary for a family, asserts that it uses the
// legacy backend, and returns a handle bound to it.
//
// NEVER relax this to accept the nft backend. Modern base images symlink
// iptables to the nft variant, which is why the backend is asserted rather
// than inferred from the binary's name, and the sandbox runtimes this proxy
// targets carry x_tables and not nftables.
//
// override names a binary explicitly and nothing else is tried. With no
// override the legacy-specific name comes first and the generic name second,
// which is the image that ships one binary under the generic name.
func Open(ctx context.Context, family Family, override string) (*iptables.IPTables, Tool, error) {
	candidates := legacyBinaries(family)
	if override != "" {
		candidates = []string{override}
	}
	reasons := make([]string, 0, len(candidates))
	for _, name := range candidates {
		tool, err := detectTool(ctx, name)
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		if tool.Backend != BackendLegacy {
			reasons = append(reasons, fmt.Sprintf("%s uses the %s backend (%s)", tool.Path, tool.Backend, tool.Version))
			continue
		}
		handle, err := iptables.New(iptables.Path(tool.Path), iptables.IPFamily(protocol(family)),
			iptables.Timeout(waitSeconds))
		if err != nil {
			return nil, Tool{}, fmt.Errorf("open %s: %w", tool.Path, err)
		}
		return handle, tool, nil
	}
	return nil, Tool{}, fmt.Errorf("%w for %s: %s. Install a legacy iptables binary in this image",
		ErrNoLegacyBackend, family, strings.Join(reasons, "; "))
}

func protocol(family Family) iptables.Protocol {
	if family == FamilyIPv6 {
		return iptables.ProtocolIPv6
	}
	return iptables.ProtocolIPv4
}

// Tables is the part of an iptables handle this package drives. Apply and
// Verify take it, so a test drives them against a recorded ruleset.
type Tables interface {
	ClearChain(table, chain string) error
	Append(table, chain string, rulespec ...string) error
	Insert(table, chain string, pos int, rulespec ...string) error
	InsertUnique(table, chain string, pos int, rulespec ...string) error
	Exists(table, chain string, rulespec ...string) (bool, error)
	List(table, chain string) ([]string, error)
}

// Apply puts the program in the tables, writing each rule to progress as it
// goes. It walks the order Program lays out, which is the order --dry-run
// prints.
//
// Every owned chain is flushed before it is refilled, so re-running installs
// the same rules rather than a second copy. A failure stops the run and
// names the rule that could not go in. Stopping leaves the chains stricter
// than the finished ruleset rather than looser, which is a property of that
// order.
func Apply(handle Tables, program Program, progress io.Writer) error {
	for _, step := range program.sealSteps() {
		if err := clearChain(handle, step.Table, step.Chain); err != nil {
			return err
		}
		if err := writeStep(handle, step, progress); err != nil {
			return err
		}
	}
	for _, chain := range program.unsealedChains() {
		if err := clearChain(handle, chain.Table, chain.Name); err != nil {
			return err
		}
	}
	for _, step := range program.fillSteps() {
		if err := writeStep(handle, step, progress); err != nil {
			return err
		}
	}
	return nil
}

func clearChain(handle Tables, table, chain string) error {
	if err := handle.ClearChain(table, chain); err != nil {
		return fmt.Errorf("clear the %s chain in the %s table: %w", chain, table, err)
	}
	return nil
}

func writeStep(handle Tables, step Step, progress io.Writer) error {
	if progress != nil {
		fmt.Fprintln(progress, step.String())
	}
	if err := applyStep(handle, step); err != nil {
		return fmt.Errorf("%s: %w", step, err)
	}
	return nil
}

func applyStep(handle Tables, step Step) error {
	switch {
	case step.Existing:
		//nolint:wrapcheck // the caller names the step
		return handle.InsertUnique(step.Table, step.Chain, step.At, step.Spec...)
	case step.At > 0:
		return handle.Insert(step.Table, step.Chain, step.At, step.Spec...) //nolint:wrapcheck // same
	default:
		return handle.Append(step.Table, step.Chain, step.Spec...) //nolint:wrapcheck // same
	}
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
// chain's terminal DROP is checked by position as well. Every accept is
// inserted above it, so a DROP that is not last leaves the rules after it
// accepting.
//
// Each OUTPUT jump is the first rule in its OUTPUT chain. A rule ahead of
// the filter jump accepts what the terminal DROP would drop, and one ahead
// of the nat jump rewrites the destination before the REDIRECT sees it.
func Verify(handle Tables, program Program, progress io.Writer) error {
	var found problems
	for _, step := range program.Steps {
		present, err := handle.Exists(step.Table, step.Chain, step.Spec...)
		switch {
		case err != nil:
			found.addf("%s: %v", step, err)
		case !present:
			found.addf("not in the tables: %s", step)
		}
		if step.Existing {
			found.add(jumpProblems(handle, step)...)
		}
	}
	for _, chain := range program.Chains {
		found.add(chainProblems(handle, chain)...)
	}
	if len(found) > 0 {
		return fmt.Errorf("%w for %s:\n  %s", ErrRulesMissing, program.Family, strings.Join(found, "\n  "))
	}
	if progress != nil {
		fmt.Fprintf(progress, "# %s verified: %d rules present, no rule this ruleset did not install, "+
			"the terminal DROP is last, each OUTPUT jump is first\n", program.Family, len(program.Steps))
	}
	return nil
}

// jumpProblems reports a rule that runs before the OUTPUT jump attaching an
// owned chain. Whatever runs first decides the packet, so a jump that is not
// the first rule governs only what the rules ahead of it passed on.
//
// The jump is found by its target, because iptables prints a rule back in
// its own normalised form.
func jumpProblems(handle Tables, step Step) []string {
	target := jumpTarget(step.Spec)
	if target == "" {
		return nil
	}
	rules, err := chainRules(handle, step.Table, step.Chain)
	if err != nil {
		return []string{err.Error()}
	}
	for i, rule := range rules {
		if !strings.HasSuffix(rule, " -j "+target) {
			continue
		}
		if i == 0 {
			return nil
		}
		return []string{fmt.Sprintf("the %s chain in the %s table jumps to %s only at position %d, so the "+
			"rules ahead of it decide the packet first. Those rules are:\n    %s",
			step.Chain, step.Table, target, i+1, strings.Join(rules[:i], "\n    "))}
	}
	// Exists already reports a jump that is not there at all.
	return nil
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
	if len(rules) != chain.Rules {
		found.addf("the %s chain in the %s table holds %d rules and this ruleset installs %d, so it holds a "+
			"rule this ruleset did not put there. A rule above the terminal DROP accepts what the DROP would "+
			"drop. The chain is:\n    %s",
			chain.Name, chain.Table, len(rules), chain.Rules, strings.Join(rules, "\n    "))
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
		found.addf("the %s chain holds %d DROP rules, so it was applied more than once", filterChain, count)
	case rules[len(rules)-1] != drop:
		found.addf("the last rule in the %s chain is %q, not the terminal DROP. Every accept is inserted "+
			"above the DROP, so a rule below it is never reached and a DROP that is not last leaves the rules "+
			"after it accepting", filterChain, rules[len(rules)-1])
	}
	return found
}
