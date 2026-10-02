// Package gates proves that each CI gate rejects what it exists to reject.
// Each case points a gate script at a fixture module under testdata that
// must fail it, and asserts the message a developer sees. Every script this
// test runs takes that directory as its first argument.
//
// The lint gate also has a control case: the same fixture passes without the
// gate_negative build tag, which leaves the offending file out of the build.
// A gate that failed everything could not pass that case.
//
// The import gate exempts a file whose path under its module root starts
// with test/. Its fixture is linted from a copy in a temporary directory,
// once under a path element named test and once under none, so the cases
// hold wherever the repository itself is checked out.
package gates_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repoRoot is the repository root relative to this package directory.
const repoRoot = "../.."

// The gate scripts under scripts/.
const (
	lintScript     = "lint.sh"
	licensesScript = "check-licenses.sh"
	noticeScript   = "notice.sh"
	vulnScript     = "vuln.sh"
)

func TestGates(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("gate self-tests build the tool directives in go.mod; skipped under -short")
	}

	tests := []struct {
		name string
		// script is the gate under scripts/.
		script string
		// fixture is the module directory under testdata the gate runs over.
		fixture string
		// args go to the gate after the directory.
		args []string
		// copyTo places the fixture somewhere else before the gate runs
		// and returns the copy. A nil value lints the fixture where it
		// sits.
		copyTo func(t *testing.T, fixture string) string
		// wantExit is the exit code the gate must return. Every gate exits
		// 0 when it passes. govulncheck exits 3 on a finding, and
		// golangci-lint and go-licenses exit 1.
		wantExit int
		// wantOutput are substrings that must all appear in the combined
		// output, naming the offending module and the gate that caught it.
		wantOutput []string
		// wantAbsent are substrings that must not appear in the output.
		wantAbsent []string
	}{
		{
			name:     "license gate rejects a GPL-3.0 module in the build list",
			script:   licensesScript,
			fixture:  "gpl-module",
			wantExit: 1,
			wantOutput: []string{
				"Not allowed license 'GPL-3.0' found for library 'github.com/AdguardTeam/gomitmproxy'",
			},
		},
		{
			name:     "NOTICE gate rejects a NOTICE that leaves out a module a binary imports",
			script:   noticeScript,
			fixture:  "stale-notice",
			args:     []string{"--check"},
			wantExit: 1,
			wantOutput: []string{
				"+golang.org/x/text v0.3.7",
				"notice: FAIL. NOTICE is stale",
			},
			// The module only test/ imports does not ship in a binary.
			wantAbsent: []string{"github.com/pkg/errors"},
		},
		{
			name:     "import gate rejects an import under github.com/keycardlabs/",
			script:   lintScript,
			fixture:  "banned-import",
			args:     []string{"--build-tags", "gate_negative"},
			copyTo:   copyOutsideTheTestTree,
			wantExit: 1,
			wantOutput: []string{
				"banned.go:5:8: import 'github.com/keycardlabs/gatefixture' is not allowed from list 'no-internal-keycard-modules'",
				"(depguard)",
			},
		},
		{
			name:     "import gate rejects a test fixture imported from a shipped file",
			script:   lintScript,
			fixture:  "banned-import",
			args:     []string{"--build-tags", "gate_negative"},
			copyTo:   copyOutsideTheTestTree,
			wantExit: 1,
			wantOutput: []string{
				"shipped.go:5:8: import 'github.com/keycardai/egress-proxy/test/fakeas' is not allowed " +
					"from list 'no-test-fixtures-in-shipped-code'",
				"(depguard)",
			},
		},
		{
			// Tests are exempt from banned package imports, since they are not
			// redistributed derivative works (binaries, images, etc).
			name:       "import gate allows a test fixture imported from a file under test/",
			script:     lintScript,
			fixture:    "banned-import",
			args:       []string{"--build-tags", "gate_negative"},
			copyTo:     copyOutsideTheTestTree,
			wantExit:   1,
			wantAbsent: []string{"allowed.go"},
		},
		{
			// depguard matches a files glob against the absolute path, so
			// a glob naming test/ would read the path the repository is
			// checked out under and turn the whole rule off. The exemption
			// is an exclusion rule on the module-relative path instead,
			// and this case is what holds it there: the same verdicts
			// under a path element named test as under none.
			name:     "import gate reads the path under the module root, not the path of the checkout",
			script:   lintScript,
			fixture:  "banned-import",
			args:     []string{"--build-tags", "gate_negative"},
			copyTo:   copyUnderATestPath,
			wantExit: 1,
			wantOutput: []string{
				"shipped.go:5:8: import 'github.com/keycardai/egress-proxy/test/fakeas' is not allowed " +
					"from list 'no-test-fixtures-in-shipped-code'",
				"(depguard)",
			},
			wantAbsent: []string{"allowed.go"},
		},
		{
			name:       "import gate passes the same module without the banned files",
			script:     lintScript,
			fixture:    "banned-import",
			copyTo:     copyOutsideTheTestTree,
			wantExit:   0,
			wantOutput: []string{"0 issues.", "lint: OK"},
		},
		{
			name:     "import gate lints the files behind the acceptance and images tags",
			script:   lintScript,
			fixture:  "tagged-import",
			wantExit: 1,
			wantOutput: []string{
				"images.go:5:8: import 'github.com/keycardlabs/gatefixture' is not allowed from list " +
					"'no-internal-keycard-modules'",
				"acceptance.go:5:8: import 'github.com/keycardlabs/gatefixture' is not allowed from list " +
					"'no-internal-keycard-modules'",
			},
		},
		{
			name:     "vulnerability gate rejects a reachable published vulnerability",
			script:   vulnScript,
			fixture:  "vulnerable-module",
			wantExit: 3,
			wantOutput: []string{
				"Vulnerability #1: GO-2022-1059",
				"Found in: golang.org/x/text@v0.3.7",
				"vulnerable.main calls language.ParseAcceptLanguage",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Each case runs a tool over its own fixture module. The go build
			// cache and the tool caches are safe for concurrent use.
			t.Parallel()
			script := filepath.Join(repoRoot, "scripts", tt.script)
			fixture := filepath.Join("testdata", tt.fixture)
			if tt.copyTo != nil {
				fixture = tt.copyTo(t, fixture)
			}
			args := append([]string{script, fixture}, tt.args...)
			if tt.script == lintScript {
				// golangci-lint holds a lock for the whole run and refuses a
				// second one while it is held. The lint cases start together,
				// so each waits for the lock instead.
				args = append(args, "--allow-serial-runners")
			}
			cmd := exec.CommandContext(t.Context(), "bash", args...)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			err := cmd.Run()

			exit := 0
			var exitErr *exec.ExitError
			switch {
			case err == nil:
			case errors.As(err, &exitErr):
				exit = exitErr.ExitCode()
			default:
				require.NoError(t, err, "running %s\n%s", tt.script, out.String())
			}
			assert.Equal(t, tt.wantExit, exit, "%s exit status\n%s", tt.script, out.String())
			for _, want := range tt.wantOutput {
				assert.Contains(t, out.String(), want, "%s output", tt.script)
			}
			for _, absent := range tt.wantAbsent {
				assert.NotContains(t, out.String(), absent, "%s output", tt.script)
			}
		})
	}
}

// copyOutsideTheTestTree copies a fixture module to a temporary directory
// and returns the copy. It fails the test when any element of that path is
// named test, so that it and copyUnderATestPath are the two halves of the
// same question and no run collapses them into one.
func copyOutsideTheTestTree(t *testing.T, fixture string) string {
	t.Helper()
	destination := filepath.Join(t.TempDir(), filepath.Base(fixture))
	require.False(t, slices.Contains(strings.Split(destination, string(filepath.Separator)), "test"),
		"the copy is under a directory named test, where the import gate exempts it: %s", destination)
	require.NoError(t, os.CopyFS(destination, os.DirFS(fixture)), "copy %s", fixture)
	return destination
}

// copyUnderATestPath copies a fixture module to a temporary directory that
// has an element named test above the module root, and returns the copy.
// The import gate reads the path under the module root, so the element
// above it changes no verdict.
func copyUnderATestPath(t *testing.T, fixture string) string {
	t.Helper()
	destination := filepath.Join(t.TempDir(), "test", filepath.Base(fixture))
	require.NoError(t, os.CopyFS(destination, os.DirFS(fixture)), "copy %s", fixture)
	return destination
}
