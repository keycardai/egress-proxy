// Package gates proves that each CI gate rejects what it exists to reject.
// Each case points a gate script at a fixture module under testdata that
// must fail it, and asserts the message a developer sees. Every script this
// test runs takes that directory as its first argument.
//
// The lint gate also has a control case: the same fixture passes without the
// gate_negative build tag, which leaves the offending file out of the build.
// A gate that failed everything could not pass that case.
package gates_test

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
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
			wantExit: 1,
			wantOutput: []string{
				"banned.go:5:8: import 'github.com/keycardlabs/gatefixture' is not allowed from list 'no-internal-keycard-modules'",
				"(depguard)",
			},
		},
		{
			name:     "import gate rejects a test fixture imported from a non-test file",
			script:   lintScript,
			fixture:  "banned-import",
			args:     []string{"--build-tags", "gate_negative"},
			wantExit: 1,
			wantOutput: []string{
				"shipped.go:5:8: import 'github.com/keycardai/egress-proxy/test/fakeas' is not allowed " +
					"from list 'no-test-fixtures-in-shipped-code'",
				"(depguard)",
			},
		},
		{
			name:       "import gate passes the same module without the banned files",
			script:     lintScript,
			fixture:    "banned-import",
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
