// Package gates proves that each CI gate rejects what it exists to reject.
// Every gate script under scripts/ accepts a module directory, and each case
// points a script at a fixture module under testdata that must fail it, with
// the message a developer would see. A control case per gate shows the gate
// passes the same fixture once the offending input is removed, so a gate that
// fails everything cannot pass this test.
package gates_test

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot is the repository root relative to this package directory.
const repoRoot = "../.."

// The gate scripts under scripts/.
const (
	lintScript     = "lint.sh"
	licensesScript = "check-licenses.sh"
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
		// args are passed to the gate after the directory.
		args []string
		// wantExit is the exit code the gate must return. Every gate exits
		// 0 when it passes; govulncheck exits 3 on a finding and
		// golangci-lint and go-licenses exit 1.
		wantExit int
		// wantOutput are substrings that must all appear in the combined
		// output, naming the offending module and the gate that caught it.
		wantOutput []string
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
			name:       "import gate passes the same module without the banned file",
			script:     lintScript,
			fixture:    "banned-import",
			wantExit:   0,
			wantOutput: []string{"0 issues.", "lint: OK"},
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
			// Each case runs a tool over its own fixture module; the go build
			// cache and the tool caches are safe for concurrent use.
			t.Parallel()
			script := filepath.Join(repoRoot, "scripts", tt.script)
			fixture := filepath.Join("testdata", tt.fixture)
			args := append([]string{script, fixture}, tt.args...)
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
				t.Fatalf("running %s: %v\n%s", tt.script, err, out.String())
			}
			if exit != tt.wantExit {
				t.Errorf("%s exited %d, want %d\n%s", tt.script, exit, tt.wantExit, out.String())
			}
			for _, want := range tt.wantOutput {
				if !strings.Contains(out.String(), want) {
					t.Errorf("%s output lacks %q\n%s", tt.script, want, out.String())
				}
			}
		})
	}
}
