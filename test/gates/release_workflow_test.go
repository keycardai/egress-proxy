package gates_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// The workflow fields the release properties read.
type workflow struct {
	Jobs map[string]workflowJob `json:"jobs"`
}

type workflowJob struct {
	Needs       any               `json:"needs"`
	Permissions map[string]string `json:"permissions"`
	Outputs     map[string]string `json:"outputs"`
	Steps       []workflowStep    `json:"steps"`
}

type workflowStep struct {
	ID   string            `json:"id"`
	Uses string            `json:"uses"`
	If   string            `json:"if"`
	Env  map[string]string `json:"env"`
	With map[string]any    `json:"with"`
	Run  string            `json:"run"`
}

func usesAction(name string) func(workflowStep) bool {
	return func(s workflowStep) bool { return strings.HasPrefix(s.Uses, name+"@") }
}

func hasID(id string) func(workflowStep) bool {
	return func(s workflowStep) bool { return s.ID == id }
}

// TestReleaseWorkflow pins the properties of release.yml that keep the
// published and signed images on github.sha, the commit whose gates passed.
// docs/security-model.md names this test as the mitigation's test.
func TestReleaseWorkflow(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "release.yml"))
	require.NoError(t, err)
	var wf workflow
	require.NoError(t, yaml.Unmarshal(raw, &wf))

	tests := []struct {
		name  string
		check func(t *testing.T, wf workflow)
	}{
		{
			name: "publish checks out github.sha and no other ref",
			check: func(t *testing.T, wf workflow) {
				t.Helper()
				var refs []any
				for _, s := range wf.Jobs["publish"].Steps {
					if usesAction("actions/checkout")(s) {
						refs = append(refs, s.With["ref"])
					}
				}
				assert.Equal(t, []any{"${{ github.sha }}"}, refs,
					"publish must have one checkout, of github.sha")
			},
		},
		{
			name: "the release commit guard runs before the registry login",
			check: func(t *testing.T, wf workflow) {
				t.Helper()
				steps := wf.Jobs["publish"].Steps
				guard := slices.IndexFunc(steps, hasID("release-commit-guard"))
				login := slices.IndexFunc(steps, usesAction("docker/login-action"))
				require.GreaterOrEqual(t, guard, 0, "publish has no release-commit-guard step")
				require.GreaterOrEqual(t, login, 0, "publish has no docker/login-action step")
				assert.Less(t, guard, login, "the guard must run before the registry login")

				g := steps[guard]
				assert.Equal(t, "env.RELEASE_CREATED == 'true'", g.If)
				assert.Equal(t, "${{ needs.release-please.outputs.sha }}", g.Env["RELEASE_SHA"])
				assert.Contains(t, g.Run, `if [ "$RELEASE_SHA" != "$GITHUB_SHA" ]; then`)
				assert.Contains(t, g.Run, "exit 1")
			},
		},
		{
			name: "release-please skips the release unless the check says false",
			check: func(t *testing.T, wf workflow) {
				t.Helper()
				rp := wf.Jobs["release-please"]
				assert.Equal(t, "release-commit", rp.Needs)
				i := slices.IndexFunc(rp.Steps, usesAction("googleapis/release-please-action"))
				require.GreaterOrEqual(t, i, 0, "release-please job has no release-please-action step")
				assert.Equal(t, "${{ needs.release-commit.outputs.skip != 'false' }}",
					rp.Steps[i].With["skip-github-release"])

				check := wf.Jobs["release-commit"]
				assert.Equal(t, "${{ steps.check.outputs.skip }}", check.Outputs["skip"])
				assert.GreaterOrEqual(t, slices.IndexFunc(check.Steps, hasID("check")), 0,
					"release-commit job has no step with id check")
			},
		},
		{
			name: "the release commit check holds a read-only token",
			check: func(t *testing.T, wf workflow) {
				t.Helper()
				assert.Equal(t, map[string]string{"contents": "read", "pull-requests": "read"},
					wf.Jobs["release-commit"].Permissions)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.check(t, wf)
		})
	}
}
