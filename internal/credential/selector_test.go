package credential_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/credential"
)

const perSandboxFile = `version: 1
credentials:
  - resource: "https://api.github.com/"
    sandbox: keycard-demo
    value: demo-sekrit
  - resource: "https://api.github.com/"
    sandbox: troy-research
    value: research-sekrit
  - resource: "https://api.github.com/"
    application: review-agent
    value: review-sekrit
  - resource: "https://maps.example/"
    value: shared-maps-key
`

func writeStatic(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestStaticFileAnswersPerSandbox(t *testing.T) {
	t.Parallel()
	file, err := credential.LoadStaticFile(writeStatic(t, perSandboxFile))
	require.NoError(t, err)
	tests := map[string]struct {
		sandbox  string
		resource string
		want     string
		wantErr  error
	}{
		"the sandbox's own entry": {
			sandbox: "keycard-demo", resource: "https://api.github.com/", want: "demo-sekrit",
		},
		"another sandbox's own entry": {
			sandbox: "troy-research", resource: "https://api.github.com/", want: "research-sekrit",
		},
		"a shared entry": {
			sandbox: "keycard-demo", resource: "https://maps.example/", want: "shared-maps-key",
		},
		"a sandbox with no entry": {
			sandbox: "pierce", resource: "https://api.github.com/", wantErr: credential.ErrUnavailable,
		},
		"a resource nobody holds": {
			sandbox: "keycard-demo", resource: "https://pypi.org/", wantErr: credential.ErrUnavailable,
		},
		"the shared view never sees a sandbox entry": {
			sandbox: "", resource: "https://api.github.com/", wantErr: credential.ErrUnavailable,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var source credential.Source = file
			if tc.sandbox != "" {
				source = file.ForSandbox(tc.sandbox)
			}
			got, err := source.Credential(t.Context(), tc.resource)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
	assert.Contains(t, file.ForSandbox("keycard-demo").Describe(), "keycard-demo", "the view names its sandbox")
	assert.NotContains(t, file.ForSandbox("keycard-demo").Describe(), "sekrit")
	assert.Equal(t, []string{"keycard-demo", "troy-research"}, file.Sandboxes(), "the sandboxes the file names")
}

// TestStaticFileAnswersPerApplication pins the application view: its own
// entries first, then the shared ones, and never a sandbox's.
func TestStaticFileAnswersPerApplication(t *testing.T) {
	t.Parallel()
	file, err := credential.LoadStaticFile(writeStatic(t, perSandboxFile))
	require.NoError(t, err)
	tests := map[string]struct {
		application string
		resource    string
		want        string
		wantErr     error
	}{
		"the application's own entry": {
			application: "review-agent", resource: "https://api.github.com/", want: "review-sekrit",
		},
		"a shared entry": {
			application: "review-agent", resource: "https://maps.example/", want: "shared-maps-key",
		},
		"an application with no entry reads the shared ones": {
			application: "research-agent", resource: "https://maps.example/", want: "shared-maps-key",
		},
		"an application with no entry never reads a sandbox's": {
			application: "research-agent", resource: "https://api.github.com/", wantErr: credential.ErrUnavailable,
		},
		"a resource nobody holds": {
			application: "review-agent", resource: "https://pypi.org/", wantErr: credential.ErrUnavailable,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, readErr := file.ForApplication(tc.application).Credential(t.Context(), tc.resource)
			if tc.wantErr != nil {
				require.ErrorIs(t, readErr, tc.wantErr)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, readErr)
			assert.Equal(t, tc.want, got)
		})
	}
	description := file.ForApplication("review-agent").Describe()
	assert.Contains(t, description, "application review-agent", "the view names its application")
	assert.NotContains(t, description, "sekrit")
	assert.Equal(t, []string{"review-agent"}, file.Applications(), "the applications the file names")
	_, err = file.ForSandbox("review-agent").Credential(t.Context(), "https://api.github.com/")
	require.ErrorIs(t, err, credential.ErrUnavailable, "a sandbox view never reads an application entry")
}

func TestLoadStaticFileRefusesScopeMisuse(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		body    string
		wantErr string
	}{
		"a repeated sandbox resource": {
			body: "  - resource: \"https://api.github.com/\"\n    sandbox: keycard-demo\n    value: a\n" +
				"  - resource: \"https://api.github.com/\"\n    sandbox: keycard-demo\n    value: b\n",
			wantErr: `repeats an earlier entry for sandbox "keycard-demo"`,
		},
		"a repeated application resource": {
			body: "  - resource: \"https://api.github.com/\"\n    application: review-agent\n    value: a\n" +
				"  - resource: \"https://api.github.com/\"\n    application: review-agent\n    value: b\n",
			wantErr: `repeats an earlier entry for application "review-agent"`,
		},
		"an entry naming both a sandbox and an application": {
			body: "  - resource: \"https://api.github.com/\"\n    sandbox: keycard-demo\n" +
				"    application: review-agent\n    value: a\n",
			wantErr: `credentials[0]: sandbox "keycard-demo" and application "review-agent" both scope the entry; set one`,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := credential.LoadStaticFile(writeStatic(t, "version: 1\ncredentials:\n"+tc.body))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestSelector(t *testing.T) {
	t.Parallel()
	file, err := credential.LoadStaticFile(writeStatic(t, perSandboxFile))
	require.NoError(t, err)
	selector := credential.NewSelector()
	demo := credential.SandboxKey{Name: "keycard-demo", Workspace: "default"}
	require.NoError(t, selector.Add(demo, credential.Selected{Source: file.ForSandbox("keycard-demo")}))
	require.NoError(t, selector.Add(credential.SandboxKey{Name: "keycard-demo", Workspace: "study-group"},
		credential.Selected{Source: file.ForSandbox("troy-research"), ClientID: "research-app"}))

	err = selector.Add(demo, credential.Selected{Source: file})
	require.Error(t, err, "a repeated key is refused")

	got, ok := selector.Select(demo)
	require.True(t, ok)
	value, err := got.Source.Credential(t.Context(), "https://api.github.com/")
	require.NoError(t, err)
	assert.Equal(t, "demo-sekrit", value)

	got, ok = selector.Select(credential.SandboxKey{Name: "keycard-demo", Workspace: "study-group"})
	require.True(t, ok, "the same name in another workspace is another entry")
	assert.Equal(t, "research-app", got.ClientID)

	_, ok = selector.Select(credential.SandboxKey{Name: "pierce", Workspace: "default"})
	assert.False(t, ok)
	assert.Equal(t, "2 sandbox identities selected by assertion", selector.Describe())
}

// TestSelectorDescribe pins the start-up announcement: a map with nothing in
// it is left out, so a proxy that serves sandboxes alone never mentions
// applications.
func TestSelectorDescribe(t *testing.T) {
	t.Parallel()
	file, err := credential.LoadStaticFile(writeStatic(t, perSandboxFile))
	require.NoError(t, err)
	tests := map[string]struct {
		sandboxes    []string
		applications []string
		// asSandbox names the applications that exchange as the asserted
		// sandbox, and forOwner those among them that exchange for its
		// owner.
		asSandbox []string
		forOwner  []string
		want      string
	}{
		"nothing mapped": {
			want: "no identities selected by assertion",
		},
		"applications exchanged as the sandbox": {
			applications: []string{"review-agent", "research-agent"},
			asSandbox:    []string{"review-agent"},
			want:         "2 application identities selected by assertion, 1 exchanged as the sandbox",
		},
		"applications exchanged for the sandbox owner": {
			applications: []string{"review-agent", "research-agent"},
			asSandbox:    []string{"review-agent", "research-agent"},
			forOwner:     []string{"review-agent"},
			want: "2 application identities selected by assertion, 2 exchanged as the sandbox, " +
				"1 of them for the sandbox owner",
		},
		"sandboxes alone": {
			sandboxes: []string{"keycard-demo", "troy-research"},
			want:      "2 sandbox identities selected by assertion",
		},
		"applications alone": {
			applications: []string{"review-agent", "research-agent"},
			want:         "2 application identities selected by assertion",
		},
		"both": {
			sandboxes:    []string{"keycard-demo"},
			applications: []string{"review-agent", "research-agent"},
			want:         "2 application and 1 sandbox identities selected by assertion",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)
			selector := credential.NewSelector()
			for _, sandbox := range tc.sandboxes {
				key := credential.SandboxKey{Name: sandbox, Workspace: "default"}
				r.NoError(selector.Add(key, credential.Selected{Source: file.ForSandbox(sandbox)}))
			}
			for _, application := range tc.applications {
				selected := credential.Selected{
					Source:            file.ForApplication(application),
					SubjectIsClient:   slices.Contains(tc.asSandbox, application),
					ImpersonatesOwner: slices.Contains(tc.forOwner, application),
				}
				r.NoError(selector.AddApplication(application, selected))
			}
			assert.Equal(t, tc.want, selector.Describe())
		})
	}
}

// TestSelectorApplications pins that applications are their own map: a
// name in one never answers for the other, and a repeated name is refused.
func TestSelectorApplications(t *testing.T) {
	t.Parallel()
	file, err := credential.LoadStaticFile(writeStatic(t, perSandboxFile))
	require.NoError(t, err)
	selector := credential.NewSelector()
	require.NoError(t, selector.AddApplication("review-agent",
		credential.Selected{Source: file.ForApplication("review-agent"), ClientID: "review-app"}))
	require.NoError(t, selector.Add(credential.SandboxKey{Name: "review-agent", Workspace: "default"},
		credential.Selected{Source: file.ForSandbox("keycard-demo")}),
		"a sandbox may carry an application's name")

	err = selector.AddApplication("review-agent", credential.Selected{Source: file})
	require.Error(t, err, "a repeated application is refused")
	err = selector.AddApplication("research-agent", credential.Selected{})
	require.Error(t, err, "an application without a source is refused")

	got, ok := selector.SelectApplication("review-agent")
	require.True(t, ok)
	assert.Equal(t, "review-app", got.ClientID)
	value, err := got.Source.Credential(t.Context(), "https://api.github.com/")
	require.NoError(t, err)
	assert.Equal(t, "review-sekrit", value)

	_, ok = selector.SelectApplication("research-agent")
	assert.False(t, ok)
	assert.Equal(t, "1 application and 1 sandbox identities selected by assertion", selector.Describe())
}
