package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/config"
	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/policy"
)

// TestStaticSourcesRefusals pins the static-mode misconfigurations the
// document parser cannot see, because they need the credential file: a name
// repeated across workspaces, which a file selecting by name cannot tell
// apart, an entry for a sandbox the document does not map, which would
// silently fall back to the shared credential, and a scoped entry in a
// document that maps nothing, which no request could ever select. An empty
// sandboxes field leaves sandbox_assertion and sandboxes out of the document.
func TestStaticSourcesRefusals(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		sandboxes string
		file      string
		wantErr   string
	}{
		"a scoped entry with no sandboxes and no applications": {
			file: "  - resource: \"https://api.github.com/\"\n    sandbox: troy-research\n    value: a\n" +
				"  - resource: \"https://maps.example/\"\n    application: review-agent\n    value: b\n" +
				"  - resource: \"https://pypi.org/\"\n    value: c\n",
			wantErr: "2 entries are scoped to a sandbox or application, " +
				"which needs sandbox_assertion and sandboxes or applications in the document",
		},
		"a name repeated across workspaces": {
			sandboxes: "  - name: agent\n  - name: agent\n    workspace: study-group\n",
			file:      "  - resource: \"https://api.github.com/\"\n    sandbox: agent\n    value: a\n",
			wantErr:   `sandbox name "agent" repeats across workspaces`,
		},
		"an entry for a sandbox the document does not name": {
			sandboxes: "  - name: troy-research\n",
			file:      "  - resource: \"https://api.github.com/\"\n    sandbox: troy-reserch\n    value: a\n",
			wantErr:   `entries for sandbox "troy-reserch", which sandboxes does not name`,
		},
		"an entry for an application the document does not name": {
			sandboxes: "  - name: troy-research\n",
			file:      "  - resource: \"https://api.github.com/\"\n    application: review-agent\n    value: a\n",
			wantErr:   `entries for application "review-agent", which applications does not name`,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "credentials.yaml")
			require.NoError(t, os.WriteFile(path, []byte("version: 1\ncredentials:\n"+tc.file), 0o600))
			doc := "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - url: https://api.github.com/\n" +
				"credentials:\n  static_file: " + path + "\n"
			if tc.sandboxes != "" {
				doc += "sandbox_assertion:\n  issuer_key_file: /k.pub\nsandboxes:\n" + tc.sandboxes
			}
			cfg, err := config.Parse([]byte(doc), config.Overrides{})
			require.NoError(t, err, "Parse:\n%s", doc)
			_, _, err = staticSources(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestStaticSourcesMapsEachSandbox pins the happy path: one view per mapped
// sandbox, and no process-level source.
func TestStaticSourcesMapsEachSandbox(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	file := "version: 1\ncredentials:\n" +
		"  - resource: \"https://api.github.com/\"\n    sandbox: keycard-demo\n    value: a\n" +
		"  - resource: \"https://api.github.com/\"\n    sandbox: troy-research\n    value: b\n"
	require.NoError(t, os.WriteFile(path, []byte(file), 0o600))
	doc := "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - url: https://api.github.com/\n" +
		"credentials:\n  static_file: " + path + "\n" +
		"sandbox_assertion:\n  issuer_key_file: /k.pub\nsandboxes:\n  - name: keycard-demo\n  - name: troy-research\n"
	cfg, err := config.Parse([]byte(doc), config.Overrides{})
	require.NoError(t, err)
	source, selector, err := staticSources(cfg)
	require.NoError(t, err)
	assert.Nil(t, source, "sandboxes replace the process source")
	assert.Equal(t, "2 sandbox identities selected by assertion", selector.Describe())
}

// TestStaticSourcesMapsEachApplication pins that applications get their own
// views beside the sandboxes, and an application with no entry of its own
// still maps, because it reads the shared entries.
func TestStaticSourcesMapsEachApplication(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	file := "version: 1\ncredentials:\n" +
		"  - resource: \"https://api.github.com/\"\n    sandbox: keycard-demo\n    value: a\n" +
		"  - resource: \"https://api.github.com/\"\n    application: review-agent\n    value: b\n" +
		"  - resource: \"https://maps.example/\"\n    value: c\n"
	require.NoError(t, os.WriteFile(path, []byte(file), 0o600))
	doc := "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - url: https://api.github.com/\n" +
		"credentials:\n  static_file: " + path + "\n" +
		"sandbox_assertion:\n  issuer_key_file: /k.pub\nsandboxes:\n  - name: keycard-demo\n" +
		"applications:\n  - name: review-agent\n  - name: research-agent\n"
	cfg, err := config.Parse([]byte(doc), config.Overrides{})
	require.NoError(t, err)
	source, selector, err := staticSources(cfg)
	require.NoError(t, err)
	assert.Nil(t, source, "the maps replace the process source")
	assert.Equal(t, "2 application and 1 sandbox identities selected by assertion", selector.Describe())
	review, ok := selector.SelectApplication("review-agent")
	require.True(t, ok)
	got, err := review.Source.Credential(t.Context(), "https://api.github.com/")
	require.NoError(t, err)
	assert.Equal(t, "b", got, "the application's own entry")
	research, ok := selector.SelectApplication("research-agent")
	require.True(t, ok)
	got, err = research.Source.Credential(t.Context(), "https://maps.example/")
	require.NoError(t, err)
	assert.Equal(t, "c", got, "the shared entry")
}

// TestExchangeSourcesMapsEachApplication pins that an application with an
// identity gets its own exchange, named by its client id on the record.
func TestExchangeSourcesMapsEachApplication(t *testing.T) {
	t.Parallel()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("sekrit"), 0o600))
	identity := "    identity:\n      zone_url: https://z.example\n      client_id: %s\n" +
		"      client_secret_file: " + secret + "\n      impersonate: {user: troy}\n"
	doc := "version: 1\nsandbox:\n  id: sbx-1\nendpoints:\n  - url: https://api.github.com/\n" +
		"sandbox_assertion:\n  issuer_key_file: /k.pub\n" +
		"sandboxes:\n  - name: keycard-demo\n" + fmt.Sprintf(identity, "demo") +
		"applications:\n  - name: review-agent\n" + fmt.Sprintf(identity, "review") +
		"  - name: research-agent\n" + fmt.Sprintf(identity, "research")
	cfg, err := config.Parse([]byte(doc), config.Overrides{})
	require.NoError(t, err)
	deny, err := policy.NewDenyList(nil, nil)
	require.NoError(t, err)
	source, selector, err := exchangeSources(cfg, deny, nil)
	require.NoError(t, err)
	assert.Nil(t, source, "the maps replace the process source")
	assert.Equal(t, "2 application and 1 sandbox identities selected by assertion", selector.Describe())
	review, ok := selector.SelectApplication("review-agent")
	require.True(t, ok)
	assert.Equal(t, "review", review.ClientID)
	demo, ok := selector.Select(credential.SandboxKey{Name: "keycard-demo", Workspace: "default"})
	require.True(t, ok)
	assert.Equal(t, "demo", demo.ClientID)
}
