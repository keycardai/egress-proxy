package credential_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/credential"
)

const staticFile = "version: 1\ncredentials:\n" +
	"  - resource: https://api.github.com/\n    value: " + secret + "\n" +
	"  - resource: https://maps.example/\n    value: maps-key\n"

// write puts body in a file the loader accepts by mode.
func write(t *testing.T, body string, mode fs.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), mode), "write the credential file")
	// Set the mode again because WriteFile applies the process umask.
	require.NoError(t, os.Chmod(path, mode), "chmod the credential file")
	return path
}

func TestStaticFileAnswersByResource(t *testing.T) {
	t.Parallel()
	source, err := credential.LoadStaticFile(write(t, staticFile, 0o600))
	require.NoError(t, err, "LoadStaticFile")
	tests := []struct {
		name     string
		resource string
		want     string
		wantErr  error
	}{
		{name: "a resource the file names", resource: "https://api.github.com/", want: secret},
		{name: "another resource the file names", resource: "https://maps.example/", want: "maps-key"},
		{name: "a resource the file omits", resource: "https://pypi.org/", wantErr: credential.ErrUnavailable},
		{
			name: "a resource differing by its trailing slash", resource: "https://maps.example",
			wantErr: credential.ErrUnavailable,
		},
		{name: "no resource at all", resource: "", wantErr: credential.ErrUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := source.Credential(t.Context(), tc.resource)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr, "Credential")
				assert.Empty(t, got, "a refused lookup returns no credential")
				return
			}
			require.NoError(t, err, "Credential")
			assert.Equal(t, tc.want, got, "the credential for %s", tc.resource)
		})
	}
}

// TestStaticFileDescribeNamesTheFileAndNoCredential pins what the start-up
// announcement and the admin socket report.
func TestStaticFileDescribeNamesTheFileAndNoCredential(t *testing.T) {
	t.Parallel()
	path := write(t, staticFile, 0o600)
	source, err := credential.LoadStaticFile(path)
	require.NoError(t, err, "LoadStaticFile")
	description := source.Describe()
	assert.Contains(t, description, path, "the description names the file")
	assert.Contains(t, description, "2 credentials", "the description counts the credentials")
	assert.NotContains(t, description, secret, "the description carries a credential")
}

func TestLoadStaticFileRefusals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		mode    fs.FileMode
		wantErr string
	}{
		{
			name: "a file the group can read", body: staticFile, mode: 0o640,
			wantErr: "it has mode 0640",
		},
		{
			name: "a file anyone can read", body: staticFile, mode: 0o644,
			wantErr: "it has mode 0644",
		},
		{
			name: "a version this build does not read", mode: 0o600,
			body:    "version: 2\ncredentials:\n  - resource: https://a/\n    value: v\n",
			wantErr: "version is 2",
		},
		{
			name: "an unknown key", mode: 0o600,
			body:    "version: 1\ncredential:\n  - resource: https://a/\n    value: v\n",
			wantErr: `unknown field "credential"`,
		},
		{
			name: "an unknown key in an entry", mode: 0o600,
			body:    "version: 1\ncredentials:\n  - resource: https://a/\n    token: v\n",
			wantErr: `unknown field "token"`,
		},
		{
			name: "top-level keys that differ only in case", mode: 0o600,
			body: "version: 1\ncredentials:\n  - resource: https://a/\n    value: one\n" +
				"CREDENTIALS:\n  - resource: https://b/\n    value: two\n",
			wantErr: "keys that differ only in case",
		},
		{
			name: "entry keys that differ only in case", mode: 0o600,
			body: "version: 1\ncredentials:\n  - resource: https://a/\n" +
				"    RESOURCE: https://b/\n    value: one\n",
			wantErr: "keys that differ only in case",
		},
		{
			name: "a second YAML document", mode: 0o600,
			body: "version: 1\ncredentials:\n  - resource: https://a/\n    value: one\n" +
				"---\nversion: 1\ncredentials:\n  - resource: https://b/\n    value: two\n",
			wantErr: "more than one YAML document",
		},
		{name: "no credentials at all", body: "version: 1\n", mode: 0o600, wantErr: "credentials is empty"},
		{
			name: "an entry without a resource", mode: 0o600,
			body:    "version: 1\ncredentials:\n  - value: v\n",
			wantErr: "credentials[0]: resource is empty",
		},
		{
			name: "an entry without a value", mode: 0o600,
			body:    "version: 1\ncredentials:\n  - resource: https://a/\n",
			wantErr: "credentials[0]: resource \"https://a/\": invalid credential: empty value",
		},
		{
			name: "a credential that would split the request head", mode: 0o600,
			body:    "version: 1\ncredentials:\n  - resource: https://a/\n    value: \"one\\r\\ntwo\"\n",
			wantErr: "invalid character",
		},
		{
			name: "a resource named twice", mode: 0o600,
			body: "version: 1\ncredentials:\n  - resource: https://a/\n    value: one\n" +
				"  - resource: https://a/\n    value: two\n",
			wantErr: `credentials[1]: resource "https://a/" repeats an earlier entry`,
		},
		{
			name: "a document that is not a mapping", body: "- just a list\n", mode: 0o600,
			wantErr: "invalid credential file",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := write(t, tc.body, tc.mode)
			source, err := credential.LoadStaticFile(path)
			require.ErrorContains(t, err, tc.wantErr, "LoadStaticFile")
			assert.Nil(t, source, "a refused file yields no source")
			assert.NotContains(t, err.Error(), secret, "the message quotes a credential")
		})
	}
}

func TestLoadStaticFileRefusesWhatIsNotAReadableFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{name: "a missing file", path: filepath.Join(dir, "missing.yaml"), wantErr: "no such file"},
		{name: "a directory", path: dir, wantErr: "it is not a regular file"},
		{
			name:    "a file larger than the loader reads",
			path:    write(t, "version: 1\n# "+strings.Repeat("x", 1<<20)+"\n", 0o600),
			wantErr: "it is larger than 1048576 bytes",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := credential.LoadStaticFile(tc.path)
			require.ErrorContains(t, err, tc.wantErr, "LoadStaticFile")
		})
	}
}
