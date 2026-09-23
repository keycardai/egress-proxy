package credential_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/credential"
)

// TestReadSecretFile reads a file that holds one secret and nothing else,
// with the surrounding whitespace an editor leaves removed.
func TestReadSecretFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("  s3cr3t\n"), 0o600), "write the secret file")

	secret, err := credential.ReadSecretFile(path)
	require.NoError(t, err, "ReadSecretFile")
	assert.Equal(t, "s3cr3t", secret, "the secret without its surrounding whitespace")
}

// TestReadSecretFileRefusals covers every file the proxy will not take a
// secret from. Each one stops the process, because a secret it cannot read
// safely is one it must not offer to the zone.
func TestReadSecretFileRefusals(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	group := filepath.Join(dir, "group-readable")
	require.NoError(t, os.WriteFile(group, []byte("s3cr3t"), 0o640), "write the group-readable file")
	empty := filepath.Join(dir, "empty")
	require.NoError(t, os.WriteFile(empty, []byte("\n  \n"), 0o600), "write the empty file")
	control := filepath.Join(dir, "control")
	require.NoError(t, os.WriteFile(control, []byte("s3c\rr3t"), 0o600), "write the file with a control character")
	large := filepath.Join(dir, "large")
	require.NoError(t, os.WriteFile(large, []byte(strings.Repeat("x", 1<<20+1)), 0o600), "write the large file")

	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{name: "a file that is not there", path: filepath.Join(dir, "absent"), wantErr: "no such file"},
		{name: "a directory", path: dir, wantErr: "it is not a regular file"},
		{name: "a file another user can read", path: group, wantErr: "readable by its owner alone"},
		{name: "a file larger than the reader reads", path: large, wantErr: "it is larger than 1048576 bytes"},
		{name: "a file holding no secret", path: empty, wantErr: "empty value"},
		{name: "a secret holding a control character", path: control, wantErr: "contains an invalid character"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			secret, err := credential.ReadSecretFile(tc.path)
			require.Error(t, err, "ReadSecretFile must refuse this file")
			require.ErrorContains(t, err, tc.wantErr, "the message names the problem")
			assert.Empty(t, secret, "a refused file yields no secret")
			assert.NotContains(t, err.Error(), "s3c", "the message NEVER quotes the contents")
		})
	}
}
