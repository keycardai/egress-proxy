package credential_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/credential"
)

// TestReadSecretFile reads one secret and removes surrounding whitespace.
func TestReadSecretFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("  s3cr3t\n"), 0o600), "write the secret file")

	secret, err := credential.ReadSecretFile(path)
	require.NoError(t, err, "ReadSecretFile")
	assert.Equal(t, "s3cr3t", secret, "the secret without its surrounding whitespace")
}

// errTokenFileKind stands in for the caller's sentinel, so a case can check
// that the check wraps what the caller named.
var errTokenFileKind = errors.New("invalid token file")

// TestCheckTokenFileRefusals checks the file conditions that the proxy rejects
// for a projected ServiceAccount token. The kubelet writes the token
// world-readable, so the permission rule that covers a secret file does not
// apply here.
func TestCheckTokenFileRefusals(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	group := filepath.Join(dir, "group-readable")
	require.NoError(t, os.WriteFile(group, []byte("token"), 0o644), "write the world-readable file")
	large := filepath.Join(dir, "large")
	require.NoError(t, os.WriteFile(large, []byte(strings.Repeat("x", 64<<10+1)), 0o600), "write the large file")
	// A bound token from a Kubernetes 1.34 cluster is about 1 KiB. The cap
	// must leave room for a longer audience list.
	realistic := filepath.Join(dir, "realistic")
	require.NoError(t, os.WriteFile(realistic, []byte(strings.Repeat("x", 4<<10)), 0o644), "write a token-sized file")
	fifo := filepath.Join(dir, "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o644), "make the FIFO")

	tests := []struct {
		name string
		path string
		// wantErr names the problem. Empty accepts the file.
		wantErr string
	}{
		{name: "a file that is not there", path: filepath.Join(dir, "absent"), wantErr: "no such file"},
		{name: "a directory", path: dir, wantErr: "it is not a regular file"},
		// A FIFO with no writer blocks os.ReadFile forever. The stat happens
		// before any read, so this case cannot hang.
		{name: "a FIFO", path: fifo, wantErr: "it is not a regular file"},
		{name: "a file larger than the reader reads", path: large, wantErr: "it is larger than 65536 bytes"},
		{name: "a token the kubelet wrote world-readable", path: group},
		{name: "a token with room to spare under the cap", path: realistic},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := credential.CheckTokenFile(errTokenFileKind, tc.path)
			if tc.wantErr == "" {
				require.NoError(t, err, "CheckTokenFile must accept this file")
				return
			}
			require.Error(t, err, "CheckTokenFile must refuse this file")
			require.ErrorIs(t, err, errTokenFileKind, "the error wraps the kind the caller named")
			require.ErrorContains(t, err, tc.wantErr, "the message names the problem")
		})
	}
}

// TestReadSecretFileRefusals checks every file condition that the proxy
// rejects. A secret that fails these checks never reaches the zone.
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
