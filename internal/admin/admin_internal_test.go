package admin

import (
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunReturnsTheServeFailure covers the arm of Run that wraps a Serve
// error. Closing the listener is the only way to make Serve fail, and the
// Server does not export it, so this case lives inside the package.
func TestRunReturnsTheServeFailure(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "admin.sock")
	server, err := New(t.Context(), Options{Path: path, Info: func() any { return nil }})
	require.NoError(t, err, "New")

	require.NoError(t, server.listener.Close(), "close the listener out from under Serve")
	err = server.Run(t.Context())
	require.Error(t, err, "Run over a closed listener")
	require.ErrorIs(t, err, net.ErrClosed, "the failure names the closed listener")
	assert.ErrorContains(t, err, "admin: serve", "the failure says where it came from")
}

// TestCheckDirMode covers the refusal on its own. prepareDir chmods the
// directory before it checks, and a chmod a non-root process cannot make fail
// is not something a test can arrange.
func TestCheckDirMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mode    fs.FileMode
		wantErr string
	}{
		{name: "the proxy uid alone", mode: 0o700},
		{name: "group readable", mode: 0o750, wantErr: "has mode 0750 and must have mode 0700"},
		{name: "world writable", mode: 0o777, wantErr: "has mode 0777 and must have mode 0700"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			require.NoError(t, os.Chmod(dir, tc.mode), "prepare the fixture directory")
			err := checkDirMode(dir)
			if tc.wantErr == "" {
				require.NoError(t, err, "checkDirMode on a directory with mode %#o", tc.mode)
				return
			}
			require.ErrorIs(t, err, errSocketPath, "checkDirMode on a directory with mode %#o", tc.mode)
			require.ErrorContains(t, err, tc.wantErr, "the failure names both modes")
			assert.ErrorContains(t, err, dir, "the failure names the directory")
		})
	}
}

func TestCheckDirModeOnAMissingDirectory(t *testing.T) {
	t.Parallel()
	err := checkDirMode(filepath.Join(t.TempDir(), "absent"))
	require.ErrorIs(t, err, fs.ErrNotExist, "checkDirMode on a directory that is not there")
	assert.ErrorContains(t, err, "admin: stat", "the failure says where it came from")
}
