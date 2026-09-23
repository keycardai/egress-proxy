//go:build unix

package ca_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/ca"
)

// TestOutputDirectoryIsReadableByTheWorkload pins the mode of the output
// directory for every way the proxy creates it, under the umask a hardened
// base image sets and over a directory the container runtime already mounted.
//
//nolint:paralleltest // The umask is process state, so this test runs alone.
func TestOutputDirectoryIsReadableByTheWorkload(t *testing.T) {
	restore := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(restore) })

	entryPoints := []struct {
		name string
		call func(t *testing.T, outDir string)
	}{
		{
			name: "PrepareDirectories",
			call: func(t *testing.T, outDir string) {
				t.Helper()
				stateDir := filepath.Join(t.TempDir(), "state")
				require.NoError(t, ca.PrepareDirectories(stateDir, outDir), "PrepareDirectories")
			},
		},
		{
			name: "WriteCertificate",
			call: func(t *testing.T, outDir string) {
				t.Helper()
				_, err := newAuthority(t, ca.Options{}).WriteCertificate(outDir)
				require.NoError(t, err, "WriteCertificate")
			},
		},
	}
	// mode zero leaves the directory absent, so the call creates it.
	cases := []struct {
		name string
		mode os.FileMode
	}{
		{name: "absent"},
		{name: "mounted too restrictive", mode: 0o700},
		{name: "mounted too permissive", mode: 0o777},
	}
	for _, entry := range entryPoints {
		for _, tc := range cases {
			t.Run(entry.name+"/"+tc.name, func(t *testing.T) {
				outDir := filepath.Join(t.TempDir(), "shared-ca")
				if tc.mode != 0 {
					require.NoError(t, os.Mkdir(outDir, tc.mode))
					require.NoError(t, os.Chmod(outDir, tc.mode), "Mkdir subtracts the umask")
				}
				entry.call(t, outDir)
				info, err := os.Stat(outDir)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0o755), info.Mode().Perm(),
					"mode, so the workload's uid can read the certificate out of the directory")
			})
		}
	}
}
