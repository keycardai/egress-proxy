//go:build linux

package netsetup_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// TestContainmentReadsThisProcess runs the check with the real capability
// read, sysctl read and file owner, which every TestContainment case
// supplies instead. The receipt names this process's own uid, so the
// capability and owner reads pass only if they answer the way an
// unprivileged sidecar's do. The sysctl is whatever the host set: the kernel
// default passes, and Docker's 0 must be refused.
func TestContainmentReadsThisProcess(t *testing.T) {
	t.Parallel()
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("the check refuses a ruleset that exempts uid 0, and this test runs as root")
	}
	start, err := netsetup.UnprivilegedPortStart()
	require.NoError(t, err, "read the sysctl")
	receipt := contained()
	receipt.ProxyUID = uid
	path := place(t, receipt)
	got, err := netsetup.Containment(netsetup.ContainmentRequest{
		Path:            path,
		TransparentPort: netsetup.DefaultRedirectPort,
		UID:             uid,
		Now:             now,
	})
	if start <= netsetup.DefaultRedirectPort {
		require.ErrorIs(t, err, netsetup.ErrNotContained, "a port start the workload can bind under")
		assert.Contains(t, err.Error(), "net.ipv4.ip_unprivileged_port_start is", "the one refusal")
		assert.NotContains(t, err.Error(), "CAP_NET_ADMIN", "this process holds no NET_ADMIN")
		assert.NotContains(t, err.Error(), "is owned by", "this process owns its receipt")
		return
	}
	require.NoError(t, err, "an unprivileged process owning its receipt, under a port start above the redirect port")
	assert.Equal(t, receipt, got, "the receipt the check passed")
}

func TestUnprivilegedPortStart(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		missing bool
		want    int
		wantErr error
	}{
		{name: "the kernel default", body: "1024\n", want: 1024},
		{name: "a runtime that lowered it to zero", body: "0\n", want: 0},
		{name: "a value that is not a number", body: "many\n", wantErr: netsetup.ErrPortStart},
		{name: "no sysctl at all", missing: true, wantErr: fs.ErrNotExist},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "ip_unprivileged_port_start")
			if !tc.missing {
				require.NoError(t, os.WriteFile(path, []byte(tc.body), 0o644))
			}
			got, err := netsetup.UnprivilegedPortStartAt(path)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr, "the error the caller keys on")
				return
			}
			require.NoError(t, err, "read the sysctl")
			assert.Equal(t, tc.want, got, "the port start")
		})
	}
}
