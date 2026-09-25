//go:build linux

package netsetup_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// TestContainmentReadsThisProcess runs the check with real capability, sysctl,
// namespace, and owner reads. The receipt names this process's uid and
// network namespace, so those reads pass only when they match an
// unprivileged sidecar. The sysctl
// has the host's value. The kernel default passes, and Docker's 0 must fail.
func TestContainmentReadsThisProcess(t *testing.T) {
	t.Parallel()
	uid := os.Getuid()
	require.NotZero(t, uid, "do not run the tests as root. The check refuses a ruleset that exempts uid 0, "+
		"so this test cannot pass as root")
	start, err := netsetup.UnprivilegedPortStart()
	require.NoError(t, err, "read the sysctl")
	namespace, err := netsetup.CurrentNetNamespace()
	require.NoError(t, err, "read the network namespace")
	receipt := contained()
	receipt.ProxyUID = uid
	receipt.NetNamespace = &namespace
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
		assert.NotContains(t, err.Error(), "network namespace", "the receipt names this process's namespace")
		return
	}
	require.NoError(t, err, "an unprivileged process owning its receipt, under a port start above the redirect port")
	assert.Equal(t, receipt, got, "the receipt the check passed")
}

// TestNetNamespaceAt reads real namespace links. readlink on the link gives
// net:[inode] (namespaces(7)), which is a second source for the inode.
func TestNetNamespaceAt(t *testing.T) {
	t.Parallel()
	link, err := os.Readlink("/proc/self/ns/net")
	require.NoError(t, err, "read the namespace link")
	var inode uint64
	_, err = fmt.Sscanf(link, "net:[%d]", &inode)
	require.NoError(t, err, "the link names the namespace inode: %q", link)
	current, err := netsetup.CurrentNetNamespace()
	require.NoError(t, err, "read this process's namespace")
	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		{name: "this process by its self link", path: "/proc/self/ns/net"},
		{name: "this process by its pid", path: fmt.Sprintf("/proc/%d/ns/net", os.Getpid())},
		{name: "a namespace link that does not exist", path: "/proc/self/ns/none", wantErr: fs.ErrNotExist},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := netsetup.NetNamespaceAt(tc.path)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr, "the error the caller keys on")
				return
			}
			require.NoError(t, err, "stat the namespace link")
			assert.Equal(t, inode, got.Inode, "the inode readlink names")
			assert.NotZero(t, got.Device, "the nsfs device")
			assert.Equal(t, current, got, "the namespace CurrentNetNamespace reads")
		})
	}
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
