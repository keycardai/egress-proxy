package netsetup_test

import (
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// now is the clock the fixture receipt is dated against, so a case that
// turns on the receipt's age says so in its own edit.
//
//nolint:gochecknoglobals // a fixture the cases share
var now = time.Date(2026, time.September, 23, 12, 0, 0, 0, time.UTC)

// writeFile writes a fixture into the test's own directory and returns its
// path.
func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

// podNetwork is the network namespace the fixture receipt was written in and
// the fixture sidecar runs in.
func podNetwork() netsetup.NetNamespace {
	return netsetup.NetNamespace{Device: 4, Inode: 4026532288}
}

// contained is the receipt a sidecar starts on: the rules were applied,
// verified and then made unchangeable, in the sidecar's network namespace.
func contained() netsetup.Receipt {
	cfg := netsetup.DefaultConfig()
	cfg.DNSServers = valid().DNSServers
	programs := make([]netsetup.Program, 0, len(cfg.Families()))
	for _, family := range cfg.Families() {
		program, err := cfg.Program(family)
		if err != nil {
			panic(err)
		}
		programs = append(programs, program)
	}
	receipt := netsetup.NewReceipt(cfg, programs, true, now.Add(-time.Minute))
	receipt.CapabilitiesDropped = true
	namespace := podNetwork()
	receipt.NetNamespace = &namespace
	return receipt
}

// place writes a receipt at 0644 in a directory at 0755, which is what the
// init container leaves, and returns its path.
func place(t *testing.T, receipt netsetup.Receipt) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "egress")
	require.NoError(t, os.MkdirAll(dir, 0o755)) //nolint:gosec // G301: the sidecar traverses it as another uid
	path := filepath.Join(dir, "netsetup.json")
	require.NoError(t, netsetup.WriteReceipt(path, receipt))
	return path
}

// TestTheReceiptNamesTheResolversTheSidecarForwardsTo checks that the
// receipt records the cluster resolvers. The sidecar forwards to the
// resolvers the receipt names.
func TestTheReceiptNamesTheResolversTheSidecarForwardsTo(t *testing.T) {
	t.Parallel()
	cfg := netsetup.DefaultConfig()
	cfg.DNSServers = []netip.Addr{netip.MustParseAddr("10.43.0.10"), netip.MustParseAddr("fd00::a")}
	program, err := cfg.Program(netsetup.FamilyIPv4)
	require.NoError(t, err, "build the ruleset")
	written := netsetup.NewReceipt(cfg, []netsetup.Program{program}, true, now)

	read, err := netsetup.ReadReceipt(place(t, written))
	require.NoError(t, err, "read the receipt back")
	assert.Equal(t, []string{"10.43.0.10", "fd00::a"}, read.DNSServers, "the resolvers the sidecar forwards to")
	assert.Equal(t, netsetup.DefaultDNSPort, read.DNSPort, "the port the DNS redirect targets")
}

// TestRemoveReceiptLeavesNothingBehind proves the unlink a failed run
// depends on. A receipt an earlier run left says the rules are in force when
// they are not.
func TestRemoveReceiptLeavesNothingBehind(t *testing.T) {
	t.Parallel()
	path := place(t, contained())
	require.NoError(t, netsetup.RemoveReceipt(path), "remove the receipt")
	_, err := os.Stat(path)
	require.ErrorIs(t, err, fs.ErrNotExist, "the receipt is gone")
	require.NoError(t, netsetup.RemoveReceipt(path), "removing a receipt that is already gone is not a failure")
}

// wantReceiptJSON is the receipt the sidecar reads. The field names are the
// contract, so the whole document is pinned.
const wantReceiptJSON = `{
  "version": 1,
  "verified_at": "2026-09-23T12:00:00Z",
  "verified": true,
  "proxy_uid": 1337,
  "redirect_port": 1015,
  "capture_ports": [
    80,
    443
  ],
  "dns_port": 53,
  "dns_servers": [
    "10.43.0.10"
  ],
  "families": [
    "ipv4",
    "ipv6"
  ],
  "ruleset_digest": "sha256:0123",
  "capabilities_dropped": true,
  "net_namespace": {
    "device": 4,
    "inode": 4026532288
  }
}
`

// TestWriteReceipt pins the receipt's content and the modes it is written
// with. An existing file or directory keeps its mode, which the rows that
// start from one pin.
//
// It reads the umask, which is process-wide, so it does not run in
// parallel.
//
//nolint:paralleltest // it sets the process umask to read it
func TestWriteReceipt(t *testing.T) {
	umask := os.FileMode(syscall.Umask(0)) //nolint:gosec // G115: a umask is 0 to 0777
	syscall.Umask(int(umask))
	receipt := netsetup.Receipt{
		Version: 1, VerifiedAt: now, Verified: true, ProxyUID: 1337, RedirectPort: 1015,
		CapturePorts: []int{80, 443}, DNSPort: 53, DNSServers: []string{"10.43.0.10"},
		Families: []string{"ipv4", "ipv6"}, RulesetDigest: "sha256:0123", CapabilitiesDropped: true,
		NetNamespace: &netsetup.NetNamespace{Device: 4, Inode: 4026532288},
	}
	tests := []struct {
		name string
		// fileMode and dirMode are what exists before the write. Zero means
		// the path does not exist.
		fileMode, dirMode os.FileMode
		wantFile, wantDir os.FileMode
	}{
		{name: "a new receipt in a missing directory", wantFile: 0o644 &^ umask, wantDir: 0o755 &^ umask},
		{name: "an existing receipt keeps its mode", fileMode: 0o600, dirMode: 0o755, wantFile: 0o600, wantDir: 0o755},
		{
			name:    "an existing directory keeps its mode, as an emptyDir mount point at 0777 does",
			dirMode: 0o777, wantFile: 0o644 &^ umask, wantDir: 0o777,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "egress")
			path := filepath.Join(dir, "netsetup.json")
			if tc.dirMode != 0 {
				require.NoError(t, os.Mkdir(dir, 0o700))
				require.NoError(t, os.Chmod(dir, tc.dirMode))
			}
			if tc.fileMode != 0 {
				require.NoError(t, os.WriteFile(path, []byte("earlier"), tc.fileMode))
			}
			require.NoError(t, netsetup.WriteReceipt(path, receipt), "write the receipt")

			body, err := os.ReadFile(path)
			require.NoError(t, err, "read the receipt back")
			assert.JSONEq(t, wantReceiptJSON, string(body), "the receipt")
			file, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, tc.wantFile, file.Mode().Perm(), "the receipt's mode")
			parent, err := os.Stat(dir)
			require.NoError(t, err)
			assert.Equal(t, tc.wantDir, parent.Mode().Perm(), "the directory's mode")
		})
	}
}
