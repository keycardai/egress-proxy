package netsetup_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// now is the clock every containment case is measured against, so a case
// that turns on the receipt's age says so in its own edit.
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

// contained is the receipt a sidecar starts on: the rules were applied,
// verified and then made unchangeable.
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

// request is a containment check for a sidecar that matches the receipt.
// The capability read, the owner and the sysctl are all supplied, because a
// unit test cannot arrange any of the three on the host it runs on. 1024 is
// the kernel default for ip_unprivileged_port_start.
func request(path string) netsetup.ContainmentRequest {
	return netsetup.ContainmentRequest{
		Path:            path,
		TransparentPort: netsetup.DefaultRedirectPort,
		UID:             netsetup.DefaultProxyUID,
		Now:             now,
		NetAdmin:        func() (bool, error) { return false, nil },
		PortStart:       func() (int, error) { return 1024, nil },
		Owner:           func(fs.FileInfo) (int, bool) { return netsetup.DefaultProxyUID, true },
	}
}

func TestContainment(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(*netsetup.Receipt)
		ask  func(*netsetup.ContainmentRequest)
		// chmod and chmodDir loosen the receipt and the directory it is in.
		chmod    fs.FileMode
		chmodDir fs.FileMode
		want     []string
	}{
		{name: "a receipt that matches the sidecar"},
		{
			name: "a receipt that says the tables were never read back",
			edit: func(r *netsetup.Receipt) { r.Verified = false },
			want: []string{"the rules were not verified"},
		},
		{
			name: "a receipt written by a process that kept the capability to change the rules",
			edit: func(r *netsetup.Receipt) { r.CapabilitiesDropped = false },
			want: []string{"kept CAP_NET_ADMIN", "--keep-net-admin"},
		},
		{
			name: "a receipt with no timestamp",
			edit: func(r *netsetup.Receipt) { r.VerifiedAt = time.Time{} },
			want: []string{"carries no verified_at"},
		},
		{
			name: "a receipt dated after now, which this pod's init container did not write",
			edit: func(r *netsetup.Receipt) { r.VerifiedAt = now.Add(time.Hour) },
			want: []string{"A receipt dated in the future"},
		},
		{
			name: "a sidecar running as a uid the rules do not exclude",
			ask:  func(q *netsetup.ContainmentRequest) { q.UID = 1000 },
			want: []string{"the ruleset excludes uid 1337 and this process runs as uid 1000", "--proxy-uid 1000"},
		},
		{
			name: "a transparent listener on a port the redirect does not target",
			ask:  func(q *netsetup.ContainmentRequest) { q.TransparentPort = 15001 },
			want: []string{"sends captured traffic to port 1015 and listen.transparent binds port 15001"},
		},
		{
			name: "a sidecar with no transparent listener under a redirect that targets one",
			ask:  func(q *netsetup.ContainmentRequest) { q.TransparentPort = 0 },
			want: []string{"listen.transparent binds port 0"},
		},
		{
			name: "a receipt naming no address family",
			edit: func(r *netsetup.Receipt) { r.Families = nil },
			want: []string{"names no address family"},
		},
		{
			name: "a sidecar that still holds the capability that programs the tables",
			ask:  func(q *netsetup.ContainmentRequest) { q.NetAdmin = func() (bool, error) { return true, nil } },
			want: []string{"this process holds CAP_NET_ADMIN", "capabilities.drop ALL"},
		},
		{
			name:  "a receipt any uid can write",
			chmod: 0o666,
			want:  []string{"so a uid other than its owner can write it", "Set the mode to 0644"},
		},
		{
			name:     "a directory any uid can put a replacement receipt in",
			chmodDir: 0o777,
			want:     []string{"so a uid other than its owner can replace the receipt in it", "Set the mode to 0755"},
		},
		{
			name: "a receipt owned by a uid that is neither root nor the sidecar's",
			ask:  func(q *netsetup.ContainmentRequest) { q.Owner = func(fs.FileInfo) (int, bool) { return 1000, true } },
			want: []string{"is owned by uid 1000, which is neither root nor this process's own uid 1337"},
		},
		{
			name: "a filesystem that does not say who owns the receipt",
			ask:  func(q *netsetup.ContainmentRequest) { q.Owner = func(fs.FileInfo) (int, bool) { return 0, false } },
			want: []string{"the filesystem does not report who owns"},
		},
		{
			name: "a kernel that lets an unprivileged process bind the redirect port",
			ask:  func(q *netsetup.ContainmentRequest) { q.PortStart = func() (int, error) { return 0, nil } },
			want: []string{
				"net.ipv4.ip_unprivileged_port_start is 0",
				"can bind the redirect port 1015 and stand in for the proxy",
			},
		},
		{
			name: "an unprivileged port start equal to the redirect port, which the workload can still bind",
			ask:  func(q *netsetup.ContainmentRequest) { q.PortStart = func() (int, error) { return 1015, nil } },
			want: []string{"net.ipv4.ip_unprivileged_port_start is 1015"},
		},
		{
			name: "a platform that does not report the unprivileged port start, which is not a failure to read it",
			ask: func(q *netsetup.ContainmentRequest) {
				q.PortStart = func() (int, error) { return 0, netsetup.ErrPortStartNotSupported }
			},
		},
		{
			name: "an unprivileged port start that could not be read at all",
			ask: func(q *netsetup.ContainmentRequest) {
				q.PortStart = func() (int, error) { return 0, assert.AnError }
			},
			want: []string{"the lowest port an unprivileged process may bind could not be read"},
		},
		{
			name: "a platform with no capability sets, which is not a failure to read them",
			ask: func(q *netsetup.ContainmentRequest) {
				q.NetAdmin = func() (bool, error) { return false, netsetup.ErrCapabilitiesNotSupported }
			},
		},
		{
			name: "capabilities that could not be read at all",
			ask: func(q *netsetup.ContainmentRequest) {
				q.NetAdmin = func() (bool, error) { return false, assert.AnError }
			},
			want: []string{"capabilities could not be read"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			receipt := contained()
			if tc.edit != nil {
				tc.edit(&receipt)
			}
			path := place(t, receipt)
			if tc.chmod != 0 {
				require.NoError(t, os.Chmod(path, tc.chmod), "set the receipt mode")
			}
			if tc.chmodDir != 0 {
				require.NoError(t, os.Chmod(filepath.Dir(path), tc.chmodDir), "set the directory mode")
			}
			ask := request(path)
			if tc.ask != nil {
				tc.ask(&ask)
			}
			err := netsetup.Containment(ask)
			if len(tc.want) == 0 {
				require.NoError(t, err, "the sidecar can assert its own containment")
				return
			}
			require.ErrorIs(t, err, netsetup.ErrNotContained, "the error the caller keys on")
			for _, want := range tc.want {
				assert.Contains(t, err.Error(), want, "the refusal names this disagreement")
			}
		})
	}
}

func TestReadReceiptRefusals(t *testing.T) {
	t.Parallel()
	good, err := json.Marshal(contained())
	require.NoError(t, err)
	tests := []struct {
		name string
		body string
		// missing asks for a path where no file is.
		missing bool
		// put replaces the plain file the case is read from, for the shapes
		// a receipt must not have.
		put     func(t *testing.T) string
		want    string
		wantErr error
	}{
		{name: "the receipt the init container writes", body: string(good)},
		{
			name:    "no receipt at all, so either the init container did not run or it wrote elsewhere",
			missing: true, want: "no netsetup receipt", wantErr: netsetup.ErrNoReceipt,
		},
		{name: "a receipt that is not JSON", body: "not json", want: "does not parse"},
		{
			name: "a receipt from a schema version this build does not read",
			body: `{"version":99}`, want: "is version 99 and this build reads version 1",
		},
		{
			// A link at the receipt's path points the mode and owner checks
			// at one file and the read at another, so the open refuses to
			// follow it.
			name: "a receipt that is a symbolic link to a receipt that would pass",
			put: func(t *testing.T) string {
				t.Helper()
				target := writeFile(t, "target.json", string(good))
				link := filepath.Join(filepath.Dir(target), "netsetup.json")
				require.NoError(t, os.Symlink(target, link), "link the receipt")
				return link
			},
			want: "read the netsetup receipt", wantErr: syscall.ELOOP,
		},
		{
			name: "a receipt that is a directory rather than a file",
			put: func(t *testing.T) string {
				t.Helper()
				dir := filepath.Join(t.TempDir(), "netsetup.json")
				require.NoError(t, os.Mkdir(dir, 0o755)) //nolint:gosec // G301: a fixture the sidecar refuses
				return dir
			},
			want: "not a regular file", wantErr: netsetup.ErrUnreadableReceipt,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, "netsetup.json", tc.body)
			if tc.put != nil {
				path = tc.put(t)
			}
			if tc.missing {
				path += ".missing"
			}
			got, err := netsetup.ReadReceipt(path)
			if tc.want == "" {
				require.NoError(t, err, "read the receipt")
				assert.Equal(t, netsetup.DefaultProxyUID, got.ProxyUID, "the uid the rules exclude")
				return
			}
			require.Error(t, err, "the receipt is unusable")
			assert.Contains(t, err.Error(), tc.want, "the error says why")
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr, "the error the caller keys on")
			}
		})
	}
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
