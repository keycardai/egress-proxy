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

// request builds a containment check for a sidecar that matches the receipt.
// The test supplies capability, owner, sysctl, and namespace reads because it
// cannot change those values on the host. 1024 is the kernel default for
// ip_unprivileged_port_start.
func request(path string) netsetup.ContainmentRequest {
	return netsetup.ContainmentRequest{
		Path:            path,
		TransparentPort: netsetup.DefaultRedirectPort,
		DNSPort:         netsetup.DefaultDNSPort,
		UID:             netsetup.DefaultProxyUID,
		Now:             now,
		NetAdmin:        func() (bool, error) { return false, nil },
		PortStart:       func() (int, error) { return 1024, nil },
		NetNamespace:    func() (netsetup.NetNamespace, error) { return podNetwork(), nil },
		Owner:           func(fs.FileInfo) (int, bool) { return netsetup.DefaultProxyUID, true },
	}
}

// containmentCase edits a matching receipt and request, and names the
// refusals Containment must report. An empty want expects the check to pass.
type containmentCase struct {
	name string
	edit func(*netsetup.Receipt)
	ask  func(*netsetup.ContainmentRequest)
	// chmod and chmodDir loosen the receipt and its directory.
	chmod    fs.FileMode
	chmodDir fs.FileMode
	want     []string
}

func TestContainment(t *testing.T) {
	t.Parallel()
	runContainment(t, []containmentCase{
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
			want: []string{"has no verified_at"},
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
			want: []string{"sends captured traffic to port 1015 and listen.transparent_port is 15001"},
		},
		{
			name: "a resolver on a port the DNS redirect does not target",
			ask:  func(q *netsetup.ContainmentRequest) { q.DNSPort = 5353 },
			want: []string{"redirect DNS to port 53 and listen.dns binds port 5353", "--dns-port 5353"},
		},
		{
			name: "DNS redirected to a sidecar that runs no resolver",
			ask:  func(q *netsetup.ContainmentRequest) { q.DNSPort = 0 },
			want: []string{"this process runs no resolver", "--dns-port 0"},
		},
		{
			name: "a resolver the rules redirect nothing to",
			edit: func(r *netsetup.Receipt) { r.DNSPort = 0 },
			want: []string{"the rules redirect no DNS to it", "--dns-port 53"},
		},
		{
			name: "a sidecar with no transparent listener under a redirect that targets one",
			ask:  func(q *netsetup.ContainmentRequest) { q.TransparentPort = 0 },
			want: []string{"listen.transparent_port is 0"},
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
			// An emptyDir mount point is 0777. A replacement is owned by the
			// uid that wrote it, so the owner check refuses it.
			name:     "a directory every uid can write, which is what an emptyDir mount point is",
			chmodDir: 0o777,
		},
		{
			name: "a receipt owned by a uid that is neither root nor the sidecar's",
			ask: func(q *netsetup.ContainmentRequest) {
				q.Owner = func(info fs.FileInfo) (int, bool) {
					if info.IsDir() {
						return 0, true
					}
					return 1000, true
				}
			},
			want: []string{"netsetup.json is owned by uid 1000, which is neither root nor this process's own uid 1337"},
		},
		{
			name: "a directory owned by a uid that is neither root nor the sidecar's",
			ask: func(q *netsetup.ContainmentRequest) {
				q.Owner = func(info fs.FileInfo) (int, bool) {
					if info.IsDir() {
						return 1000, true
					}
					return 0, true
				}
			},
			want: []string{"egress is owned by uid 1000", "So that uid can replace the receipt"},
		},
		{
			name: "a ruleset that exempts uid 0, with a sidecar running as root to match it",
			edit: func(r *netsetup.Receipt) { r.ProxyUID = 0 },
			ask:  func(q *netsetup.ContainmentRequest) { q.UID = 0 },
			want: []string{"the ruleset excludes uid 0", "Uid 0 would exempt every root process in the pod"},
		},
		{
			name: "a filesystem that does not say who owns the receipt",
			ask:  func(q *netsetup.ContainmentRequest) { q.Owner = func(fs.FileInfo) (int, bool) { return 0, false } },
			want: []string{"the filesystem does not report who owns"},
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
		{
			name: "a receipt from the sidecar's own network namespace",
			edit: func(r *netsetup.Receipt) { r.NetNamespace = &netsetup.NetNamespace{Device: 7, Inode: 4026532999} },
			ask: func(q *netsetup.ContainmentRequest) {
				q.NetNamespace = func() (netsetup.NetNamespace, error) {
					return netsetup.NetNamespace{Device: 7, Inode: 4026532999}, nil
				}
			},
		},
		{
			name: "a receipt from a network namespace on another device",
			edit: func(r *netsetup.Receipt) { r.NetNamespace = &netsetup.NetNamespace{Device: 5, Inode: 4026532288} },
			want: []string{
				"the receipt was written in network namespace device 5 inode 4026532288 and this process is in " +
					"network namespace device 4 inode 4026532288",
				"the init container and the sidecar are not in the same pod network",
			},
		},
		{
			name: "a receipt from another network namespace on the same device",
			edit: func(r *netsetup.Receipt) { r.NetNamespace = &netsetup.NetNamespace{Device: 4, Inode: 4026531840} },
			want: []string{
				"the receipt was written in network namespace device 4 inode 4026531840 and this process is in " +
					"network namespace device 4 inode 4026532288",
				"the init container and the sidecar are not in the same pod network",
			},
		},
		{
			name: "a receipt that records no network namespace",
			edit: func(r *netsetup.Receipt) { r.NetNamespace = nil },
			want: []string{"the receipt records no network namespace", "Re-run the init container"},
		},
		{
			// The init container on such a platform records no namespace
			// either, so neither side has one to compare.
			name: "a platform that does not report the network namespace, which is not a failure to read it",
			edit: func(r *netsetup.Receipt) { r.NetNamespace = nil },
			ask: func(q *netsetup.ContainmentRequest) {
				q.NetNamespace = func() (netsetup.NetNamespace, error) {
					return netsetup.NetNamespace{}, netsetup.ErrNetNamespaceNotSupported
				}
			},
		},
		{
			name: "a network namespace that could not be read at all",
			ask: func(q *netsetup.ContainmentRequest) {
				q.NetNamespace = func() (netsetup.NetNamespace, error) { return netsetup.NetNamespace{}, assert.AnError }
			},
			want: []string{"this process's network namespace could not be read"},
		},
	})
}

// TestContainmentPortStart covers the sysctl check and the receipt's
// redirect_port_protection, which decides whether the check runs.
func TestContainmentPortStart(t *testing.T) {
	t.Parallel()
	runContainment(t, []containmentCase{
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
			// The sysctl has to be above every port the sidecar binds. A
			// resolver port above the redirect port is the one to name.
			name: "a kernel that lets an unprivileged process bind the DNS port",
			edit: func(r *netsetup.Receipt) { r.DNSPort = 2000 },
			ask: func(q *netsetup.ContainmentRequest) {
				q.DNSPort = 2000
				q.PortStart = func() (int, error) { return 1024, nil }
			},
			want: []string{"can bind the DNS port 2000 and stand in for the proxy"},
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
			name: "a receipt that allows an unprotected redirect port, on a kernel that lets the workload bind it",
			edit: func(r *netsetup.Receipt) { r.RedirectPortProtection = netsetup.PortProtectionAllowUnprotected },
			ask:  func(q *netsetup.ContainmentRequest) { q.PortStart = func() (int, error) { return 0, nil } },
		},
		{
			name: "a receipt that allows an unprotected redirect port, on a kernel that does not expose the sysctl",
			edit: func(r *netsetup.Receipt) { r.RedirectPortProtection = netsetup.PortProtectionAllowUnprotected },
			ask: func(q *netsetup.ContainmentRequest) {
				q.PortStart = func() (int, error) { return 0, assert.AnError }
			},
		},
		{
			name: "a receipt that requires a protected redirect port, on a kernel that lets the workload bind it",
			edit: func(r *netsetup.Receipt) { r.RedirectPortProtection = netsetup.PortProtectionRequired },
			ask:  func(q *netsetup.ContainmentRequest) { q.PortStart = func() (int, error) { return 0, nil } },
			want: []string{"net.ipv4.ip_unprivileged_port_start is 0"},
		},
	})
}

func runContainment(t *testing.T, tests []containmentCase) {
	t.Helper()
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
			got, err := netsetup.Containment(ask)
			if len(tc.want) == 0 {
				require.NoError(t, err, "the sidecar can assert its own containment")
				assert.Equal(t, receipt, got, "the receipt the check passed")
				return
			}
			require.ErrorIs(t, err, netsetup.ErrNotContained, "the error the caller keys on")
			assert.Zero(t, got, "a refused check returns no receipt to log")
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
		// missing uses a path with no file.
		missing bool
		// put replaces the regular file with a shape a receipt must not have.
		put     func(t *testing.T) string
		want    string
		wantErr error
	}{
		{name: "the receipt the init container writes", body: string(good)},
		{
			name:    "no receipt at all, so either the init container did not run or it wrote elsewhere",
			missing: true, want: "no netsetup receipt", wantErr: netsetup.ErrNoReceipt,
		},
		{
			name: "a receipt that is not JSON",
			body: "not json", want: "does not parse", wantErr: netsetup.ErrUnreadableReceipt,
		},
		{
			name: "a receipt from a schema version this build does not read",
			body: `{"version":99}`, want: "is version 99 and this build reads version 1",
			wantErr: netsetup.ErrUnreadableReceipt,
		},
		{
			// A blocking open waits for a writer that never comes. The
			// sidecar hangs at start-up instead of refusing the receipt.
			name: "a receipt that is a FIFO",
			put: func(t *testing.T) string {
				t.Helper()
				fifo := filepath.Join(t.TempDir(), "netsetup.json")
				require.NoError(t, syscall.Mkfifo(fifo, 0o644), "make the FIFO")
				return fifo
			},
			want: "not a regular file", wantErr: netsetup.ErrUnreadableReceipt,
		},
		{
			// A link at the receipt path can make the mode, owner, and read
			// use different files, so the open refuses to follow it.
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
