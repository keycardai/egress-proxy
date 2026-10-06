package netsetup_test

import (
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// valid is the configuration every validation case starts from: the pod
// contract with a resolver filled in, which is what the init container
// builds.
func valid() netsetup.Config {
	cfg := netsetup.DefaultConfig()
	cfg.DNSServers = []netip.Addr{netip.MustParseAddr("10.43.0.10")}
	return cfg
}

func TestValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(*netsetup.Config)
		// want is the text every problem message must contain. An empty
		// list means the configuration validates.
		want []string
	}{
		{name: "the pod contract with a resolver", edit: func(*netsetup.Config) {}},
		{
			name: "a negative uid",
			edit: func(c *netsetup.Config) { c.ProxyUID = -1 },
			want: []string{"proxy uid -1 is out of range 1-2147483647"},
		},
		{
			name: "root as the proxy uid, which would exempt every root process in the pod",
			edit: func(c *netsetup.Config) { c.ProxyUID = 0 },
			want: []string{"proxy uid 0 is root"},
		},
		{
			name: "the lowest uid the proxy may run as",
			edit: func(c *netsetup.Config) { c.ProxyUID = 1 },
		},
		{
			name: "the highest uid Kubernetes accepts for runAsUser",
			edit: func(c *netsetup.Config) { c.ProxyUID = math.MaxInt32 },
		},
		{
			name: "a uid above what Kubernetes accepts for runAsUser",
			edit: func(c *netsetup.Config) { c.ProxyUID = math.MaxInt32 + 1 },
			want: []string{"proxy uid 2147483648 is out of range 1-2147483647"},
		},
		{
			name: "a redirect port outside 1-65535",
			edit: func(c *netsetup.Config) { c.RedirectPort = 0 },
			want: []string{"redirect port 0 is out of range"},
		},
		{
			name: "no capture ports, so nothing reaches the proxy",
			edit: func(c *netsetup.Config) { c.CapturePorts = nil },
			want: []string{"no capture ports"},
		},
		{
			name: "more capture ports than one multiport match holds",
			edit: func(c *netsetup.Config) { c.CapturePorts = make([]int, 16) },
			want: []string{"16 capture ports: one multiport match holds at most 15"},
		},
		{
			name: "the redirect port among the capture ports, which would redirect the listener to itself",
			edit: func(c *netsetup.Config) { c.CapturePorts = []int{80, c.RedirectPort} },
			want: []string{"is the redirect port"},
		},
		{
			name: "no resolver, so the sidecar's resolver would have nowhere to forward",
			edit: func(c *netsetup.Config) { c.DNSServers = nil },
			want: []string{"no DNS servers"},
		},
		{
			name: "no DNS redirect, which is a pod whose sidecar runs no resolver",
			edit: func(c *netsetup.Config) { c.DNSPort = 0 },
		},
		{
			name: "a DNS port outside 0-65535",
			edit: func(c *netsetup.Config) { c.DNSPort = 70000 },
			want: []string{"dns port 70000 is out of range 0-65535"},
		},
		{
			name: "the DNS port on the transparent frontend, which answers no query",
			edit: func(c *netsetup.Config) { c.DNSPort = c.RedirectPort },
			want: []string{"is the redirect port", "answers no query"},
		},
		{
			name: "a resolver written as IPv4-in-IPv6, which would go in the wrong family's ruleset",
			edit: func(c *netsetup.Config) { c.DNSServers = []netip.Addr{netip.MustParseAddr("::ffff:10.43.0.10")} },
			want: []string{"is IPv4 written as IPv6; write it as 10.43.0.10"},
		},
		{
			name: "a pod CIDR written as IPv4-in-IPv6",
			edit: func(c *netsetup.Config) { c.PodCIDRs = []netip.Prefix{netip.MustParsePrefix("::ffff:10.42.0.0/112")} },
			want: []string{"pod CIDR ::ffff:10.42.0.0/112 is IPv4 written as IPv6"},
		},
		{
			name: "every problem at once, so one run tells the operator all of them",
			edit: func(c *netsetup.Config) {
				c.ProxyUID, c.RedirectPort, c.CapturePorts, c.DNSServers = -1, 0, nil, nil
			},
			want: []string{"proxy uid -1", "redirect port 0", "no capture ports", "no DNS servers"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := valid()
			tc.edit(&cfg)
			err := cfg.Validate()
			if len(tc.want) == 0 {
				require.NoError(t, err, "the configuration validates")
				return
			}
			require.ErrorIs(t, err, netsetup.ErrInvalidConfig, "the error the caller keys on")
			for _, want := range tc.want {
				assert.Contains(t, err.Error(), want, "the report names this problem")
			}
		})
	}
}

func TestFamilies(t *testing.T) {
	t.Parallel()
	cfg := valid()
	assert.Equal(t, []netsetup.Family{netsetup.FamilyIPv4, netsetup.FamilyIPv6}, cfg.Families(),
		"IPv6Proxy programs both families")
	cfg.IPv6 = netsetup.IPv6Deny
	assert.Equal(t, []netsetup.Family{netsetup.FamilyIPv4, netsetup.FamilyIPv6}, cfg.Families(),
		"IPv6Deny programs both families: the rules that deny IPv6 go in the tables")
	cfg.IPv6 = netsetup.IPv6None
	assert.Equal(t, []netsetup.Family{netsetup.FamilyIPv4}, cfg.Families(),
		"IPv6None programs IPv4 alone")
}

func TestNameservers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		file    string
		want    []string
		wantErr string
	}{
		{
			name: "the resolvers a cluster resolv.conf names",
			file: "search default.svc.cluster.local\nnameserver 10.43.0.10\noptions ndots:5\n",
			want: []string{"10.43.0.10"},
		},
		{
			name: "several resolvers, in the order the file lists them",
			file: "nameserver 10.43.0.10\nnameserver fd00::a\n",
			want: []string{"10.43.0.10", "fd00::a"},
		},
		{
			name: "a resolver written as IPv4-in-IPv6 is unmapped to the address it names",
			file: "nameserver ::ffff:10.43.0.10\n",
			want: []string{"10.43.0.10"},
		},
		{
			name: "a commented-out resolver is not one",
			file: "# nameserver 10.43.0.10\nnameserver 10.43.0.11 ; a comment\n",
			want: []string{"10.43.0.11"},
		},
		{
			name: "a file naming no resolver, which would drop every resolution",
			file: "search default.svc.cluster.local\n", wantErr: "names no resolver",
		},
		{
			name: "a resolver that is not an address",
			file: "nameserver resolver.local\n", wantErr: `"resolver.local", which is not an address`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, "resolv.conf", tc.file)
			got, err := netsetup.Nameservers(path)
			if tc.wantErr != "" {
				require.Error(t, err, "the file names no usable resolver")
				assert.Contains(t, err.Error(), tc.wantErr, "the error says why")
				return
			}
			require.NoError(t, err, "read the resolvers")
			assert.Equal(t, tc.want, addrTexts(got), "the resolvers, in order")
		})
	}
	_, err := netsetup.Nameservers(writeFile(t, "resolv.conf", "") + ".missing")
	require.Error(t, err, "a resolv.conf that is not there")
}

func addrTexts(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, addr := range addrs {
		out[i] = addr.String()
	}
	return out
}

// TestKernelHasIPv6 pins what the probe does with each answer the
// filesystem can give. Only the file being absent says the kernel has no
// IPv6. Any other error means this process cannot tell, and reading it as
// "no IPv6" would leave the family unprogrammed and every IPv6 destination
// reachable on every port.
func TestKernelHasIPv6(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	present := filepath.Join(dir, "if_inet6")
	require.NoError(t, os.WriteFile(present, []byte("\n"), 0o600), "the file that says the kernel has IPv6")

	tests := []struct {
		name string
		path string
		want bool
		// wantErr says the probe could not tell.
		wantErr bool
	}{
		{name: "the file is there", path: present, want: true},
		{name: "the file is absent", path: filepath.Join(dir, "missing"), want: false},
		{
			// A path under a regular file answers ENOTDIR, which is neither
			// "there" nor "absent".
			name: "the path cannot be walked", path: filepath.Join(present, "if_inet6"), wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			has, err := netsetup.KernelHasIPv6At(tc.path)
			if tc.wantErr {
				require.ErrorIs(t, err, netsetup.ErrIPv6Undetermined, "an unreadable probe is not an answer")
				assert.False(t, has, "a probe that failed reports no IPv6 alongside its error")
				return
			}
			require.NoError(t, err, "the probe answers")
			assert.Equal(t, tc.want, has, "whether the kernel has IPv6")
		})
	}
}
