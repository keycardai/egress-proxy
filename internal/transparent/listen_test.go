package transparent_test

import (
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/transparent"
)

// TestListen pins how many sockets an address opens and which family each
// one is. A wildcard address must open one socket per family rather than one
// dual-stack socket, because SO_ORIGINAL_DST on a dual-stack socket cannot
// answer for a redirected IPv4 connection under gVisor's netstack.
func TestListen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		address string
		// wantNetworks is the network each returned listener is bound on, in
		// order. A kernel with no IPv6 returns the prefix of it that does
		// not name tcp6.
		wantNetworks []string
		wantErr      string
	}{
		{
			// A dual-stack socket would come back as one AF_INET6 listener,
			// so the first listener being AF_INET is what pins one socket
			// per family.
			name:    "a wildcard address, which binds one socket per family",
			address: "0.0.0.0:0", wantNetworks: []string{"tcp4", "tcp6"},
		},
		{
			name:    "the IPv6 wildcard, which binds the same pair",
			address: "[::]:0", wantNetworks: []string{"tcp4", "tcp6"},
		},
		{
			name:    "an empty host, which binds the same pair",
			address: ":0", wantNetworks: []string{"tcp4", "tcp6"},
		},
		{
			name:    "an IPv4 literal, which binds that family alone",
			address: "127.0.0.1:0", wantNetworks: []string{"tcp4"},
		},
		{
			name:    "an IPv6 literal, which binds that family alone",
			address: "[::1]:0", wantNetworks: []string{"tcp6"},
		},
		{
			name:    "an address that names no port",
			address: "0.0.0.0", wantErr: "is not host:port",
		},
		{
			name:    "localhost, which is a name and not an address",
			address: "localhost:0", wantErr: "host must be an IP address",
		},
		{
			name:    "a DNS name",
			address: "proxy.example.com:0", wantErr: "host must be an IP address",
		},
		{
			name:    "a port no socket can bind",
			address: "0.0.0.0:99999", wantErr: "listen on 0.0.0.0:99999",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			listeners, err := transparent.Listen(t.Context(), tc.address)
			if tc.wantErr != "" {
				require.Error(t, err, "the address is refused")
				assert.Contains(t, err.Error(), tc.wantErr, "the refusal says why")
				assert.Empty(t, listeners, "a refused address leaves no socket open")
				return
			}
			require.NoError(t, err, "open the sockets")
			t.Cleanup(func() {
				for _, listener := range listeners {
					_ = listener.Close()
				}
			})
			require.NotEmpty(t, listeners, "a socket is open")
			require.LessOrEqual(t, len(listeners), len(tc.wantNetworks), "no socket beyond the ones expected")
			for i, listener := range listeners {
				assert.Equal(t, tc.wantNetworks[i], networkOf(t, listener), "listener %d", i)
			}
			// Every socket carries one family, so no two share an address.
			seen := make(map[string]bool, len(listeners))
			for _, listener := range listeners {
				addr := listener.Addr().String()
				assert.False(t, seen[addr], "two listeners bound %s", addr)
				seen[addr] = true
			}
		})
	}
}

// networkOf reports which family a listener is bound on. An IPv4 socket
// carries a four-byte address.
func networkOf(t *testing.T, listener net.Listener) string {
	t.Helper()
	addr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok, "the listener is bound on TCP")
	if addr.IP.To4() != nil {
		return "tcp4"
	}
	return "tcp6"
}

// TestListenFailsWhenTheIPv6PortIsTaken holds the IPv6 wildcard port with a
// V6ONLY socket, which leaves the IPv4 bind free. Only a kernel with no IPv6
// may leave the IPv6 socket out, so this must fail and close the IPv4 socket
// it opened.
func TestListenFailsWhenTheIPv6PortIsTaken(t *testing.T) {
	t.Parallel()
	holder, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp6", "[::]:0")
	require.NoError(t, err, "hold the IPv6 wildcard port")
	t.Cleanup(func() { _ = holder.Close() })
	_, port, err := net.SplitHostPort(holder.Addr().String())
	require.NoError(t, err)

	listeners, err := transparent.Listen(t.Context(), net.JoinHostPort("0.0.0.0", port))
	require.Error(t, err, "a taken IPv6 port fails the call")
	assert.Contains(t, err.Error(), "listen on [::]:"+port, "the refusal names the IPv6 socket")
	require.ErrorIs(t, err, syscall.EADDRINUSE, "the refusal keeps the bind error")
	assert.Empty(t, listeners, "a refused address leaves no socket open")

	inet, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", net.JoinHostPort("0.0.0.0", port))
	require.NoError(t, err, "the IPv4 socket Listen opened is closed again")
	_ = inet.Close()
}
