package transparent_test

import (
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/transparent"
)

// TestListen pins the address and family of each socket. The first socket
// being 127.0.0.1 over AF_INET is what pins one socket per family: a
// dual-stack socket would come back as one AF_INET6 listener. A kernel with
// no IPv6 returns the IPv4 socket alone.
func TestListen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		port      int
		wantAddrs []netip.Addr
		wantErr   string
	}{
		{
			name:      "a port, which binds the loopback address of each family",
			port:      0,
			wantAddrs: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
		},
		{name: "a port no socket can bind", port: 99999, wantErr: "listen on 127.0.0.1:99999"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			listeners, err := transparent.Listen(t.Context(), tc.port)
			if tc.wantErr != "" {
				require.Error(t, err, "the port is refused")
				assert.Contains(t, err.Error(), tc.wantErr, "the refusal says why")
				assert.Empty(t, listeners, "a refused port leaves no socket open")
				return
			}
			require.NoError(t, err, "open the sockets")
			t.Cleanup(func() {
				for _, listener := range listeners {
					_ = listener.Close()
				}
			})
			require.NotEmpty(t, listeners, "a socket is open")
			require.LessOrEqual(t, len(listeners), len(tc.wantAddrs), "no socket beyond the ones expected")
			for i, listener := range listeners {
				addr, ok := listener.Addr().(*net.TCPAddr)
				require.True(t, ok, "listener %d is bound on TCP", i)
				assert.Equal(t, tc.wantAddrs[i], addr.AddrPort().Addr(), "listener %d binds loopback alone", i)
			}
		})
	}
}

// TestListenFailsWhenTheIPv6PortIsTaken holds the IPv6 loopback port, which
// leaves the IPv4 bind free. Only a kernel with no IPv6 may leave the IPv6
// socket out, so this must fail and close the IPv4 socket it opened.
func TestListenFailsWhenTheIPv6PortIsTaken(t *testing.T) {
	t.Parallel()
	holder, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp6", "[::1]:0")
	require.NoError(t, err, "hold the IPv6 loopback port")
	t.Cleanup(func() { _ = holder.Close() })
	tcp, ok := holder.Addr().(*net.TCPAddr)
	require.True(t, ok, "the holder is bound on TCP")
	port := strconv.Itoa(tcp.Port)

	listeners, err := transparent.Listen(t.Context(), tcp.Port)
	require.Error(t, err, "a taken IPv6 port fails the call")
	assert.Contains(t, err.Error(), "listen on [::1]:"+port, "the refusal names the IPv6 socket")
	require.ErrorIs(t, err, syscall.EADDRINUSE, "the refusal keeps the bind error")
	assert.Empty(t, listeners, "a refused port leaves no socket open")

	inet, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", net.JoinHostPort("127.0.0.1", port))
	require.NoError(t, err, "the IPv4 socket Listen opened is closed again")
	_ = inet.Close()
}
