//go:build linux

package transparent_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/transparent"
)

// TestOriginalDestinationNeverInventsADestination drives the getsockopt
// against a real socket. A connection no REDIRECT rule touched has no
// pre-redirect destination, so the only answers that keep the frontend
// honest are a failure or the address the connection was accepted on. The
// frontend refuses the second with not_redirected, so neither reaches a
// policy decision.
//
// Which of the two comes back depends on whether conntrack holds an entry
// for the connection, which the kernel this runs on decides. Both are
// asserted, and an address that is neither fails the test.
func TestOriginalDestinationNeverInventsADestination(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		network string
		address string
	}{
		{name: "an IPv4 socket", network: "tcp4", address: "127.0.0.1:0"},
		{name: "an IPv6 socket", network: "tcp6", address: "[::1]:0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			listener, err := (&net.ListenConfig{}).Listen(t.Context(), tc.network, tc.address)
			require.NoError(t, err, "listen on %s", tc.address)
			t.Cleanup(func() { _ = listener.Close() })
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr == nil {
					accepted <- conn
				}
			}()
			client, err := (&net.Dialer{}).DialContext(t.Context(), tc.network, listener.Addr().String())
			require.NoError(t, err, "dial the listener")
			t.Cleanup(func() { _ = client.Close() })
			server := <-accepted
			t.Cleanup(func() { _ = server.Close() })

			got, err := transparent.OriginalDestination(server)
			if err != nil {
				// Both levels were tried before the failure, so a socket of
				// either family reaches the option its own family answers.
				assert.Contains(t, err.Error(), "SOL_IP/SO_ORIGINAL_DST",
					"the failure names the IPv4 level it tried")
				assert.Contains(t, err.Error(), "SOL_IPV6/IP6T_SO_ORIGINAL_DST",
					"the failure names the IPv6 level it tried")
				return
			}
			local, err := netip.ParseAddrPort(server.LocalAddr().String())
			require.NoError(t, err, "the address the connection was accepted on")
			assert.Equal(t, local.Addr().Unmap(), got.Addr().Unmap(),
				"an unredirected connection is attributed to the address it was accepted on")
			assert.Equal(t, local.Port(), got.Port(),
				"and to the port it was accepted on")
		})
	}
}

// TestOriginalDestinationRefusesAConnectionWithNoFileDescriptor pins that a
// connection the getsockopt cannot be made against fails rather than
// answering with a zero address, which the frontend would read as a
// destination.
func TestOriginalDestinationRefusesAConnectionWithNoFileDescriptor(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	got, err := transparent.OriginalDestination(server)
	require.ErrorIs(t, err, transparent.ErrNotSupported, "a pipe has no original destination")
	assert.Equal(t, netip.AddrPort{}, got, "nothing that reads as a destination is returned")
}
