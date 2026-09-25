package transparent_test

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/transparent"
)

// sockaddrIn builds a Linux sockaddr_in the way the kernel fills it: the
// family in host byte order and the port in network byte order.
func sockaddrIn(addr [4]byte, port uint16) []byte {
	b := make([]byte, 16)
	binary.NativeEndian.PutUint16(b[0:2], 2)
	binary.BigEndian.PutUint16(b[2:4], port)
	copy(b[4:8], addr[:])
	return b
}

// sockaddrIn6 builds a Linux sockaddr_in6, scope id included.
func sockaddrIn6(addr [16]byte, port uint16, scope uint32) []byte {
	b := make([]byte, 28)
	binary.NativeEndian.PutUint16(b[0:2], 10)
	binary.BigEndian.PutUint16(b[2:4], port)
	copy(b[8:24], addr[:])
	binary.NativeEndian.PutUint32(b[24:28], scope)
	return b
}

// TestParseSockaddr decodes the two structures SO_ORIGINAL_DST answers
// with. The Linux family numbers are written out, so the decoding is the
// same on a developer's machine, where AF_INET6 is 30, as it is in a pod.
func TestParseSockaddr(t *testing.T) {
	t.Parallel()
	mapped := netip.MustParseAddr("::ffff:192.0.2.77").As16()
	tests := []struct {
		name    string
		raw     []byte
		want    string
		wantErr error
	}{
		{
			name: "an IPv4 destination",
			raw:  sockaddrIn([4]byte{192, 0, 2, 77}, 443), want: "192.0.2.77:443",
		},
		{
			name: "an IPv6 destination",
			raw:  sockaddrIn6(netip.MustParseAddr("2001:db8::1").As16(), 8443, 0), want: "[2001:db8::1]:8443",
		},
		{
			name: "a v4-mapped IPv6 destination decodes to the address the client used",
			raw:  sockaddrIn6(mapped, 443, 0), want: "192.0.2.77:443",
		},
		{
			name: "a link-local IPv6 destination keeps its scope id",
			raw:  sockaddrIn6(netip.MustParseAddr("fe80::1").As16(), 443, 7), want: "[fe80::1%7]:443",
		},
		{
			name: "an AF_INET sockaddr shorter than AF_INET needs",
			raw:  sockaddrIn([4]byte{192, 0, 2, 77}, 443)[:12], wantErr: transparent.ErrShortSockaddr,
		},
		{
			name: "an AF_INET6 sockaddr shorter than AF_INET6 needs",
			raw:  sockaddrIn6(mapped, 443, 0)[:20], wantErr: transparent.ErrShortSockaddr,
		},
		{name: "fewer bytes than a family and a port", raw: []byte{2, 0}, wantErr: transparent.ErrShortSockaddr},
		{
			name: "a family that is neither AF_INET nor AF_INET6",
			raw:  append([]byte{1, 0, 0, 0}, make([]byte, 24)...), wantErr: transparent.ErrUnknownFamily,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := transparent.ParseSockaddr(tc.raw)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr, "the error the caller keys on")
				assert.Equal(t, netip.AddrPort{}, got, "no destination is returned with the error")
				return
			}
			require.NoError(t, err, "decode the sockaddr")
			assert.Equal(t, tc.want, got.String(), "the destination")
		})
	}
}
