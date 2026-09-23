//go:build !linux

package transparent

import (
	"net"
	"net/netip"
)

// Supported reports whether this platform can recover a redirected
// connection's original destination. Only Linux can, so only Linux runs the
// transparent frontend.
const Supported = false

// OriginalDestination is not supported on this platform. The sockaddr
// decoding in this package is portable and tested everywhere. The getsockopt
// that feeds it exists only on Linux.
func OriginalDestination(net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, ErrNotSupported
}
