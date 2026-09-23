// Package transparent accepts the connections a netfilter REDIRECT rule
// sent to this process, recovers what each one was opened to, and hands it
// to the proxy.
//
// The redirect rewrites the destination address before the connection
// arrives, so the accepted socket's local address is this listener. The
// pre-redirect address is kept by conntrack and read back with getsockopt.
// The name the client used is read from the ClientHello, or from the Host
// header on a cleartext port, without consuming either.
package transparent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
)

// Linux address family numbers. The buffer getsockopt fills is a Linux
// sockaddr, so these are Linux's values and not the host's: darwin numbers
// AF_INET6 30 where Linux numbers it 10. Source: linux
// include/linux/socket.h.
const (
	linuxAFInet  = 2
	linuxAFInet6 = 10
)

// Sizes of the two structures getsockopt returns, from linux
// include/uapi/linux/in.h and in6.h:
//
//	sockaddr_in  = family 2 + port 2 + addr 4 + zero 8               = 16
//	sockaddr_in6 = family 2 + port 2 + flowinfo 4 + addr 16 + scope 4 = 28
const (
	sockaddrIn4Len = 16
	sockaddrIn6Len = 28
	// sockaddrHeadLen is the family and the port, which every sockaddr
	// starts with.
	sockaddrHeadLen = 4
)

var (
	// ErrNotSupported is returned by OriginalDestination on a platform with
	// no SO_ORIGINAL_DST, which is every platform but Linux.
	ErrNotSupported = errors.New(
		"recovering the original destination needs SO_ORIGINAL_DST, which exists only on Linux",
	)
	// ErrShortSockaddr is returned when the kernel returned fewer bytes than
	// the address family needs.
	ErrShortSockaddr = errors.New("sockaddr is shorter than its address family requires")
	// ErrUnknownFamily is returned for an address family that is neither
	// AF_INET nor AF_INET6.
	ErrUnknownFamily = errors.New("sockaddr names an unknown address family")
)

// ParseSockaddr decodes a Linux sockaddr_in or sockaddr_in6 into an address
// and port. A v4-mapped v6 address decodes to the v4 address it names,
// because that is the destination the client used.
//
// sa_family is in host byte order and the port is in network byte order,
// which is why the two fields are read with different byte orders.
func ParseSockaddr(raw []byte) (netip.AddrPort, error) {
	if len(raw) < sockaddrHeadLen {
		return netip.AddrPort{}, fmt.Errorf("%w: %d bytes", ErrShortSockaddr, len(raw))
	}
	family := binary.NativeEndian.Uint16(raw[0:2])
	port := binary.BigEndian.Uint16(raw[2:4])
	switch family {
	case linuxAFInet:
		if len(raw) < sockaddrIn4Len {
			return netip.AddrPort{}, fmt.Errorf("%w: AF_INET needs %d bytes, got %d",
				ErrShortSockaddr, sockaddrIn4Len, len(raw))
		}
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[4:8])), port), nil
	case linuxAFInet6:
		if len(raw) < sockaddrIn6Len {
			return netip.AddrPort{}, fmt.Errorf("%w: AF_INET6 needs %d bytes, got %d",
				ErrShortSockaddr, sockaddrIn6Len, len(raw))
		}
		addr := netip.AddrFrom16([16]byte(raw[8:24])).Unmap()
		// The scope id identifies the interface a link-local address belongs
		// to, and such an address without it is ambiguous.
		if scope := binary.NativeEndian.Uint32(raw[24:28]); scope != 0 && addr.Is6() {
			addr = addr.WithZone(strconv.FormatUint(uint64(scope), 10))
		}
		return netip.AddrPortFrom(addr, port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("%w: %d", ErrUnknownFamily, family)
	}
}
