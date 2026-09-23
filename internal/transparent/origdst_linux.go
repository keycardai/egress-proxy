//go:build linux

package transparent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ip6tSoOriginalDst is SO_ORIGINAL_DST's counterpart at SOL_IPV6. Both are
// 80. golang.org/x/sys/unix carries SO_ORIGINAL_DST and not this one, so the
// number is written out, from linux
// include/uapi/linux/netfilter_ipv6/ip6_tables.h.
const ip6tSoOriginalDst = 80

// Supported reports whether this platform can recover a redirected
// connection's original destination. Only Linux can, so only Linux runs the
// transparent frontend.
const Supported = true

// OriginalDestination returns the destination the connection was opened to
// before a REDIRECT rule rewrote it.
//
// The level to ask at follows the socket's own address family. A v6 socket
// carrying a v4-mapped connection answers at SOL_IP, so a failure at one
// level falls back to the other and the caller does not have to know which
// listener accepted the connection.
func OriginalDestination(conn net.Conn) (netip.AddrPort, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("%w: the connection is %T", ErrNotSupported, conn)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("raw connection: %w", err)
	}
	levels := []struct {
		level, option int
		name          string
	}{
		{unix.SOL_IP, unix.SO_ORIGINAL_DST, "SOL_IP/SO_ORIGINAL_DST"},
		{unix.SOL_IPV6, ip6tSoOriginalDst, "SOL_IPV6/IP6T_SO_ORIGINAL_DST"},
	}
	if isIPv6Socket(tcp.LocalAddr()) {
		levels[0], levels[1] = levels[1], levels[0]
	}
	var (
		addrPort netip.AddrPort
		failures []error
	)
	controlErr := raw.Control(func(fd uintptr) {
		for _, level := range levels {
			parsed, err := originalDestinationAt(fd, level.level, level.option)
			if err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", level.name, err))
				continue
			}
			addrPort, failures = parsed, nil
			return
		}
	})
	if controlErr != nil {
		return netip.AddrPort{}, fmt.Errorf("control the raw connection: %w", controlErr)
	}
	if len(failures) > 0 {
		return netip.AddrPort{}, fmt.Errorf("recover the original destination: %w", errors.Join(failures...))
	}
	return addrPort, nil
}

func originalDestinationAt(fd uintptr, level, option int) (netip.AddrPort, error) {
	buf, err := getsockoptSockaddr(fd, level, option)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return ParseSockaddr(buf)
}

func isIPv6Socket(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	return ok && tcp.IP.To4() == nil
}

// getsockoptSockaddr reads a socket option whose value is a sockaddr. Both
// the standard library and golang.org/x/sys/unix expose getsockopt only for
// the option shapes they name, and a sockaddr is not among them, so the
// syscall is made here and the bytes the kernel wrote are returned as they
// are.
func getsockoptSockaddr(fd uintptr, level, option int) ([]byte, error) {
	buf := make([]byte, sockaddrIn6Len)
	size := uint32(len(buf))
	_, _, errno := unix.Syscall6(
		uintptr(unix.SYS_GETSOCKOPT),
		fd,
		uintptr(level),
		uintptr(option),
		uintptr(unsafe.Pointer(&buf[0])), //nolint:gosec // G103: the kernel writes a sockaddr into this buffer
		uintptr(unsafe.Pointer(&size)),   //nolint:gosec // G103: and reports its length here
		0,
	)
	if errno != 0 {
		return nil, errno
	}
	if int(size) > len(buf) {
		return nil, fmt.Errorf("the kernel returned %d bytes into a %d byte buffer", size, len(buf))
	}
	return buf[:size], nil
}
