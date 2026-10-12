package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ErrListen is a set of sockets the resolver could not open.
var ErrListen = errors.New("dns listener")

// Listen opens the UDP and TCP sockets the resolver answers on.
//
// A host of 127.0.0.1 or ::1 gets one pair of sockets of that address
// family. An address with no host, or an unspecified one, gets a pair on
// each. A REDIRECT in the nat OUTPUT chain rewrites the destination to
// 127.0.0.1 or ::1 and the packet then leaves through lo, so no other
// address receives a redirected query. Listen refuses every other host. See
// [CheckListen].
//
// The IPv6 pair is optional. A kernel without IPv6 does not redirect
// anything to it. The IPv4 pair is required.
func Listen(ctx context.Context, address string) (Sockets, error) {
	addrs, port, err := parseListen(address)
	if err != nil {
		return Sockets{}, fmt.Errorf("%w: %w", ErrListen, err)
	}
	sockets, err := bind(ctx, addrs[0], port)
	if err != nil {
		return Sockets{}, err
	}
	if len(addrs) == 1 {
		return sockets, nil
	}
	six, err := bind(ctx, addrs[1], port)
	if err != nil {
		//nolint:nilerr // a kernel without IPv6 does not redirect anything to an IPv6 socket
		return sockets, nil
	}
	return Sockets{
		Packet: append(sockets.Packet, six.Packet...),
		Stream: append(sockets.Stream, six.Stream...),
	}, nil
}

// bind opens one UDP and one TCP socket on an address. If the TCP socket
// cannot be opened, it closes the UDP one. A resolver on UDP alone would
// refuse every TCP fallback.
func bind(ctx context.Context, addr netip.Addr, port int) (Sockets, error) {
	udpNetwork, tcpNetwork := "udp4", "tcp4"
	if addr.Is6() {
		udpNetwork, tcpNetwork = "udp6", "tcp6"
	}
	address := net.JoinHostPort(addr.String(), strconv.Itoa(port))
	config := &net.ListenConfig{}
	packet, err := config.ListenPacket(ctx, udpNetwork, address)
	if err != nil {
		return Sockets{}, fmt.Errorf("%w: listen on udp %s: %w", ErrListen, address, err)
	}
	stream, err := config.Listen(ctx, tcpNetwork, address)
	if err != nil {
		return Sockets{}, errors.Join(
			fmt.Errorf("%w: listen on tcp %s: %w", ErrListen, address, err),
			packet.Close(),
		)
	}
	return Sockets{Packet: []net.PacketConn{packet}, Stream: []net.Listener{stream}}, nil
}

// ErrNotLoopback marks a listen.dns host that Listen refuses because other
// pods could reach it, or a redirected query would not arrive on it.
var ErrNotLoopback = errors.New("not a loopback address")

// CheckListen returns the error Listen returns for an address it refuses
// before binding. The address is host:port. The host must be empty, an
// unspecified address, 127.0.0.1, ::1 or ::ffff:127.0.0.1. A hostname is
// refused, including localhost.
//
// NEVER widen this to an address other pods can reach. The resolver
// decides what the sandbox can look up and answers no one else.
func CheckListen(address string) error {
	_, _, err := parseListen(address)
	return err
}

// parseListen reads a listen address as the addresses Listen binds and the
// port. An empty or unspecified host binds 127.0.0.1 and ::1, in that
// order. 127.0.0.1 and ::ffff:127.0.0.1 bind 127.0.0.1, and ::1 binds ::1.
func parseListen(address string) ([]netip.Addr, int, error) {
	host, port, err := splitListen(address)
	if err != nil {
		return nil, 0, err
	}
	ipv4Loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	if host == "" {
		return []netip.Addr{ipv4Loopback, netip.IPv6Loopback()}, port, nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return nil, 0, notLoopback(address)
	}
	if addr.IsUnspecified() {
		return []netip.Addr{ipv4Loopback, netip.IPv6Loopback()}, port, nil
	}
	if addr.Unmap() == ipv4Loopback || addr == netip.IPv6Loopback() {
		return []netip.Addr{addr.Unmap()}, port, nil
	}
	return nil, 0, notLoopback(address)
}

// notLoopback is the error for a listen address whose host Listen refuses.
func notLoopback(address string) error {
	return fmt.Errorf("listen.dns %q: %w. Leave the host empty, or name 127.0.0.1 or ::1", address, ErrNotLoopback)
}

// listenAddrs is the addresses and port a listen address binds. It returns
// no address and port zero for an address Listen refuses.
func listenAddrs(listen string) ([]netip.Addr, int) {
	addrs, port, err := parseListen(listen)
	if err != nil {
		return nil, 0
	}
	return addrs, port
}

// Port is the port an address binds, zero when the address names none or
// does not parse. The containment check compares it with the port the
// netsetup rules redirect DNS to.
func Port(address string) int {
	if strings.TrimSpace(address) == "" {
		return 0
	}
	_, port, err := splitListen(address)
	if err != nil {
		return 0
	}
	return port
}

// errPort marks a listen address whose port is not a number in 1-65535.
var errPort = errors.New("does not name a port in 1-65535")

// splitListen reads an address as a host and a port.
func splitListen(address string) (string, int, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return "", 0, fmt.Errorf("listen.dns %q is not host:port: %w", address, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("listen.dns %q %w", address, errPort)
	}
	return host, port, nil
}
