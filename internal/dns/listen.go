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
// A loopback literal gets one pair of sockets of that address family. An
// address with no host, or an unspecified one, gets a pair on each
// family's loopback address, because a REDIRECT in the nat OUTPUT chain
// rewrites the destination to 127.0.0.1 or ::1 and the packet then leaves
// through lo. Listen refuses every other host. See [BindsLoopback].
//
// The IPv6 pair is optional. A kernel without IPv6 does not redirect
// anything to it. The IPv4 pair is required.
func Listen(ctx context.Context, address string) (Sockets, error) {
	host, port, err := splitListen(address)
	if err != nil {
		return Sockets{}, err
	}
	addrs, err := boundAddrs(host)
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

// ErrNotLoopback is a listen host that would bind an address other pods can
// reach.
var ErrNotLoopback = errors.New("is not a loopback address. Leave the host empty, or name 127.0.0.1 or ::1")

// BindsLoopback reports whether Listen accepts a host. The host must be
// empty, an unspecified address or a loopback IP literal. A hostname is
// refused, including localhost.
//
// NEVER widen this to an address other pods can reach. The resolver
// decides what the sandbox can look up and answers no one else.
func BindsLoopback(host string) bool {
	if host == "" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && (addr.IsUnspecified() || addr.IsLoopback())
}

// boundAddrs is what Listen binds for a host. An empty or unspecified host
// binds 127.0.0.1 and ::1, in that order. A loopback literal binds itself,
// and an IPv4-mapped one binds its IPv4 address. Any other host is an error.
func boundAddrs(host string) ([]netip.Addr, error) {
	if !BindsLoopback(host) {
		return nil, fmt.Errorf("listen.dns host %q %w", host, ErrNotLoopback)
	}
	if literal, err := netip.ParseAddr(host); err == nil && !literal.IsUnspecified() {
		return []netip.Addr{literal.Unmap()}, nil
	}
	return []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()}, nil
}

// listenAddrs is the addresses and port a listen address binds. It returns
// no address and port zero for an address Listen refuses.
func listenAddrs(listen string) ([]netip.Addr, int) {
	host, port, err := splitListen(listen)
	if err != nil {
		return nil, 0
	}
	addrs, err := boundAddrs(host)
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

// splitListen reads an address as a host and a port.
func splitListen(address string) (string, int, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return "", 0, fmt.Errorf("%w: listen.dns %q is not host:port: %w", ErrListen, address, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("%w: listen.dns %q does not name a port in 1-65535", ErrListen, address)
	}
	return host, port, nil
}
