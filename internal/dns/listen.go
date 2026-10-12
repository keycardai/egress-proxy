package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// ErrListen is a set of sockets the resolver could not open.
var ErrListen = errors.New("dns listener")

// Listen opens the UDP and TCP sockets the resolver answers on: one pair
// on 127.0.0.1 and one on ::1, at port. A REDIRECT in the nat OUTPUT chain
// rewrites the destination to one of those two addresses and the packet
// then leaves through lo. Other pods cannot reach either address.
//
// NEVER bind another address here. The resolver decides what the sandbox
// can look up and answers no one else.
//
// Listen skips the IPv6 pair when the kernel cannot provide IPv6 (see
// [netsetup.FamilyUnavailable]). The receipt family check refuses the start
// if the redirect covers IPv6. Every other IPv6 error closes the IPv4 pair
// and fails the call. The IPv4 pair is always required.
func Listen(ctx context.Context, port int) (Sockets, error) {
	return listen(ctx, &net.ListenConfig{}, port)
}

// listen is Listen with the socket options it binds with.
func listen(ctx context.Context, config *net.ListenConfig, port int) (Sockets, error) {
	if port < 1 || port > maxPort {
		return Sockets{}, fmt.Errorf("%w: port %d is outside 1-%d", ErrListen, port, maxPort)
	}
	addrs := loopback()
	sockets, err := bind(ctx, config, addrs[0], port)
	if err != nil {
		return Sockets{}, err
	}
	six, err := bind(ctx, config, addrs[1], port)
	if netsetup.FamilyUnavailable(err) {
		return sockets, nil
	}
	if err != nil {
		return Sockets{}, errors.Join(err, sockets.Close())
	}
	return Sockets{
		Packet: append(sockets.Packet, six.Packet...),
		Stream: append(sockets.Stream, six.Stream...),
	}, nil
}

// maxPort is the highest port Listen binds.
const maxPort = 65535

// loopback is the addresses Listen binds, in the order it binds them.
func loopback() []netip.Addr {
	return []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()}
}

// bind opens one UDP and one TCP socket on an address. If the TCP socket
// cannot be opened, it closes the UDP one. A resolver on UDP alone would
// refuse every TCP fallback.
func bind(ctx context.Context, config *net.ListenConfig, addr netip.Addr, port int) (Sockets, error) {
	udpNetwork, tcpNetwork := "udp4", "tcp4"
	if addr.Is6() {
		udpNetwork, tcpNetwork = "udp6", "tcp6"
	}
	address := net.JoinHostPort(addr.String(), strconv.Itoa(port))
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
