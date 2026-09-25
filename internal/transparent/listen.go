package transparent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// Listen opens the sockets the transparent frontend accepts redirected
// connections on. A wildcard address gets one socket per address family. A
// literal address gets one socket of that address family.
//
// NEVER open a dual-stack socket here. Go answers a wildcard address with an
// AF_INET6 socket carrying IPV6_V6ONLY off (go net/ipsock_posix.go,
// favoriteAddrFamily, and net/sockopt_linux.go, setDefaultSockopts). Under
// gVisor's netstack, SO_ORIGINAL_DST on such a socket looks the connection
// up under the listener's own network protocol, IPv6, while the redirected
// IPv4 connection was tracked under IPv4, and the lookup answers ENOTCONN
// (gvisor pkg/tcpip/transport/tcp/endpoint.go, Endpoint.getSockOpt for
// tcpip.OriginalDestinationOption, and pkg/tcpip/stack/conntrack.go,
// ConnTrack.originalDst, whose tupleID carries netProto). A Linux kernel
// takes the family from the option level instead (linux
// net/netfilter/nf_conntrack_proto.c, getorigdst), so it answers either
// socket. One socket per family works on both.
//
// The host must be empty or an IP address. A name is an error.
//
// The IPv6 socket is optional only when the kernel has no IPv6, which
// socket(2) reports as EAFNOSUPPORT. Such a kernel has no ip6tables ruleset
// redirecting anything to it. Every other IPv6 error fails the call. gVisor
// registers IPv6 even when net.ipv6.conf.all.disable_ipv6 is set (gvisor
// runsc/boot/loader.go, newEmptySandboxNetworkStack), so under gVisor the
// IPv6 socket always opens. The IPv4 socket is never optional. A frontend
// that binds nothing accepts nothing, and the filter DROP then denies the
// workload every destination.
func Listen(ctx context.Context, address string) ([]net.Listener, error) {
	config := &net.ListenConfig{}
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return nil, fmt.Errorf("listen.transparent %q is not host:port: %w", address, err)
	}
	if host != "" {
		literal, parseErr := netip.ParseAddr(host)
		if parseErr != nil {
			return nil, fmt.Errorf("listen.transparent %q: host must be an IP address: %w", address, parseErr)
		}
		if !literal.IsUnspecified() {
			return listenLiteral(ctx, config, literal, address)
		}
	}
	inet, err := config.Listen(ctx, "tcp4", net.JoinHostPort("0.0.0.0", port))
	if err != nil {
		return nil, fmt.Errorf("listen on 0.0.0.0:%s: %w", port, err)
	}
	inet6, err := config.Listen(ctx, "tcp6", net.JoinHostPort("::", port))
	if errors.Is(err, syscall.EAFNOSUPPORT) {
		return []net.Listener{inet}, nil
	}
	if err != nil {
		_ = inet.Close()
		return nil, fmt.Errorf("listen on [::]:%s: %w", port, err)
	}
	return []net.Listener{inet, inet6}, nil
}

// listenLiteral binds the one family a specific address belongs to.
func listenLiteral(
	ctx context.Context, config *net.ListenConfig, literal netip.Addr, address string,
) ([]net.Listener, error) {
	network := "tcp4"
	if literal.Is6() {
		network = "tcp6"
	}
	listener, err := config.Listen(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", address, err)
	}
	return []net.Listener{listener}, nil
}

// Addresses renders what a set of listeners is bound to, for the start-up
// log.
func Addresses(listeners []net.Listener) string {
	parts := make([]string, 0, len(listeners))
	for _, listener := range listeners {
		parts = append(parts, listener.Addr().String())
	}
	return strings.Join(parts, ",")
}
