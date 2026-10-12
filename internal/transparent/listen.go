package transparent

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// Listen opens the sockets the transparent frontend accepts redirected
// connections on: one on 127.0.0.1 and one on ::1, both on port.
//
// The sockets bind loopback and nothing else. REDIRECT rewrites the
// destination of a locally generated packet to 127.0.0.1 or ::1 (linux
// net/netfilter/nf_nat_redirect.c for NF_INET_LOCAL_OUT, and gvisor
// pkg/tcpip/stack/iptables_targets.go, RedirectTarget.Action for the Output
// hook), so every connection the ruleset captures arrives there. A packet
// from outside the pod cannot: the kernel drops an IPv4 packet addressed to
// 127.0.0.0/8 that arrives on another interface unless route_localnet is set
// (linux Documentation/networking/ip-sysctl.rst, route_localnet), and drops
// an IPv6 packet addressed to ::1 (linux net/ipv6/ip6_input.c, ip6_rcv_core,
// per RFC 4291 section 2.5.3). NEVER bind another address here.
//
// NEVER open a dual-stack socket here. Under gVisor's netstack,
// SO_ORIGINAL_DST on an AF_INET6 socket looks the connection up under IPv6,
// while a redirected IPv4 connection was tracked under IPv4, and the lookup
// answers ENOTCONN (gvisor pkg/tcpip/transport/tcp/endpoint.go,
// Endpoint.getSockOpt for tcpip.OriginalDestinationOption, and
// pkg/tcpip/stack/conntrack.go, ConnTrack.originalDst, whose tupleID has
// netProto). One socket per family works on gVisor and on Linux.
//
// Listen skips the IPv6 socket when the kernel cannot provide IPv6 (see
// [netsetup.FamilyUnavailable]). The receipt family check refuses the start
// if the redirect covers IPv6. Every other IPv6 error closes the IPv4
// socket and fails the call. gVisor registers IPv6 even when
// net.ipv6.conf.all.disable_ipv6 is set (gvisor runsc/boot/loader.go,
// newEmptySandboxNetworkStack), so under gVisor the IPv6 socket always
// opens. The IPv4 socket is never optional. A frontend
// that binds nothing accepts nothing, and the filter DROP then denies the
// workload every destination.
func Listen(ctx context.Context, port int) ([]net.Listener, error) {
	return listen(ctx, &net.ListenConfig{}, port)
}

// listen is Listen with the socket options it binds with.
func listen(ctx context.Context, config *net.ListenConfig, port int) ([]net.Listener, error) {
	inetAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	inet, err := config.Listen(ctx, "tcp4", inetAddress)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", inetAddress, err)
	}
	inet6Address := net.JoinHostPort("::1", strconv.Itoa(port))
	inet6, err := config.Listen(ctx, "tcp6", inet6Address)
	if netsetup.FamilyUnavailable(err) {
		return []net.Listener{inet}, nil
	}
	if err != nil {
		_ = inet.Close()
		return nil, fmt.Errorf("listen on %s: %w", inet6Address, err)
	}
	return []net.Listener{inet, inet6}, nil
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
