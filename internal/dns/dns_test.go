package dns_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/dns"
	"github.com/keycardai/egress-proxy/internal/policy"
)

// The document the fixture stands for: two endpoint hosts and the zone.
//
//nolint:gochecknoglobals // one allowlist every table row reads
var fixtureHosts = []string{"upstream.test", "api.example.com", "zone.keycard.test"}

// The addresses the upstream resolver answers with.
const (
	upstreamA    = "203.0.113.10"
	upstreamAAAA = "2001:db8::10"
)

// waitFor bounds every wait in this package's tests.
const waitFor = 10 * time.Second

// fixtureMaxConnections is the TCP connection cap every fixture resolver
// runs with. It is above what any test here opens, so a row that is not
// about the cap never meets it.
const fixtureMaxConnections = 16

func TestTheAllowlistDecidesEveryName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// query is the name as a client asks for it.
		query   string
		qtype   uint16
		qclass  uint16
		rcode   int
		verdict policy.Verdict
		reason  policy.Reason
		// upstream is how many queries the forwarding resolver must see.
		upstream int64
	}{
		{
			name: "an endpoint host resolves", query: "upstream.test.", qtype: mdns.TypeA,
			qclass: mdns.ClassINET, rcode: mdns.RcodeSuccess,
			verdict: policy.VerdictAllow, reason: policy.ReasonEndpointAllowed, upstream: 1,
		},
		{
			name: "an endpoint host resolves for AAAA", query: "upstream.test.", qtype: mdns.TypeAAAA,
			qclass: mdns.ClassINET, rcode: mdns.RcodeSuccess,
			verdict: policy.VerdictAllow, reason: policy.ReasonEndpointAllowed, upstream: 1,
		},
		{
			name: "the name matches whatever case it is asked in", query: "UpStream.TEST.", qtype: mdns.TypeA,
			qclass: mdns.ClassINET, rcode: mdns.RcodeSuccess,
			verdict: policy.VerdictAllow, reason: policy.ReasonEndpointAllowed, upstream: 1,
		},
		{
			name: "the zone host resolves", query: "zone.keycard.test.", qtype: mdns.TypeA,
			qclass: mdns.ClassINET, rcode: mdns.RcodeSuccess,
			verdict: policy.VerdictAllow, reason: policy.ReasonEndpointAllowed, upstream: 1,
		},
		{
			name: "the exfiltration name is refused and does not reach the resolver", query: "data.attacker.example.",
			qtype: mdns.TypeA, qclass: mdns.ClassINET, rcode: mdns.RcodeNameError,
			verdict: policy.VerdictDeny, reason: policy.ReasonNoMatchingEndpoint, upstream: 0,
		},
		{
			name: "a subdomain of an endpoint host is refused", query: "data.upstream.test.",
			qtype: mdns.TypeA, qclass: mdns.ClassINET, rcode: mdns.RcodeNameError,
			verdict: policy.VerdictDeny, reason: policy.ReasonNoMatchingEndpoint, upstream: 0,
		},
		{
			name: "an endpoint host used as a prefix is refused", query: "upstream.test.attacker.example.",
			qtype: mdns.TypeA, qclass: mdns.ClassINET, rcode: mdns.RcodeNameError,
			verdict: policy.VerdictDeny, reason: policy.ReasonNoMatchingEndpoint, upstream: 0,
		},
		{
			name: "an endpoint host with an extra leading label is refused", query: "xupstream.test.",
			qtype: mdns.TypeA, qclass: mdns.ClassINET, rcode: mdns.RcodeNameError,
			verdict: policy.VerdictDeny, reason: policy.ReasonNoMatchingEndpoint, upstream: 0,
		},
		{
			name:  "a search domain appended to an endpoint host is refused",
			query: "upstream.test.svc.cluster.local.", qtype: mdns.TypeA, qclass: mdns.ClassINET,
			rcode: mdns.RcodeNameError, verdict: policy.VerdictDeny,
			reason: policy.ReasonNoMatchingEndpoint, upstream: 0,
		},
		{
			name: "a TXT query for an unlisted name is refused", query: "leak.attacker.example.",
			qtype: mdns.TypeTXT, qclass: mdns.ClassINET, rcode: mdns.RcodeNameError,
			verdict: policy.VerdictDeny, reason: policy.ReasonNoMatchingEndpoint, upstream: 0,
		},
		{
			name: "a query outside class IN is refused on an endpoint host", query: "upstream.test.",
			qtype: mdns.TypeTXT, qclass: mdns.ClassCHAOS, rcode: mdns.RcodeNameError,
			verdict: policy.VerdictDeny, reason: policy.ReasonNoMatchingEndpoint, upstream: 0,
		},
		{
			name: "the root is refused", query: ".", qtype: mdns.TypeNS, qclass: mdns.ClassINET,
			rcode: mdns.RcodeNameError, verdict: policy.VerdictDeny,
			reason: policy.ReasonNoMatchingEndpoint, upstream: 0,
		},
	}
	// Both transports run every row. DNS falls back to TCP for an answer
	// that does not fit in a datagram, RFC 7766 section 5, so a resolver
	// that filtered only UDP would leave the whole allowlist bypassable.
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			t.Parallel()
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					fixture := newFixture(t, fixtureHosts)
					reply := fixture.ask(t, protocol, tc.query, tc.qtype, tc.qclass)

					assert.Equal(t, mdns.RcodeToString[tc.rcode], mdns.RcodeToString[reply.Rcode],
						"the response code for %s", tc.query)
					assert.Equal(t, tc.upstream, fixture.upstream.seen(),
						"queries the forwarding resolver saw for %s", tc.query)

					record := fixture.sink.only(t)
					assert.Equal(t, audit.ScopeDNS, record.Scope, "the record scope")
					assert.Equal(t, tc.verdict, record.Decision.Verdict, "the verdict")
					assert.Equal(t, tc.reason, record.Decision.Reason, "the reason")
					require.NotNil(t, record.Query, "the record holds the question")
					assert.Equal(t, mdns.TypeToString[tc.qtype], record.Query.Type, "the query type")
					assert.Equal(t, mdns.ClassToString[tc.qclass], record.Query.Class, "the query class")
					assert.Equal(t, protocol, record.Query.Protocol, "the query protocol")
					assert.Equal(t, mdns.RcodeToString[tc.rcode], record.Query.Rcode, "the recorded rcode")
					assert.Equal(t, queryHost(tc.query), record.Destination.Host, "the destination host")
					assert.Equal(t, dns.DefaultPort, record.Destination.Port, "the destination port")
				})
			}
		})
	}
}

// queryHost is the name a record holds for a query: canonical and without
// its trailing dot.
func queryHost(query string) string {
	if query == "." {
		return ""
	}
	return mdns.CanonicalName(query)[:len(mdns.CanonicalName(query))-1]
}

func TestAnAllowedNameAnswersWithWhatTheResolverSent(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t, fixtureHosts)
	reply := fixture.ask(t, "udp", "upstream.test.", mdns.TypeA, mdns.ClassINET)

	require.Len(t, reply.Answer, 1, "the answer section")
	record, ok := reply.Answer[0].(*mdns.A)
	require.True(t, ok, "the answer is an A record, got %T", reply.Answer[0])
	assert.Equal(t, upstreamA, record.A.String(), "the address the resolver sent")
}

// clientOptionCode is a local EDNS0 option code, from the range RFC 6891
// section 9 reserves for local use. A client that can put bytes of its own
// choosing in one has a channel to whoever answers the name.
const clientOptionCode = 65001

func TestNothingTheClientSentReachesTheResolver(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// query shapes what the client sends for upstream.test.
		query func() *mdns.Msg
		// check reads the message the forwarding resolver was sent.
		check func(t *testing.T, asked *mdns.Msg)
	}{
		{
			name: "the name goes upstream canonical whatever case the client used",
			query: func() *mdns.Msg {
				query := new(mdns.Msg)
				query.SetQuestion("UpStReAm.TeSt.", mdns.TypeA)
				return query
			},
			check: func(t *testing.T, asked *mdns.Msg) {
				t.Helper()
				require.Len(t, asked.Question, 1, "the forwarded message holds one question")
				assert.Equal(t, "upstream.test.", asked.Question[0].Name,
					"the forwarded name, which the client's case bits do not reach")
				assert.Equal(t, mdns.TypeToString[mdns.TypeA], mdns.TypeToString[asked.Question[0].Qtype],
					"the forwarded query type")
			},
		},
		{
			name: "an EDNS0 option the client sent does not go upstream",
			query: func() *mdns.Msg {
				query := new(mdns.Msg)
				query.SetQuestion("upstream.test.", mdns.TypeA)
				query.SetEdns0(4096, false)
				opt, _ := query.Extra[0].(*mdns.OPT)
				opt.Option = append(opt.Option, &mdns.EDNS0_LOCAL{
					Code: clientOptionCode, Data: bytes.Repeat([]byte{0xAB}, 400),
				})
				return query
			},
			check: func(t *testing.T, asked *mdns.Msg) {
				t.Helper()
				opt := asked.IsEdns0()
				require.NotNil(t, opt, "the forwarded message advertises what this resolver takes")
				for _, option := range opt.Option {
					assert.NotEqual(t, uint16(clientOptionCode), option.Option(),
						"the client's option reached the resolver")
				}
			},
		},
		{
			name: "the client's message id does not go upstream",
			query: func() *mdns.Msg {
				query := new(mdns.Msg)
				query.SetQuestion("upstream.test.", mdns.TypeA)
				query.Id = 0x4242
				return query
			},
			check: func(t *testing.T, asked *mdns.Msg) {
				t.Helper()
				assert.NotEqual(t, uint16(0x4242), asked.Id, "the forwarded message id")
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture := newFixture(t, fixtureHosts)
			query := tc.query()
			reply := fixture.exchange(t, "udp", query)

			assert.Equal(t, mdns.RcodeToString[mdns.RcodeSuccess], mdns.RcodeToString[reply.Rcode],
				"an endpoint host resolves")
			assert.Equal(t, query.Id, reply.Id, "the client reads its own message id back")
			require.Equal(t, int64(1), fixture.upstream.seen(), "the query reached the forwarding resolver")
			tc.check(t, fixture.upstream.asked(t))
		})
	}
}

func TestAResolverThatDoesNotAnswerDenies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// silent drops every query. refused answers a resolver error.
		silent bool
	}{
		{name: "a resolver that never answers spends the budget", silent: true},
		{name: "a resolver that closes the connection fails the query", silent: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture := newFixture(t, fixtureHosts, func(opts *dns.Options) {
				opts.Timeout = 200 * time.Millisecond
				if tc.silent {
					opts.Forward = []string{blackholeTarget(t)}
					return
				}
				opts.Forward = []string{closedTarget(t)}
			})
			reply := fixture.ask(t, "udp", "upstream.test.", mdns.TypeA, mdns.ClassINET)

			assert.Equal(t, mdns.RcodeToString[mdns.RcodeServerFailure], mdns.RcodeToString[reply.Rcode],
				"a query no resolver answered denies rather than forwards")
			assert.Empty(t, reply.Answer, "a failed query answers no record")
			record := fixture.sink.only(t)
			assert.Equal(t, policy.VerdictDeny, record.Decision.Verdict, "the verdict")
			assert.Equal(t, policy.ReasonUpstreamFailed, record.Decision.Reason, "the reason")
			assert.NotEmpty(t, record.Decision.Error, "the record says why the resolver failed")
		})
	}
}

func TestAMessageThatIsNotAQueryDenies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		opcode    int
		questions []mdns.Question
	}{
		{
			name: "a notify is not a lookup", opcode: mdns.OpcodeNotify,
			questions: []mdns.Question{{Name: "upstream.test.", Qtype: mdns.TypeSOA, Qclass: mdns.ClassINET}},
		},
		{
			name: "a query with no question names nothing to decide", opcode: mdns.OpcodeQuery,
			questions: nil,
		},
		{
			name: "a query with two questions names two decisions", opcode: mdns.OpcodeQuery,
			questions: []mdns.Question{
				{Name: "upstream.test.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET},
				{Name: "data.attacker.example.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture := newFixture(t, fixtureHosts)
			query := new(mdns.Msg)
			query.Id = mdns.Id()
			query.Opcode = tc.opcode
			query.Question = tc.questions
			// The handler runs directly, because the server's own accept
			// function refuses a message with a question count other than
			// one before a handler sees it.
			writer := &captureWriter{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}}
			fixture.resolver.Handler(t.Context()).ServeDNS(writer, query)

			require.NotNil(t, writer.reply, "the handler answered")
			assert.Equal(t, mdns.RcodeToString[mdns.RcodeFormatError], mdns.RcodeToString[writer.reply.Rcode],
				"a message that is not one lookup denies")
			assert.Zero(t, fixture.upstream.seen(), "queries the forwarding resolver saw")
			record := fixture.sink.only(t)
			assert.Equal(t, policy.VerdictDeny, record.Decision.Verdict, "the verdict")
			assert.Equal(t, policy.ReasonMalformedRequest, record.Decision.Reason, "the reason")
		})
	}
}

func TestNewRefusesAnUnusableResolver(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		options dns.Options
		want    string
	}{
		{
			name:    "no audit sink",
			options: dns.Options{Forward: []string{"10.43.0.10"}, Port: 53},
			want:    "no audit sink",
		},
		{
			name:    "no resolver to forward to",
			options: dns.Options{Audit: &recordingSink{}, Port: 53},
			want:    "no resolver to forward to",
		},
		{
			name: "a forward target on 127.0.0.1 at the listen port",
			options: dns.Options{
				Audit: &recordingSink{}, Port: 53, Forward: []string{"127.0.0.1:53"},
				MaxConnections: fixtureMaxConnections,
			},
			want: "would forward every allowed name to itself",
		},
		{
			name: "a forward target on 127.0.0.1 at the listen port, IPv4-mapped",
			options: dns.Options{
				Audit: &recordingSink{}, Port: 53, Forward: []string{"[::ffff:127.0.0.1]:53"},
				MaxConnections: fixtureMaxConnections,
			},
			want: "would forward every allowed name to itself",
		},
		{
			name: "a forward target on 127.0.0.1 with the default port",
			options: dns.Options{
				Audit: &recordingSink{}, Port: 53, Forward: []string{"127.0.0.1"},
				MaxConnections: fixtureMaxConnections,
			},
			want: "would forward every allowed name to itself",
		},
		{
			name: "a forward target on ::1 at the listen port",
			options: dns.Options{
				Audit: &recordingSink{}, Port: 15353, Forward: []string{"10.43.0.10", "[::1]:15353"},
				MaxConnections: fixtureMaxConnections,
			},
			want: "would forward every allowed name to itself",
		},
		{
			name: "a forward target on 0.0.0.0 at the listen port",
			options: dns.Options{
				Audit: &recordingSink{}, Port: 53, Forward: []string{"0.0.0.0"},
				MaxConnections: fixtureMaxConnections,
			},
			want: "would forward every allowed name to itself",
		},
		{
			name: "a forward target on :: at the listen port",
			options: dns.Options{
				Audit: &recordingSink{}, Port: 15353, Forward: []string{"[::]:15353"},
				MaxConnections: fixtureMaxConnections,
			},
			want: "would forward every allowed name to itself",
		},
		{
			name: "a zoned forward target on ::1 at the listen port",
			options: dns.Options{
				Audit: &recordingSink{}, Port: 15353, Forward: []string{"[::1%lo0]:15353"},
				MaxConnections: fixtureMaxConnections,
			},
			want: "would forward every allowed name to itself",
		},
		{
			name: "a zoned forward target on :: at the listen port",
			options: dns.Options{
				Audit: &recordingSink{}, Port: 15353, Forward: []string{"[::%lo]:15353"},
				MaxConnections: fixtureMaxConnections,
			},
			want: "would forward every allowed name to itself",
		},
		{
			name: "a forward target that is a name",
			options: dns.Options{
				Audit: &recordingSink{}, Port: 53, Forward: []string{"kube-dns.kube-system"},
			},
			want: "is not an IP address or address:port",
		},
		{
			name: "no connection cap",
			options: dns.Options{
				Audit: &recordingSink{}, Port: 53, Forward: []string{"10.43.0.10"},
			},
			want: "MaxConnections must be at least 1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resolver, err := dns.New(tc.options)
			require.ErrorIs(t, err, dns.ErrOptions, "the refusal is a resolver option failure")
			require.ErrorContains(t, err, tc.want, "the refusal names what is wrong")
			assert.Nil(t, resolver, "a refused configuration builds no resolver")
		})
	}
}

// TestNewAcceptsAForwardTargetThatIsNotThisResolver pins the targets the
// loop check lets through. The resolver binds only loopback addresses, so a
// target off loopback, or on another port, is a different resolver.
func TestNewAcceptsAForwardTargetThatIsNotThisResolver(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		port    int
		forward []string
		// want is Forward(), with every port explicit.
		want []string
	}{
		{
			name:    "a loopback target on another port",
			port:    53,
			forward: []string{"127.0.0.1:15353", "[::1]:15353", "10.43.0.10"},
			want:    []string{"127.0.0.1:15353", "[::1]:15353", "10.43.0.10:53"},
		},
		{
			name:    "a cluster resolver on the listen port",
			port:    53,
			forward: []string{"10.43.0.10:53", "[fd00:10:43::a]:53"},
			want:    []string{"10.43.0.10:53", "[fd00:10:43::a]:53"},
		},
		{
			name:    "a zoned link-local resolver on the listen port",
			port:    53,
			forward: []string{"[fe80::1%eth0]:53", "fe80::2%eth0"},
			want:    []string{"[fe80::1%eth0]:53", "[fe80::2%eth0]:53"},
		},
		{
			name:    "a cluster resolver with the default port",
			port:    53,
			forward: []string{"10.43.0.10"},
			want:    []string{"10.43.0.10:53"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resolver, err := dns.New(dns.Options{
				Audit: &recordingSink{}, Port: tc.port, Forward: tc.forward,
				MaxConnections: fixtureMaxConnections,
			})
			require.NoError(t, err, "build the resolver")
			assert.Equal(t, tc.want, resolver.Forward(), "the forward targets")
		})
	}
}

func TestHostsListsWhatResolves(t *testing.T) {
	t.Parallel()
	resolver, err := dns.New(dns.Options{
		Audit: &recordingSink{}, Port: 53, Forward: []string{"10.43.0.10"},
		Hosts: []string{"B.example.com", "a.example.com", "", "  "}, MaxConnections: fixtureMaxConnections,
	})
	require.NoError(t, err, "build the resolver")
	assert.Equal(t, []string{"a.example.com", "b.example.com"}, resolver.Hosts(),
		"an empty host names nothing and a host is held in lowercase")
}

// TestListenBindsLoopbackOnly pins the addresses the resolver binds:
// 127.0.0.1 and ::1 at the port, on both transports, and nothing else. The
// ::1 pair is expected only where the host has ::1.
func TestListenBindsLoopbackOnly(t *testing.T) {
	t.Parallel()
	_, port, sockets := listenLoopback(t)
	t.Cleanup(func() { _ = sockets.Close() })
	want := []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	if hasIPv6Loopback(t) {
		want = append(want, net.JoinHostPort("::1", strconv.Itoa(port)))
	}
	packet := make([]string, 0, len(sockets.Packet))
	for _, conn := range sockets.Packet {
		packet = append(packet, conn.LocalAddr().String())
	}
	stream := make([]string, 0, len(sockets.Stream))
	for _, listener := range sockets.Stream {
		stream = append(stream, listener.Addr().String())
	}
	assert.Equal(t, want, packet, "the UDP addresses")
	assert.Equal(t, want, stream, "the TCP addresses")
}

// TestListenFailsWhenIPv6IsBusy holds the port on ::1 before Listen runs.
// Only a kernel without IPv6 may leave the ::1 pair out, so Listen returns
// the error and releases the IPv4 pair it opened.
func TestListenFailsWhenIPv6IsBusy(t *testing.T) {
	t.Parallel()
	if !hasIPv6Loopback(t) {
		t.Skip("this host has no ::1")
	}
	port, held := holdIPv6Port(t)
	t.Cleanup(func() { _ = held.Close() })

	sockets, err := dns.Listen(t.Context(), port)
	require.ErrorIs(t, err, dns.ErrListen, "the refusal is a listener failure")
	require.ErrorIs(t, err, syscall.EADDRINUSE, "the ::1 error is returned")
	assert.Empty(t, sockets.Packet, "a failed Listen returns no socket")
	assert.Empty(t, sockets.Stream, "a failed Listen returns no socket")
	reclaimed, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	require.NoError(t, err, "the failed Listen left the IPv4 socket open on port %d", port)
	require.NoError(t, reclaimed.Close(), "close the reclaimed IPv4 socket")
}

// holdIPv6Port binds a UDP socket on ::1 at a port that is free on
// 127.0.0.1.
func holdIPv6Port(t *testing.T) (int, net.PacketConn) {
	t.Helper()
	for range bindAttempts {
		port := freePort(t)
		conn, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp6",
			net.JoinHostPort("::1", strconv.Itoa(port)))
		if err == nil {
			return port, conn
		}
	}
	t.Fatalf("no port was free on ::1 in %d attempts", bindAttempts)
	return 0, nil
}

// TestListenSkipsAnUnavailableIPv6Family injects each IPv6 bind error
// through the socket options. An error that says the kernel cannot provide
// IPv6 leaves the ::1 pair out. Any other error fails the call and releases
// the IPv4 pair.
func TestListenSkipsAnUnavailableIPv6Family(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		injected error
		wantErr  error
	}{
		{name: "IPv6 disabled on lo", injected: syscall.EADDRNOTAVAIL},
		{name: "a kernel without IPv6", injected: syscall.EAFNOSUPPORT},
		{name: "the ::1 port is taken", injected: syscall.EADDRINUSE, wantErr: syscall.EADDRINUSE},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			port := freePort(t)
			sockets, err := dns.ListenWith(t.Context(), failIPv6(tc.injected), port)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr, "the ::1 error is returned")
				assert.Empty(t, sockets.Packet, "a failed Listen returns no socket")
				reclaimed, reclaimErr := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4",
					net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				require.NoError(t, reclaimErr, "the failed Listen left the IPv4 socket open on port %d", port)
				require.NoError(t, reclaimed.Close(), "close the reclaimed IPv4 socket")
				return
			}
			require.NoError(t, err, "an unavailable family is skipped")
			t.Cleanup(func() { _ = sockets.Close() })
			want := "udp 127.0.0.1:" + strconv.Itoa(port) + ",tcp 127.0.0.1:" + strconv.Itoa(port)
			assert.Equal(t, want, sockets.Addresses(), "the IPv4 pair alone")
		})
	}
}

// failIPv6 is socket options that fail every IPv6 bind with err.
func failIPv6(err error) *net.ListenConfig {
	return &net.ListenConfig{Control: func(network, _ string, _ syscall.RawConn) error {
		if strings.HasSuffix(network, "6") {
			return err
		}
		return nil
	}}
}

func TestListenRefusesAPortOutsideTheRange(t *testing.T) {
	t.Parallel()
	for _, port := range []int{-1, 0, 65536} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			t.Parallel()
			sockets, err := dns.Listen(t.Context(), port)
			require.ErrorIs(t, err, dns.ErrListen, "the refusal is a listener failure")
			require.EqualError(t, err, "dns listener: port "+strconv.Itoa(port)+" is outside 1-65535",
				"the refusal names the port")
			assert.Empty(t, sockets.Packet, "a refused port binds no socket")
			assert.Empty(t, sockets.Stream, "a refused port binds no socket")
		})
	}
}

func TestServeAnswersOnTheBoundSocketsAndStops(t *testing.T) {
	t.Parallel()
	upstream := startUpstream(t)
	sink := &recordingSink{}
	address, port, sockets := listenLoopback(t)
	resolver, err := dns.New(dns.Options{
		Hosts: fixtureHosts, Forward: []string{upstream.address}, Port: port, Audit: sink,
		MaxConnections: fixtureMaxConnections,
	})
	require.NoError(t, err, "build the resolver")

	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- resolver.Serve(ctx, sockets) }()

	for _, protocol := range []string{"udp", "tcp"} {
		client := &mdns.Client{Net: protocol, Timeout: waitFor}
		query := new(mdns.Msg)
		query.SetQuestion("upstream.test.", mdns.TypeA)
		reply, _, exchangeErr := client.Exchange(query, address)
		require.NoError(t, exchangeErr, "ask the resolver over %s", protocol)
		assert.Equal(t, mdns.RcodeToString[mdns.RcodeSuccess], mdns.RcodeToString[reply.Rcode],
			"an endpoint host resolves over %s", protocol)
	}

	cancel()
	select {
	case err := <-stopped:
		require.NoError(t, err, "Serve returns once every socket has stopped")
	case <-time.After(waitFor):
		t.Fatal("Serve did not return after the context was cancelled")
	}
}

// shutdownRaces is how many times the cancelled-context run repeats. A
// stop that reaches a server before its accept loop does is a race, so one
// run proves nothing.
const shutdownRaces = 50

// TestServeReturnsWhenTheContextIsAlreadyCancelled pins the stop that
// arrives before the start. SIGTERM can land between the server goroutine
// starting and the server accepting, and a Serve that did not return then
// would burn the whole grace period and leave the kubelet to SIGKILL.
func TestServeReturnsWhenTheContextIsAlreadyCancelled(t *testing.T) {
	t.Parallel()
	upstream := startUpstream(t)
	for run := range shutdownRaces {
		_, port, sockets := listenLoopback(t)
		resolver, err := dns.New(dns.Options{
			Hosts: fixtureHosts, Forward: []string{upstream.address}, Port: port, Audit: &recordingSink{},
			MaxConnections: fixtureMaxConnections,
		})
		require.NoError(t, err, "build the resolver on run %d", run)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		stopped := make(chan error, 1)
		go func() { stopped <- resolver.Serve(ctx, sockets) }()
		select {
		case serveErr := <-stopped:
			require.NoError(t, serveErr, "Serve returns on run %d", run)
		case <-time.After(waitFor):
			t.Fatalf("Serve did not return on run %d of %d", run, shutdownRaces)
		}
		_ = sockets.Close()
	}
}

// capSettle is how long a connection past the cap is given to be served
// wrongly. Nothing signals an accept that does not happen, so this one
// wait is a clock.
const capSettle = 250 * time.Millisecond

// TestTheResolverCapsItsTCPConnections pins the bound that keeps the
// resolver off the descriptors the frontends and the audit writer need.
// miekg/dns holds a goroutine and a connection for the whole idle window,
// so a connection past the cap waits in the backlog.
func TestTheResolverCapsItsTCPConnections(t *testing.T) {
	t.Parallel()
	upstream := startUpstream(t)
	sink := &recordingSink{served: make(chan audit.Record, 4)}
	address, port, sockets := listenLoopback(t)
	resolver, err := dns.New(dns.Options{
		Hosts: fixtureHosts, Forward: []string{upstream.address}, Port: port, Audit: sink,
		MaxConnections: 1,
	})
	require.NoError(t, err, "build the resolver")
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- resolver.Serve(ctx, sockets) }()
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, <-stopped, "Serve after cancellation")
	})

	first := askOpen(t, address)
	t.Cleanup(func() { _ = first.Close() })
	waitServed(t, sink, "the first query")

	second := askOpen(t, address)
	t.Cleanup(func() { _ = second.Close() })
	select {
	case record := <-sink.served:
		require.Fail(t, "the resolver served a connection past the cap", "record %+v", record)
	case <-time.After(capSettle):
	}

	// Closing the first connection returns its slot, so the second is
	// accepted and its query is answered.
	require.NoError(t, first.Close(), "close the first connection")
	waitServed(t, sink, "the query held behind the cap")
}

// askOpen opens a TCP connection to the resolver and writes one query on
// it, leaving the connection open.
func askOpen(t *testing.T, address string) *mdns.Conn {
	t.Helper()
	conn, err := mdns.DialTimeout("tcp", address, waitFor)
	require.NoError(t, err, "open a connection to %s", address)
	query := new(mdns.Msg)
	query.SetQuestion("upstream.test.", mdns.TypeA)
	require.NoError(t, conn.WriteMsg(query), "write the query")
	return conn
}

// waitServed waits for one more record, which is the signal that the
// resolver answered a query.
func waitServed(t *testing.T, sink *recordingSink, what string) {
	t.Helper()
	select {
	case <-sink.served:
	case <-time.After(waitFor):
		t.Fatalf("waited %s for %s to be served", waitFor, what)
	}
}

// fixture is one resolver, its audit sink and the resolver it forwards to.
type fixture struct {
	resolver *dns.Resolver
	sink     *recordingSink
	upstream *upstreamResolver
}

// newFixture builds a resolver over a fresh upstream, with the options each
// test adjusts.
func newFixture(t *testing.T, hosts []string, adjust ...func(*dns.Options)) *fixture {
	t.Helper()
	upstream := startUpstream(t)
	sink := &recordingSink{}
	opts := dns.Options{
		Hosts:          hosts,
		Forward:        []string{upstream.address},
		Port:           53,
		Audit:          sink,
		Timeout:        waitFor,
		MaxConnections: fixtureMaxConnections,
	}
	for _, apply := range adjust {
		apply(&opts)
	}
	resolver, err := dns.New(opts)
	require.NoError(t, err, "build the resolver")
	return &fixture{resolver: resolver, sink: sink, upstream: upstream}
}

// ask serves one query over a real socket of the given transport, so a row
// exercises the same path a client takes.
func (f *fixture) ask(t *testing.T, protocol, name string, qtype, qclass uint16) *mdns.Msg {
	t.Helper()
	query := new(mdns.Msg)
	query.Id = mdns.Id()
	query.RecursionDesired = true
	query.Question = []mdns.Question{{Name: mdns.Fqdn(name), Qtype: qtype, Qclass: qclass}}
	return f.exchange(t, protocol, query)
}

// exchange serves one prepared message over a real socket of the given
// transport, for a test that shapes the client's query itself.
func (f *fixture) exchange(t *testing.T, protocol string, query *mdns.Msg) *mdns.Msg {
	t.Helper()
	address := serveOn(t, protocol, f.resolver.Handler(t.Context()))
	client := &mdns.Client{Net: protocol, Timeout: waitFor}
	reply, _, err := client.Exchange(query, address)
	require.NoError(t, err, "ask %v over %s", query.Question, protocol)
	return reply
}

// serveOn runs a handler on one loopback socket of the given transport and
// returns the address to ask.
func serveOn(t *testing.T, protocol string, handler mdns.Handler) string {
	t.Helper()
	server := &mdns.Server{Handler: handler, UDPSize: 4096}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	if protocol == "tcp" {
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err, "bind the test resolver over tcp")
		server.Listener = listener
	} else {
		conn, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
		require.NoError(t, err, "bind the test resolver over udp")
		server.PacketConn = conn
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	select {
	case <-started:
	case <-time.After(waitFor):
		t.Fatalf("the test resolver did not start over %s", protocol)
	}
	if server.Listener != nil {
		return server.Listener.Addr().String()
	}
	return server.PacketConn.LocalAddr().String()
}

// upstreamResolver stands in for the cluster resolver. It answers a fixed
// address for every name, counts what it was asked and keeps the last
// message. A test reads it to prove that a refused name did not reach the
// resolver, and that a forwarded query holds nothing the client put in it.
type upstreamResolver struct {
	address string
	queries atomic.Int64
	mu      sync.Mutex
	last    *mdns.Msg
}

func (u *upstreamResolver) ServeDNS(w mdns.ResponseWriter, query *mdns.Msg) {
	u.queries.Add(1)
	u.mu.Lock()
	u.last = query.Copy()
	u.mu.Unlock()
	reply := new(mdns.Msg)
	reply.SetReply(query)
	for _, question := range query.Question {
		header := mdns.RR_Header{
			Name: question.Name, Rrtype: question.Qtype, Class: mdns.ClassINET, Ttl: 30,
		}
		switch question.Qtype {
		case mdns.TypeA:
			reply.Answer = append(reply.Answer, &mdns.A{Hdr: header, A: net.ParseIP(upstreamA)})
		case mdns.TypeAAAA:
			reply.Answer = append(reply.Answer, &mdns.AAAA{Hdr: header, AAAA: net.ParseIP(upstreamAAAA)})
		}
	}
	_ = w.WriteMsg(reply)
}

func (u *upstreamResolver) seen() int64 { return u.queries.Load() }

// asked is the last message the resolver was sent.
func (u *upstreamResolver) asked(t *testing.T) *mdns.Msg {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	require.NotNil(t, u.last, "the resolver was asked something")
	return u.last
}

// startUpstream runs the fixture resolver on one loopback port over both
// transports, which is what a resolver in a resolv.conf looks like.
func startUpstream(t *testing.T) *upstreamResolver {
	t.Helper()
	upstream := &upstreamResolver{}
	address, _, sockets := listenLoopback(t)
	for _, conn := range sockets.Packet[1:] {
		_ = conn.Close()
	}
	for _, listener := range sockets.Stream[1:] {
		_ = listener.Close()
	}
	udp := &mdns.Server{PacketConn: sockets.Packet[0], Handler: upstream, UDPSize: 4096}
	tcp := &mdns.Server{Listener: sockets.Stream[0], Handler: upstream}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
	})
	upstream.address = address
	return upstream
}

// blackholeTarget is a UDP socket that reads and never answers, which is
// the resolver that spends the whole budget.
func blackholeTarget(t *testing.T) string {
	t.Helper()
	conn, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	require.NoError(t, err, "bind the silent resolver")
	t.Cleanup(func() { _ = conn.Close() })
	return conn.LocalAddr().String()
}

// closedTarget is a port nothing listens on, which is the resolver that is
// not there.
func closedTarget(t *testing.T) string {
	t.Helper()
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))
}

// bindAttempts is how many ports listenLoopback tries.
const bindAttempts = 20

// listenLoopback calls Listen on a free port and returns the 127.0.0.1
// address, the port and the sockets. Another test can hold the port over
// TCP or on ::1, which fails the bind, so listenLoopback tries another port.
func listenLoopback(t *testing.T) (string, int, dns.Sockets) {
	t.Helper()
	for range bindAttempts {
		port := freePort(t)
		sockets, err := dns.Listen(t.Context(), port)
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		require.NoError(t, err, "bind the resolver sockets on port %d", port)
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), port, sockets
	}
	t.Fatalf("no port was free on 127.0.0.1 and ::1 over UDP and TCP in %d attempts", bindAttempts)
	return "", 0, dns.Sockets{}
}

// hasIPv6Loopback reports whether this host can bind ::1.
func hasIPv6Loopback(t *testing.T) bool {
	t.Helper()
	conn, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp6", "[::1]:0")
	if err != nil {
		return false
	}
	require.NoError(t, conn.Close(), "release the IPv6 probe")
	return true
}

// freePort returns a port that is free on 127.0.0.1 over both TCP and UDP,
// because the resolver binds both. Nothing reserves it, so a later bind can
// still find it taken.
func freePort(t *testing.T) int {
	t.Helper()
	for range bindAttempts {
		stream, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
		require.NoError(t, err, "find a free TCP port")
		addr, ok := stream.Addr().(*net.TCPAddr)
		require.True(t, ok, "the listener reports a TCP address")
		packet, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4",
			net.JoinHostPort("127.0.0.1", strconv.Itoa(addr.Port)))
		require.NoError(t, stream.Close(), "release the TCP port")
		if err != nil {
			continue
		}
		require.NoError(t, packet.Close(), "release the UDP port")
		return addr.Port
	}
	t.Fatalf("no port was free on 127.0.0.1 over TCP and UDP in %d attempts", bindAttempts)
	return 0
}

// recordingSink keeps every record the resolver wrote. A test that waits
// on a query being served gives it a served channel, which Emit sends to
// without blocking.
type recordingSink struct {
	mu      sync.Mutex
	records []audit.Record
	served  chan audit.Record
}

func (s *recordingSink) Emit(record audit.Record) {
	s.mu.Lock()
	s.records = append(s.records, record)
	s.mu.Unlock()
	select {
	case s.served <- record:
	default:
	}
}

// only returns the single record a query wrote. A query that wrote none or
// several is a failure: one query is one decision.
func (s *recordingSink) only(t *testing.T) audit.Record {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.Len(t, s.records, 1, "one query writes one record")
	return s.records[0]
}

// captureWriter is a ResponseWriter that keeps the answer, for a message
// the server's accept function would refuse before a handler saw it.
type captureWriter struct {
	remote net.Addr
	reply  *mdns.Msg
}

func (c *captureWriter) LocalAddr() net.Addr  { return c.remote }
func (c *captureWriter) RemoteAddr() net.Addr { return c.remote }

func (c *captureWriter) WriteMsg(reply *mdns.Msg) error {
	c.reply = reply
	return nil
}

func (c *captureWriter) Write(b []byte) (int, error) { return len(b), nil }
func (c *captureWriter) Close() error                { return nil }
func (c *captureWriter) TsigStatus() error           { return nil }
func (c *captureWriter) TsigTimersOnly(bool)         {}
func (c *captureWriter) Hijack()                     {}
