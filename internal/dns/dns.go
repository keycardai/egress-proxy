// Package dns answers the sandbox's name lookups and refuses every name no
// endpoint declares.
//
// A DNS query is not a connection, so a destination the proxy refuses still
// leaves the pod as a query unless the resolver is constrained. The
// resolver listens on the pod loopback over UDP and TCP. It answers
// NXDOMAIN for a name outside the allowlist and forwards the rest to the
// cluster resolvers. Every query gets one audit record with scope dns.
//
// The allowlist is the endpoint hosts of the configuration document plus
// the zone host. config.DNS says why no setting changes it.
package dns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
	"golang.org/x/net/netutil"
	"golang.org/x/sync/errgroup"

	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/policy"
)

// DefaultPort is the port the resolver binds when an address names none.
const DefaultPort = 53

// The bounds on one query and on one client.
const (
	// DefaultTimeout bounds one forwarded query against one resolver.
	DefaultTimeout = 5 * time.Second
	// readTimeout is how long a socket waits for the rest of a message.
	readTimeout = 5 * time.Second
	// writeTimeout bounds the write of one answer.
	writeTimeout = 2 * time.Second
	// tcpIdleTimeout closes a TCP connection that sends nothing more,
	// which is the bound RFC 7766 section 6.2.3 asks a server to set.
	tcpIdleTimeout = 10 * time.Second
	// maxTCPQueries is how many queries one TCP connection answers before
	// the resolver closes it.
	maxTCPQueries = 64
	// shutdownGrace bounds the wait for in-flight queries on a stop.
	shutdownGrace = 5 * time.Second
)

// The answer sizes. A client that sends no EDNS0 option takes 512 bytes in
// a datagram, RFC 1035 section 4.2.1, and one that advertises more is
// capped so a large answer cannot be used to amplify.
const (
	datagramAnswerSize = 512
	maxDatagramAnswer  = 4096
)

// The protocol names a record and a client use.
const (
	protocolUDP = "udp"
	protocolTCP = "tcp"
)

// ErrOptions is a resolver this package refuses to build.
var ErrOptions = errors.New("dns resolver")

// Options is what the resolver enforces and where it forwards.
type Options struct {
	// Hosts are the names that resolve: the endpoint hosts of the document
	// and the zone host. Every other name answers NXDOMAIN. An empty list
	// resolves nothing, which is right for a document that names no
	// endpoint.
	Hosts []string
	// Forward are the resolvers an allowed name goes to, each an address
	// with an optional port. They are tried in order and the first answer
	// wins. At least one is required: with none, every allowed name would
	// fail.
	Forward []string
	// Listen is the address the resolver binds. New refuses a Forward
	// entry that names it, which would make the resolver forward to
	// itself.
	Listen string
	// Audit receives one record per query. It is required: a query that
	// leaves no record is a decision no operator can read.
	Audit audit.Sink
	// Logger receives what a record does not hold, such as an answer that
	// did not reach the client.
	Logger *slog.Logger
	// Timeout bounds one forwarded query against one resolver. Zero uses
	// DefaultTimeout.
	Timeout time.Duration
	// MaxConnections caps the TCP connections one listener accepts. It is
	// required: miekg/dns starts a goroutine per connection and holds it
	// for the idle window, and those descriptors are the ones the proxy's
	// own frontends and the audit writer need.
	MaxConnections int
}

// Resolver answers queries against the allowlist.
type Resolver struct {
	// allow holds each permitted name in canonical form, with its trailing
	// dot.
	allow    map[string]struct{}
	forward  []string
	sink     audit.Sink
	logger   *slog.Logger
	timeout  time.Duration
	maxConns int
	clients  map[string]*mdns.Client
}

// New builds a resolver. It refuses a configuration that could not answer
// or could not be bounded: no audit sink, no resolver to forward to, a
// forward target that is not an address, one that names the listen
// address, or no connection cap.
func New(opts Options) (*Resolver, error) {
	if opts.Audit == nil {
		return nil, fmt.Errorf("%w: no audit sink, and a query that leaves no record is unreadable", ErrOptions)
	}
	forward, err := forwardTargets(opts.Forward, opts.Listen)
	if err != nil {
		return nil, err
	}
	if opts.MaxConnections < 1 {
		return nil, fmt.Errorf("%w: MaxConnections must be at least 1, so the resolver cannot take every "+
			"file descriptor the frontends need. Set limits.max_dns_connections", ErrOptions)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	allow := make(map[string]struct{}, len(opts.Hosts))
	for _, host := range opts.Hosts {
		name := mdns.CanonicalName(strings.TrimSpace(host))
		if name == "." {
			continue
		}
		allow[name] = struct{}{}
	}
	return &Resolver{
		allow:    allow,
		forward:  forward,
		sink:     opts.Audit,
		logger:   logger,
		timeout:  timeout,
		maxConns: opts.MaxConnections,
		clients: map[string]*mdns.Client{
			protocolUDP: {Net: protocolUDP, Timeout: timeout},
			protocolTCP: {Net: protocolTCP, Timeout: timeout},
		},
	}, nil
}

// Hosts lists the names that resolve, sorted, for the start-up log and the
// admin socket.
func (r *Resolver) Hosts() []string {
	out := make([]string, 0, len(r.allow))
	for name := range r.allow {
		out = append(out, strings.TrimSuffix(name, "."))
	}
	sort.Strings(out)
	return out
}

// Forward lists the resolvers an allowed name is forwarded to.
func (r *Resolver) Forward() []string {
	return append([]string(nil), r.forward...)
}

// Handler answers with this resolver, with ctx bounding every forwarded
// query.
//
//nolint:ireturn // the dns server takes its handler as this interface
func (r *Resolver) Handler(ctx context.Context) mdns.Handler {
	return mdns.HandlerFunc(func(w mdns.ResponseWriter, query *mdns.Msg) {
		r.serve(ctx, w, query)
	})
}

// Sockets are the loopback sockets the resolver serves on, one pair per
// address family.
type Sockets struct {
	Packet []net.PacketConn
	Stream []net.Listener
}

// Addresses renders what the sockets are bound to, for the start-up log.
func (s Sockets) Addresses() string {
	parts := make([]string, 0, len(s.Packet)+len(s.Stream))
	for _, conn := range s.Packet {
		parts = append(parts, "udp "+conn.LocalAddr().String())
	}
	for _, listener := range s.Stream {
		parts = append(parts, "tcp "+listener.Addr().String())
	}
	return strings.Join(parts, ",")
}

// Close closes every socket and joins what the closes reported.
func (s Sockets) Close() error {
	errs := make([]error, 0, len(s.Packet)+len(s.Stream))
	for _, conn := range s.Packet {
		errs = append(errs, conn.Close())
	}
	for _, listener := range s.Stream {
		errs = append(errs, listener.Close())
	}
	return errors.Join(errs...)
}

// running is one server and the two signals a stop reads. started closes
// once the server is accepting and stopped closes once it has returned.
type running struct {
	server  *mdns.Server
	started chan struct{}
	stopped chan struct{}
}

// newRunning prepares a server to be stopped. miekg/dns calls
// NotifyStartedFunc from inside the accept loop, after the server marks
// itself started, so a closed started channel means a shutdown will take
// effect.
func newRunning(server *mdns.Server) *running {
	instance := &running{server: server, started: make(chan struct{}), stopped: make(chan struct{})}
	server.NotifyStartedFunc = func() { close(instance.started) }
	return instance
}

// Serve answers on every socket until ctx is cancelled, then stops them
// all. It returns once every server has stopped.
func (r *Resolver) Serve(ctx context.Context, sockets Sockets) error {
	handler := r.Handler(ctx)
	servers := make([]*running, 0, len(sockets.Packet)+len(sockets.Stream))
	for _, conn := range sockets.Packet {
		servers = append(servers, newRunning(&mdns.Server{
			PacketConn: conn, Handler: handler, UDPSize: maxDatagramAnswer,
			ReadTimeout: readTimeout, WriteTimeout: writeTimeout,
		}))
	}
	for _, listener := range sockets.Stream {
		servers = append(servers, newRunning(&mdns.Server{
			Listener: netutil.LimitListener(listener, r.maxConns), Handler: handler,
			ReadTimeout: readTimeout, WriteTimeout: writeTimeout,
			IdleTimeout: func() time.Duration { return tcpIdleTimeout }, MaxTCPQueries: maxTCPQueries,
		}))
	}
	group, ctx := errgroup.WithContext(ctx)
	for _, instance := range servers {
		group.Go(func() error {
			defer close(instance.stopped)
			if err := instance.server.ActivateAndServe(); err != nil {
				return fmt.Errorf("serve dns: %w", err)
			}
			return nil
		})
	}
	group.Go(func() error {
		<-ctx.Done()
		stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		for _, instance := range servers {
			r.stop(stop, instance)
		}
		return nil
	})
	if err := group.Wait(); err != nil {
		return fmt.Errorf("dns: %w", err)
	}
	return nil
}

// stop shuts one server down.
//
// ALWAYS wait for the start first. miekg/dns answers "server not started"
// and does nothing for a server that has not reached its accept loop, so a
// stop that ran ahead of the start would leave the server serving and
// Serve would never return. A server whose ActivateAndServe already
// returned needs no stop.
func (r *Resolver) stop(ctx context.Context, instance *running) {
	select {
	case <-instance.started:
	case <-instance.stopped:
		return
	case <-ctx.Done():
		r.logger.Info("the resolver did not start within the shutdown grace period")
		return
	}
	if err := instance.server.ShutdownContext(ctx); err != nil {
		r.logger.Info("the resolver did not stop cleanly", slog.String("error", err.Error()))
	}
}

// allows reports whether a canonical name is on the allowlist.
//
// The rule is exact equality, case-insensitive, on the whole name. A
// subdomain of an allowed host does NOT resolve: "data.upstream.test" is a
// name no endpoint declares, and answering it would hand the workload a
// channel to whatever serves that zone. The endpoint list names exact
// hosts and the connection decision matches a host exactly, so exact
// equality is what keeps the two answering the same question.
func (r *Resolver) allows(name string) bool {
	_, ok := r.allow[name]
	return ok
}

// serve answers one query. Every path writes a record and an answer: a
// query is never dropped in silence, and a failure denies rather than
// forwards.
func (r *Resolver) serve(ctx context.Context, w mdns.ResponseWriter, query *mdns.Msg) {
	protocol := protocolOf(w)
	reply, record := r.decide(ctx, query, protocol)
	record.Query.Rcode = rcodeName(reply.Rcode)
	r.sink.Emit(record)
	if protocol == protocolUDP {
		reply.Truncate(datagramLimit(query))
	}
	if err := w.WriteMsg(reply); err != nil {
		r.logger.Warn("the answer did not reach the client",
			slog.String("name", record.Destination.Host),
			slog.String("protocol", protocol),
			slog.String("error", err.Error()))
	}
}

// decide answers one query and describes the decision.
func (r *Resolver) decide(ctx context.Context, query *mdns.Msg, protocol string) (*mdns.Msg, audit.Record) {
	if query.Opcode != mdns.OpcodeQuery || len(query.Question) != 1 {
		record := newRecord("", mdns.Question{}, protocol)
		record.Decision = audit.Decision{Verdict: policy.VerdictDeny, Reason: policy.ReasonMalformedRequest}
		return answer(query, mdns.RcodeFormatError), record
	}
	question := query.Question[0]
	name := mdns.CanonicalName(question.Name)
	record := newRecord(name, question, protocol)
	if question.Qclass != mdns.ClassINET || !r.allows(name) {
		record.Decision = audit.Decision{Verdict: policy.VerdictDeny, Reason: policy.ReasonNoMatchingEndpoint}
		return answer(query, mdns.RcodeNameError), record
	}
	forwarded, err := r.forwardQuery(ctx, query, protocol)
	if err != nil {
		record.Decision = audit.Decision{
			Verdict: policy.VerdictDeny, Reason: policy.ReasonUpstreamFailed, Error: err.Error(),
		}
		return answer(query, mdns.RcodeServerFailure), record
	}
	record.Decision = audit.Decision{Verdict: policy.VerdictAllow, Reason: policy.ReasonEndpointAllowed}
	return forwarded, record
}

// forwardQuery sends an allowed query to each resolver in turn and returns
// the first answer. A resolver that errors or times out is passed over, and
// a query no resolver answered fails.
func (r *Resolver) forwardQuery(ctx context.Context, query *mdns.Msg, protocol string) (*mdns.Msg, error) {
	client := r.clients[protocol]
	outbound := outboundQuery(query)
	failures := make([]error, 0, len(r.forward))
	for _, target := range r.forward {
		attempt, cancel := context.WithTimeout(ctx, r.timeout)
		reply, _, err := client.ExchangeContext(attempt, outbound, target)
		cancel()
		if err == nil {
			reply.Id = query.Id
			return reply, nil
		}
		failures = append(failures, fmt.Errorf("%s over %s: %w", target, protocol, err))
	}
	return nil, errors.Join(failures...)
}

// outboundQuery is the message the resolver sends upstream for an allowed
// query. It is built rather than copied.
//
// NEVER forward what the client sent. The outbound message holds the
// canonical name, the type, the class and a message id of this resolver's
// own, and an OPT of this resolver's own where the client sent one. A name
// the document declares reaches its authoritative operator, and the query
// name's case bits, the client's message id and any EDNS0 option it sent
// do not.
func outboundQuery(query *mdns.Msg) *mdns.Msg {
	question := query.Question[0]
	outbound := new(mdns.Msg)
	outbound.Id = mdns.Id()
	outbound.RecursionDesired = query.RecursionDesired
	outbound.Question = []mdns.Question{{
		Name: mdns.CanonicalName(question.Name), Qtype: question.Qtype, Qclass: question.Qclass,
	}}
	if query.IsEdns0() != nil {
		//nolint:gosec // G115: datagramLimit is between 512 and maxDatagramAnswer
		outbound.SetEdns0(uint16(datagramLimit(query)), false)
	}
	return outbound
}

// newRecord is the shape every DNS record shares. The name is the
// destination, without its trailing dot, so a query reads the way the
// document writes a host.
func newRecord(name string, question mdns.Question, protocol string) audit.Record {
	return audit.Record{
		Scope:       audit.ScopeDNS,
		Destination: audit.Destination{Host: strings.TrimSuffix(name, "."), Port: DefaultPort},
		Query: &audit.QueryInfo{
			Type:     typeName(question.Qtype),
			Class:    className(question.Qclass),
			Protocol: protocol,
		},
	}
}

// answer is a reply with no records and the given response code.
func answer(query *mdns.Msg, rcode int) *mdns.Msg {
	reply := new(mdns.Msg)
	reply.SetRcode(query, rcode)
	return reply
}

// protocolOf reads which transport a query arrived on.
func protocolOf(w mdns.ResponseWriter) string {
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		return protocolTCP
	}
	return protocolUDP
}

// datagramLimit is the largest answer this query's client takes in one
// datagram. A client with no EDNS0 option takes 512 bytes, and one that
// advertises more is capped at maxDatagramAnswer.
func datagramLimit(query *mdns.Msg) int {
	size := datagramAnswerSize
	if opt := query.IsEdns0(); opt != nil {
		if advertised := int(opt.UDPSize()); advertised > size {
			size = advertised
		}
	}
	return min(size, maxDatagramAnswer)
}

// forwardTargets parses the resolvers and refuses one that is this
// resolver: a target on the listen port at an address Listen binds.
//
// Each target is an IP address with an optional port. A hostname is
// refused, because looking it up would need a resolver.
func forwardTargets(targets []string, listen string) ([]string, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("%w: no resolver to forward to, so every allowed name would fail", ErrOptions)
	}
	bound, listenPort := listenAddrs(listen)
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		addr, port, err := parseTarget(target)
		if err != nil {
			return nil, err
		}
		if port == listenPort && slices.Contains(bound, addr) {
			return nil, fmt.Errorf("%w: the resolver listens on %s and forwards to %s, so it would forward "+
				"every allowed name to itself. Name the cluster resolver instead", ErrOptions, listen, target)
		}
		out = append(out, net.JoinHostPort(addr.String(), strconv.Itoa(port)))
	}
	return out, nil
}

// parseTarget reads one resolver as an address and a port, defaulting the
// port to 53.
func parseTarget(target string) (netip.Addr, int, error) {
	text := strings.TrimSpace(target)
	if addr, err := netip.ParseAddr(text); err == nil {
		return addr.Unmap(), DefaultPort, nil
	}
	hostPort, err := netip.ParseAddrPort(text)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("%w: %q is not an IP address or address:port. A hostname would "+
			"need a resolver to look it up", ErrOptions, target)
	}
	return hostPort.Addr().Unmap(), int(hostPort.Port()), nil
}

// typeName is the query type as a record writes it, numeric for a type
// this build has no name for.
func typeName(qtype uint16) string {
	if name, ok := mdns.TypeToString[qtype]; ok {
		return name
	}
	return "TYPE" + strconv.Itoa(int(qtype))
}

// className is the query class as a record writes it.
func className(qclass uint16) string {
	if name, ok := mdns.ClassToString[qclass]; ok {
		return name
	}
	return "CLASS" + strconv.Itoa(int(qclass))
}

// rcodeName is the response code as a record writes it.
func rcodeName(rcode int) string {
	if name, ok := mdns.RcodeToString[rcode]; ok {
		return name
	}
	return "RCODE" + strconv.Itoa(rcode)
}
