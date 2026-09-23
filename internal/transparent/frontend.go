package transparent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/keycardai/egress-proxy/internal/policy"
	"github.com/keycardai/egress-proxy/internal/proxy"
)

// defaultPeekTimeout bounds how long a client has to send the bytes the
// destination is read from. A client that sends nothing holds a goroutine
// and a socket and is decided against nothing.
const defaultPeekTimeout = 10 * time.Second

// The options a Frontend cannot be built without. The process reads all
// three from the document, which has a default for each, so a zero here
// is a caller that never asked what bound it wanted.
var (
	errNoHandler        = errors.New("transparent: no handler to serve a redirected connection with")
	errNoMaxConnections = errors.New("transparent: MaxConnections must be positive")
	errNoIdleTimeout    = errors.New("transparent: IdleTimeout must be positive")
)

// Options configures a Frontend. Handler is required.
type Options struct {
	// Handler takes over each recovered connection. proxy.Server.ServeRedirected
	// is the one this process uses, so one decision path serves both
	// frontends.
	Handler func(net.Conn, proxy.Redirected)
	// Logger records what the frontend could not read. A nil logger
	// discards.
	Logger *slog.Logger
	// OriginalDst recovers the pre-redirect destination. Nil uses
	// SO_ORIGINAL_DST, which exists only on Linux.
	OriginalDst func(net.Conn) (netip.AddrPort, error)
	// CleartextPorts are the destination ports read as cleartext HTTP.
	// Every port outside this set is read as TLS.
	CleartextPorts []int
	// PeekTimeout bounds how long the client has to send the ClientHello or
	// the request head. Zero means ten seconds.
	PeekTimeout time.Duration
	// MaxConnections caps simultaneous connections across every listener
	// this frontend serves. It is required. This frontend and the CONNECT
	// frontend each keep their own count against it.
	MaxConnections int
	// IdleTimeout closes a connection that neither reads nor writes for
	// this long. It is required.
	IdleTimeout time.Duration
}

// Frontend accepts redirected connections, recovers what each was opened to,
// and hands it to the proxy.
type Frontend struct {
	handler        func(net.Conn, proxy.Redirected)
	logger         *slog.Logger
	originalDst    func(net.Conn) (netip.AddrPort, error)
	cleartextPorts map[int]bool
	peekTimeout    time.Duration
	idleTimeout    time.Duration
	// slots caps simultaneous connections. A connection holds one from the
	// accept that produced it until it closes.
	slots chan struct{}
}

// New builds a Frontend.
func New(options Options) (*Frontend, error) {
	if options.Handler == nil {
		return nil, errNoHandler
	}
	if options.MaxConnections <= 0 {
		return nil, errNoMaxConnections
	}
	if options.IdleTimeout <= 0 {
		return nil, errNoIdleTimeout
	}
	frontend := &Frontend{
		handler:        options.Handler,
		logger:         options.Logger,
		originalDst:    options.OriginalDst,
		cleartextPorts: make(map[int]bool, len(options.CleartextPorts)),
		peekTimeout:    options.PeekTimeout,
	}
	if frontend.logger == nil {
		frontend.logger = slog.New(slog.DiscardHandler)
	}
	if frontend.originalDst == nil {
		frontend.originalDst = OriginalDestination
	}
	if frontend.peekTimeout <= 0 {
		frontend.peekTimeout = defaultPeekTimeout
	}
	frontend.idleTimeout = options.IdleTimeout
	frontend.slots = make(chan struct{}, options.MaxConnections)
	for _, port := range options.CleartextPorts {
		frontend.cleartextPorts[port] = true
	}
	return frontend, nil
}

// Serve accepts until ctx is cancelled or the listener fails, then waits for
// the connections it is still reading. It is called once per listener,
// because a wildcard address is bound one socket per address family.
//
// A failed accept stops the frontend and, through the errgroup that composes
// the process, the proxy with it. The filter table drops what this listener
// does not receive, so a frontend that cannot accept leaves the workload
// contained rather than free.
func (f *Frontend) Serve(ctx context.Context, listener net.Listener) error {
	// The listener is closed on every return, not only on cancellation, so an
	// accept that failed for its own reason does not leave the socket bound.
	defer func() { _ = listener.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	var reading sync.WaitGroup
	defer reading.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("transparent: accept on %s: %w", listener.Addr(), err)
		}
		// A slot is taken after the accept, so a listener waiting for a
		// connection holds none. At the cap, each listener holds one accepted
		// connection unread until a slot frees.
		select {
		case f.slots <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			return nil
		}
		reading.Go(func() { f.handle(ctx, conn) })
	}
}

// release returns a slot to the cap. handle wraps it so one connection
// returns its slot once.
func (f *Frontend) release() {
	<-f.slots
}

// handle recovers a destination for one connection and hands it on. A panic
// costs this connection and nothing else, which is the recovery the CONNECT
// frontend gets from http.Server.
func (f *Frontend) handle(ctx context.Context, conn net.Conn) {
	// The slot this connection holds is returned once, whichever path ends
	// it: a panic, a destination that could not be read, or the close the
	// proxy makes when it is done with the connection.
	var once sync.Once
	release := func() { once.Do(f.release) }
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		f.logger.Error("recovered a panic on a redirected connection; the connection is closed",
			slog.Any("panic", recovered),
			slog.String("stack", string(debug.Stack())))
		_ = conn.Close()
		release()
	}()
	// The original destination is read off the socket the kernel accepted,
	// before any wrapper stands between this code and the file descriptor
	// the getsockopt needs.
	original, err := f.originalDst(conn)
	if err != nil {
		// With no pre-redirect address there is no destination to decide, to
		// record or to dial, so there is nothing to refuse either.
		f.logger.Error("a redirected connection could not be attributed to a destination",
			slog.String("remote", addrText(conn.RemoteAddr())),
			slog.String("local", addrText(conn.LocalAddr())),
			slog.String("error", err.Error()))
		_ = conn.Close()
		release()
		return
	}
	bounded := &peekedConn{Conn: proxy.IdleConn(conn, f.idleTimeout), release: release}
	bounded.reader = bufio.NewReaderSize(bounded.Conn, PeekBufferSize)
	dst := f.destination(ctx, bounded, bounded.reader, original)
	f.handler(bounded, dst)
}

// destination reads what the client is trying to reach and settles the
// refusal when it cannot be read.
//
// The peek NEVER consumes. Every byte it looked at is still in the reader
// the proxy goes on to use, so the handshake or the request that follows is
// the client's own.
func (f *Frontend) destination(
	ctx context.Context, conn net.Conn, reader *bufio.Reader, original netip.AddrPort,
) proxy.Redirected {
	port := int(original.Port())
	dst := proxy.Redirected{
		Host:      original.Addr().String(),
		Port:      port,
		Address:   original,
		Cleartext: f.cleartextPorts[port],
	}
	// A connection whose recovered destination is this listener's own
	// address was opened to the proxy rather than redirected into it.
	// Deciding it against the address would name this process as the
	// destination.
	if sameAddress(original, conn.LocalAddr()) {
		dst.Refusal = policy.ReasonNotRedirected
		return dst
	}
	// A cleartext connection is refused whatever its head says, so the
	// reason does not wait on a name the peek may not find.
	unreadable := policy.ReasonNoSNI
	if dst.Cleartext {
		unreadable = policy.ReasonCleartextNotForwarded
	}
	if err := conn.SetReadDeadline(time.Now().Add(f.peekTimeout)); err != nil {
		f.logger.Error("a redirected connection could not be given a read deadline",
			slog.String("address", original.String()),
			slog.String("error", err.Error()))
		dst.Refusal = unreadable
		return dst
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	name, err := f.name(ctx, reader, dst.Cleartext)
	if err != nil {
		f.logger.Info("a redirected connection named no destination",
			slog.String("address", original.String()),
			slog.Bool("cleartext", dst.Cleartext),
			slog.String("error", err.Error()))
		dst.Refusal = unreadable
		return dst
	}
	host, named, ok := splitAuthority(name, port)
	if !ok || named != port {
		// The name gives a port the connection was not opened to, so the
		// two disagree about the destination.
		f.logger.Info("a redirected connection named a port the connection was not opened to",
			slog.String("address", original.String()),
			slog.String("name", name))
		dst.Refusal = policy.ReasonHostMismatch
		return dst
	}
	// RFC 6066 section 3 forbids an IP literal in server_name, and a Host
	// header may give one. A name that is an address must be the address
	// the connection was opened to.
	if literal, parseErr := netip.ParseAddr(host); parseErr == nil && literal.Unmap() != original.Addr().Unmap() {
		f.logger.Info("a redirected connection named an address the connection was not opened to",
			slog.String("address", original.String()),
			slog.String("name", host))
		dst.Refusal = policy.ReasonHostMismatch
		return dst
	}
	dst.Host = policy.NormalizeHost(host)
	return dst
}

// name reads the destination the client named: the server name from the
// ClientHello, or the Host header on a cleartext port.
func (f *Frontend) name(ctx context.Context, reader *bufio.Reader, cleartext bool) (string, error) {
	if cleartext {
		return PeekHost(reader)
	}
	return PeekServerName(ctx, reader)
}

// splitAuthority reads a name that may have a port, defaulting to the port
// the connection was opened to. It reports false for a port outside 1 to
// 65535.
func splitAuthority(authority string, defaultPort int) (string, int, bool) {
	host, rawPort, err := net.SplitHostPort(authority)
	if err != nil {
		return unbracket(authority), defaultPort, true
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

// unbracket removes the brackets around an IPv6 literal. Only a matched pair
// is removed, so the host the frontend decides against is the host the TLS
// termination derives from the same bytes. NEVER strip one bracket without
// the other: the two would then disagree about the destination, and the
// decision would be recorded against a name the handshake never saw.
func unbracket(authority string) string {
	if len(authority) >= 2 && authority[0] == '[' && authority[len(authority)-1] == ']' {
		return authority[1 : len(authority)-1]
	}
	return authority
}

// sameAddress reports whether a recovered destination is the address the
// connection was accepted on.
func sameAddress(original netip.AddrPort, local net.Addr) bool {
	tcp, ok := local.(*net.TCPAddr)
	if !ok {
		return false
	}
	addr, ok := netip.AddrFromSlice(tcp.IP)
	return ok && addr.Unmap() == original.Addr().Unmap() && int(original.Port()) == tcp.Port
}

func addrText(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

// peekedConn is the accepted connection with the bytes the frontend looked
// at still in front of it. Reads come from the buffered reader, so the
// ClientHello or the request head the peek decoded is still the first thing
// the proxy reads.
type peekedConn struct {
	net.Conn

	reader *bufio.Reader
	drain  bool
	// release returns this connection's slot against the connection cap. It
	// counts one connection however many times Close is called.
	release func()
}

var _ proxy.CloseWriter = (*peekedConn)(nil)

func (c *peekedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p) //nolint:wrapcheck // net.Conn errors are read by type
}

// CloseWrite half-closes the connection the proxy was handed. Close makes
// the half-close the drain needs on its own, so this is for a handler that
// finishes writing before it is done reading.
func (c *peekedConn) CloseWrite() error {
	closer, ok := c.Conn.(proxy.CloseWriter)
	if !ok {
		return fmt.Errorf("%w: %T has no CloseWrite", errors.ErrUnsupported, c.Conn)
	}
	return closer.CloseWrite() //nolint:wrapcheck // net.Conn errors are read by type
}

// DrainOnClose makes the next Close read what the client is still sending
// first. A socket closed with unread data in its receive buffer sends RST,
// and the RST discards whatever was written to it, which on a refusal is the
// reason the workload was meant to read.
func (c *peekedConn) DrainOnClose() {
	c.drain = true
}

// drainLimit and drainTimeout bound the orderly close. Both are small: the
// drain exists to let a refusal reach the client, not to read the workload's
// request.
const (
	drainLimit   = 64 << 10
	drainTimeout = 250 * time.Millisecond
)

func (c *peekedConn) Close() error {
	if c.drain {
		c.drain = false
		if closer, ok := c.Conn.(proxy.CloseWriter); ok {
			_ = closer.CloseWrite()
		}
		_ = c.SetReadDeadline(time.Now().Add(drainTimeout))
		_, _ = io.Copy(io.Discard, io.LimitReader(c.Conn, drainLimit))
	}
	err := c.Conn.Close()
	c.release()
	return err //nolint:wrapcheck // net.Conn errors are read by type
}
