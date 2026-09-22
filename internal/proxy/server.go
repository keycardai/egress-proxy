// Package proxy is the CONNECT frontend and the request pipeline behind it.
//
// goproxy accepts the CONNECT and makes the connection decision. The proxy
// then hijacks an allowed tunnel, terminates TLS with a leaf minted for the
// SNI, and hands the decrypted connection to a net/http server. That
// server's handler makes the request decision and forwards the request
// through httputil.ReverseProxy.
//
// net/http serves the loop inside the tunnel, not goproxy. goproxy v1.9.1
// dereferences a nil URL when a request inside a MITM tunnel carries an
// asterisk-form target and a Host with a port (https.go line 498). That
// panic runs in a goroutine goproxy starts, so no recover outside goproxy
// reaches it. net/http recovers a panic per connection, routes `OPTIONS *`
// to the handler through DisableGeneralOptionsHandler, and streams
// responses.
//
// This package sets two postures explicitly. The upstream transport verifies
// against a root pool the caller supplies and refuses anything below TLS
// 1.2. Nothing chains to another proxy: goproxy's constructor reads
// HTTPS_PROXY from the environment, which names this process inside a
// sandbox, so New clears both dial hooks.
package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
	"golang.org/x/sync/errgroup"

	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/internal/policy"
)

// Headers the proxy puts on a refusal, so a client that does not read the
// body still sees why.
const (
	HeaderReason    = "X-Keycard-Deny-Reason"
	HeaderRequestID = "X-Keycard-Request-Id"
)

const (
	defaultReadHeaderTimeout = 10 * time.Second
	defaultHandshakeTimeout  = 10 * time.Second
	defaultDialTimeout       = 30 * time.Second
	// defaultResponseHeaderTimeout bounds the wait for an upstream response
	// head. It bounds no body, so a streamed response is unaffected.
	defaultResponseHeaderTimeout = 30 * time.Second
	defaultIdleTimeout           = 5 * time.Minute
	defaultShutdownGrace         = 10 * time.Second
	defaultMaxConnections        = 1024

	maxIdleConns        = 100
	maxIdleConnsPerHost = 8
	upstreamIdleTimeout = 90 * time.Second
	tlsHandshakeTimeout = 10 * time.Second

	// handlerJoinBound bounds the join at the end of stop. After Close every
	// handler has a cancelled context, and every connection Close reaches is
	// closed, so a handler returns as soon as it sees either. The bound keeps
	// a handler that is stuck, or an audit sink that stalls, from holding the
	// process.
	handlerJoinBound = 5 * time.Second
)

var (
	errNoMatcher   = errors.New("proxy: no matcher")
	errNoCertStore = errors.New("proxy: no certificate store")
	errNoAudit     = errors.New("proxy: no audit sink")
	errNoRoots     = errors.New("proxy: no upstream roots")
)

// Options configures a Server. Matcher, Certificates, Audit and
// UpstreamRoots are required.
type Options struct {
	// Matcher makes the connection and request decisions.
	Matcher *policy.Matcher
	// Certificates mints the leaves the workload sees.
	Certificates *ca.Store
	// Audit receives one record per decision.
	Audit audit.Sink
	// UpstreamRoots verifies upstream certificates.
	UpstreamRoots *x509.CertPool
	// Logger records the request path. A nil logger discards.
	Logger *slog.Logger
	// MaxConnections caps simultaneous connections on the listener. Zero
	// means 1024.
	MaxConnections int
	// IdleTimeout closes a connection that neither reads nor writes for this
	// long, on the frontend, inside a tunnel, and on the upstream leg. Zero
	// means five minutes.
	IdleTimeout time.Duration
	// ResponseHeaderTimeout bounds how long an upstream has to send a
	// response head once the request is written. Zero means thirty seconds.
	// It bounds no body, so a streamed response is unaffected.
	ResponseHeaderTimeout time.Duration
	// ReadHeaderTimeout bounds how long a client can take to send a request
	// head. Zero means ten seconds.
	ReadHeaderTimeout time.Duration
	// HandshakeTimeout bounds the TLS handshake inside a tunnel. Zero means
	// ten seconds.
	HandshakeTimeout time.Duration
	// DialTimeout bounds one upstream dial. Zero means thirty seconds.
	DialTimeout time.Duration
	// ShutdownGrace is how long Run waits for in-flight requests after its
	// context is cancelled before closing every connection. Zero means ten
	// seconds.
	ShutdownGrace time.Duration
}

func (o Options) withDefaults() Options {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.MaxConnections <= 0 {
		o.MaxConnections = defaultMaxConnections
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = defaultIdleTimeout
	}
	if o.ReadHeaderTimeout <= 0 {
		o.ReadHeaderTimeout = defaultReadHeaderTimeout
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = defaultHandshakeTimeout
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = defaultDialTimeout
	}
	if o.ResponseHeaderTimeout <= 0 {
		o.ResponseHeaderTimeout = defaultResponseHeaderTimeout
	}
	if o.ShutdownGrace <= 0 {
		o.ShutdownGrace = defaultShutdownGrace
	}
	return o
}

// Server is the CONNECT frontend. Run serves it until its context is
// cancelled.
type Server struct {
	opts      Options
	logger    *slog.Logger
	front     *http.Server
	tunnels   *http.Server
	intake    *intake
	transport *http.Transport
	reverse   *httputil.ReverseProxy
	handlers  inflight
}

// New builds the proxy.
func New(opts Options) (*Server, error) {
	switch {
	case opts.Matcher == nil:
		return nil, errNoMatcher
	case opts.Certificates == nil:
		return nil, errNoCertStore
	case opts.Audit == nil:
		return nil, errNoAudit
	case opts.UpstreamRoots == nil:
		return nil, errNoRoots
	}
	opts = opts.withDefaults()
	server := &Server{opts: opts, logger: opts.Logger, intake: newIntake()}
	server.transport = server.newTransport()
	server.reverse = &httputil.ReverseProxy{
		Rewrite:   rewrite,
		Transport: server.transport,
		// Responses stream: LLM traffic is server-sent events, and a
		// buffered proxy stalls it.
		FlushInterval:  -1,
		ModifyResponse: server.recordUpstreamStatus,
		ErrorHandler:   server.upstreamError,
		ErrorLog:       slog.NewLogLogger(opts.Logger.Handler(), slog.LevelWarn),
	}

	var http1 http.Protocols
	http1.SetHTTP1(true)
	errorLog := slog.NewLogLogger(opts.Logger.Handler(), slog.LevelWarn)
	server.front = &http.Server{
		Handler:           server.newFrontend(),
		ReadHeaderTimeout: opts.ReadHeaderTimeout,
		IdleTimeout:       opts.IdleTimeout,
		ErrorLog:          errorLog,
		Protocols:         &http1,
	}
	server.tunnels = &http.Server{
		Handler:           http.HandlerFunc(server.serveTunnelRequest),
		ReadHeaderTimeout: opts.ReadHeaderTimeout,
		IdleTimeout:       opts.IdleTimeout,
		ErrorLog:          errorLog,
		Protocols:         &http1,
		// The handler answers `OPTIONS *` like any other request, so the
		// proxy refuses and audits it.
		DisableGeneralOptionsHandler: true,
		ConnContext:                  tunnelContext,
	}
	return server, nil
}

// Run serves the listener until ctx is cancelled or a server fails, then
// stops both servers: a graceful shutdown bounded by ShutdownGrace, and a
// close of whatever is still open. It returns the first server failure, or
// nil after a shutdown the context asked for. Call Run once per Server.
//
// A request carries the run context's values and not its cancellation, so
// cancelling ctx starts the drain. The requests still open when the drain
// ends are cancelled, which is how an upgraded connection ends, because
// Close does not reach a hijacked connection.
func (s *Server) Run(ctx context.Context, listener net.Listener) error {
	limited := limitListener(listener, s.opts.MaxConnections, s.opts.IdleTimeout)
	group, ctx := errgroup.WithContext(ctx)
	requestCtx, endRequests := context.WithCancel(context.WithoutCancel(ctx))
	defer endRequests()
	base := func(net.Listener) context.Context { return requestCtx }
	s.front.BaseContext = base
	s.tunnels.BaseContext = base
	group.Go(func() error { return served("frontend", s.front.Serve(limited)) })
	group.Go(func() error { return served("tunnels", s.tunnels.Serve(s.intake)) })
	group.Go(func() error {
		<-ctx.Done()
		s.stop(ctx, endRequests)
		return nil
	})
	if err := group.Wait(); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	return nil
}

// served maps the return of http.Server.Serve: a shutdown is not a failure.
func served(name string, err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("%s: %w", name, err)
}

// inflight counts the tunnel handlers still running. stop waits on it
// after Close, because a handler the reverse proxy hijacked for an upgrade
// ends on its own goroutine and emits its record last, and Close does not
// wait for it. The wait seals the counter first, so the set it joins cannot
// grow while it joins.
type inflight struct {
	mu      sync.Mutex
	running int
	// sealed is set by wait. A sealed counter admits no handler.
	sealed bool
	// drained is set by wait and closed by the leave that brings running
	// to zero.
	drained chan struct{}
}

// enter counts a handler and reports whether it may serve. A sealed counter
// admits none, and a handler it refuses calls no leave.
func (f *inflight) enter() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sealed {
		return false
	}
	f.running++
	return true
}

func (f *inflight) leave() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running--
	if f.running == 0 && f.drained != nil {
		close(f.drained)
		f.drained = nil
	}
}

// wait seals the counter and reports whether the handlers finished within
// bound.
func (f *inflight) wait(bound time.Duration) bool {
	f.mu.Lock()
	f.sealed = true
	if f.running == 0 {
		f.mu.Unlock()
		return true
	}
	f.drained = make(chan struct{})
	drained := f.drained
	f.mu.Unlock()
	select {
	case <-drained:
		return true
	case <-time.After(bound):
		return false
	}
}

// stop drains both servers for the grace period, then ends the requests
// still open and closes what remains. It logs a shutdown that ran out of
// time and finishes it with Close. endRequests runs before Close because
// Close does not reach a connection a handler hijacked. It then joins the
// tunnel handlers for up to handlerJoinBound, so the records of the handlers
// that finish in time land before Run returns, and logs a join that ran out
// of time. Nothing here fails the run.
func (s *Server) stop(ctx context.Context, endRequests context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.opts.ShutdownGrace)
	defer cancel()
	if err := errors.Join(s.front.Shutdown(ctx), s.tunnels.Shutdown(ctx)); err != nil {
		s.logger.Warn("graceful shutdown did not finish within the grace period; closing the remaining connections",
			slog.Duration("grace", s.opts.ShutdownGrace),
			slog.String("error", err.Error()))
	}
	endRequests()
	if err := errors.Join(s.front.Close(), s.tunnels.Close()); err != nil && !errors.Is(err, net.ErrClosed) {
		s.logger.Warn("closing the servers", slog.String("error", err.Error()))
	}
	if !s.handlers.wait(handlerJoinBound) {
		s.logger.Warn("tunnel handlers still running after the close",
			slog.Duration("bound", handlerJoinBound))
	}
	s.transport.CloseIdleConnections()
}

// newFrontend wires goproxy as the CONNECT frontend.
func (s *Server) newFrontend() *goproxy.ProxyHttpServer {
	front := goproxy.NewProxyHttpServer()
	front.Verbose = false
	front.Logger = printfLogger{logger: s.logger}
	front.Tr = s.transport
	// NEVER leave these set. The constructor fills them from HTTPS_PROXY.
	front.ConnectDial = nil
	front.ConnectDialWithReq = nil
	front.NonproxyHandler = http.HandlerFunc(s.serveNonProxy)
	front.OnRequest().HandleConnectFunc(s.handleConnect)
	front.OnRequest().DoFunc(s.handlePlain)
	return front
}

// newTransport is the upstream leg: TLS 1.2 or better verified against the
// given roots, no proxy, and a deny list check on every resolved address
// before the socket connects.
//
// Four budgets bound an upstream that goes quiet, because a stalled request
// holds a frontend connection and the connection cap is finite. The dial and
// the TLS handshake each carry one. ResponseHeaderTimeout bounds the wait
// for a response head. Every upstream connection carries the same idle bound
// the frontend uses, which covers a body that stops arriving. Nothing bounds
// a whole request, because a server-sent event stream is a long request that
// is working.
func (s *Server) newTransport() *http.Transport {
	deny := s.opts.Matcher.DenyList()
	dialer := &net.Dialer{
		Timeout: s.opts.DialTimeout,
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			addrPort, err := netip.ParseAddrPort(address)
			if err != nil {
				return &deniedError{address: address}
			}
			if deny.DeniesAddr(addrPort.Addr()) {
				return &deniedError{address: address}
			}
			return nil
		},
	}
	idle := s.opts.IdleTimeout
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err //nolint:wrapcheck // the transport reads the error by type
			}
			return &idleConn{Conn: conn, timeout: idle}, nil
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    s.opts.UpstreamRoots,
		},
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		IdleConnTimeout:       upstreamIdleTimeout,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: s.opts.ResponseHeaderTimeout,
	}
}

// deniedError is the dial guard's refusal: the name resolved into a denied
// range.
type deniedError struct {
	address string
}

func (e *deniedError) Error() string {
	return "the destination resolved to " + e.address + ", which the platform deny list covers"
}

// newID is a connection or request identifier.
func newID() string {
	return rand.Text()
}

// printfLogger adapts slog to goproxy's Logger interface.
type printfLogger struct {
	logger *slog.Logger
}

func (l printfLogger) Printf(format string, v ...any) {
	l.logger.Debug(fmt.Sprintf(format, v...), slog.String("component", "goproxy"))
}
