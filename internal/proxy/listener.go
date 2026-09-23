package proxy

import (
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/net/netutil"
)

// limitListener caps simultaneous connections and idles each one out. A
// connection that neither reads nor writes for timeout closes at its next
// blocked read or write, whatever layer blocks on it. The idle bound only
// ever shortens a deadline, so a shorter one from a layer above survives.
func limitListener(listener net.Listener, maxConnections int, timeout time.Duration) net.Listener {
	return netutil.LimitListener(&idleListener{Listener: listener, timeout: timeout}, maxConnections)
}

// IdleConn gives a connection the same idle bound the CONNECT frontend
// applies to its own. The transparent frontend wraps each connection with
// it after it has read the original destination off the socket, because a
// wrapper with no way back to the TCP connection hides the getsockopt that
// reads it.
func IdleConn(conn net.Conn, timeout time.Duration) net.Conn {
	return &idleConn{Conn: conn, timeout: timeout}
}

type idleListener struct {
	net.Listener

	timeout time.Duration
}

func (l *idleListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err //nolint:wrapcheck // net/http reads the error's type to decide whether to retry
	}
	return &idleConn{Conn: conn, timeout: l.timeout}, nil
}

// idleConn bounds every blocked Read and Write by the idle timeout, without
// extending a deadline a caller set explicitly. A write pushes out a blocked
// read's deadline as well, so a connection that only writes is not idle.
type idleConn struct {
	net.Conn

	timeout time.Duration

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *idleConn) Read(p []byte) (int, error) {
	if err := c.arm(true); err != nil {
		return 0, err
	}
	return c.Conn.Read(p) //nolint:wrapcheck // net.Conn errors are read by type
}

func (c *idleConn) Write(p []byte) (int, error) {
	if err := c.arm(false); err != nil {
		return 0, err
	}
	return c.Conn.Write(p) //nolint:wrapcheck // net.Conn errors are read by type
}

func (c *idleConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *idleConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return c.Conn.SetReadDeadline(t) //nolint:wrapcheck // net.Conn errors are read by type
}

func (c *idleConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return c.Conn.SetWriteDeadline(t) //nolint:wrapcheck // net.Conn errors are read by type
}

// arm sets the deadline for the next blocked call to the sooner of the idle
// bound and the caller's deadline. A write also rearms the read deadline,
// because a transferring connection is not idle. Setting a deadline fails
// only on a closed connection. arm returns that error, so the call fails the
// way the read or write itself fails.
//
// arm holds the mutex from reading the caller's deadline to setting the
// underlying one. net/http aborts a pending read by setting a past deadline
// from another goroutine, and the lock keeps that abort in force.
func (c *idleConn) arm(read bool) error {
	idle := time.Now().Add(c.timeout)
	c.mu.Lock()
	defer c.mu.Unlock()
	if read {
		return c.Conn.SetReadDeadline(sooner(idle, c.readDeadline)) //nolint:wrapcheck // net.Conn errors are read by type
	}
	return errors.Join(
		c.Conn.SetWriteDeadline(sooner(idle, c.writeDeadline)),
		c.Conn.SetReadDeadline(sooner(idle, c.readDeadline)),
	)
}

// sooner is the earlier of the idle bound and a caller's explicit deadline.
// A zero explicit deadline means the caller set none.
func sooner(idle, explicit time.Time) time.Time {
	if !explicit.IsZero() && explicit.Before(idle) {
		return explicit
	}
	return idle
}

// intake is the listener the tunnel server accepts from. The frontend pushes
// each connection into it: the client side of a CONNECT tunnel, after its
// TLS handshake.
type intake struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newIntake() *intake {
	return &intake{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (q *intake) Accept() (net.Conn, error) {
	select {
	case conn := <-q.conns:
		return conn, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

func (q *intake) Close() error {
	q.once.Do(func() { close(q.done) })
	return nil
}

func (q *intake) Addr() net.Addr {
	return tunnelAddr{}
}

// push hands a connection to the tunnel server. It reports false once the
// listener is closed, and the caller then closes the connection.
func (q *intake) push(conn net.Conn) bool {
	select {
	case q.conns <- conn:
		return true
	case <-q.done:
		return false
	}
}

// tunnelAddr stands in for the address of the intake listener, which has no
// address of its own. Only diagnostics read it.
type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "tunnel" }
func (tunnelAddr) String() string  { return "tunnel" }
