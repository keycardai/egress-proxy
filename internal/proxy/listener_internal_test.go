package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestIdleConnKeepsAnAbortDeadlineSetDuringArm pins the ordering arm
// promises. When another goroutine sets a past deadline while arm runs, the
// blocked read sees that past deadline and returns. net/http relies on this
// to abort its background read before a hijack.
func TestIdleConnKeepsAnAbortDeadlineSetDuringArm(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	conn := &idleConn{Conn: server, timeout: time.Hour}

	const rounds = 200
	for range rounds {
		var group sync.WaitGroup
		errs := make(chan error, 1)
		group.Add(2)
		go func() {
			defer group.Done()
			_, err := conn.Read(make([]byte, 1))
			errs <- err
		}()
		go func() {
			defer group.Done()
			_ = conn.SetReadDeadline(time.Unix(1, 0))
		}()
		group.Wait()
		select {
		case err := <-errs:
			timeout, ok := err.(net.Error) //nolint:errorlint // net.Pipe returns it unwrapped
			require.True(t, ok && timeout.Timeout(), "Read = %v, want a timeout from the abort deadline", err)
		case <-time.After(5 * time.Second):
			require.Fail(t, "the read stayed blocked past the abort deadline")
		}
		_ = conn.SetReadDeadline(time.Time{})
	}
}

// TestIdleConnForwardsCloseWrite pins that the half-close reaches the TCP
// connection through the wrapper. The compile-time assertion on CloseWriter
// pins that idleConn declares the method. This pins that calling it shuts
// down the writing side of the socket underneath.
func TestIdleConnForwardsCloseWrite(t *testing.T) {
	t.Parallel()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err, "listen")
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	client, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", listener.Addr().String())
	require.NoError(t, err, "dial")
	t.Cleanup(func() { _ = client.Close() })
	server := <-accepted
	t.Cleanup(func() { _ = server.Close() })

	closer, ok := IdleConn(server, time.Hour).(CloseWriter)
	require.True(t, ok, "the wrapper has CloseWrite")
	require.NoError(t, closer.CloseWrite(), "half-close the wrapped connection")

	// The half-close reached the peer, so the client reads EOF while its own
	// direction is still open.
	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)), "deadline on the read")
	buf := make([]byte, 1)
	_, err = client.Read(buf)
	require.ErrorIs(t, err, io.EOF, "the client sees the peer finish writing")
	_, err = client.Write([]byte("the client can still write"))
	require.NoError(t, err, "the client's own direction is still open")
}

// TestIdleConnCloseWriteOnAConnectionWithoutOne reports the half-close is
// unavailable rather than claiming it happened.
func TestIdleConnCloseWriteOnAConnectionWithoutOne(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	closer, ok := IdleConn(server, time.Hour).(CloseWriter)
	require.True(t, ok, "the wrapper has CloseWrite")
	require.ErrorIs(t, closer.CloseWrite(), errors.ErrUnsupported, "a pipe cannot half-close")
}
