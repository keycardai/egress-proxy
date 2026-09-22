package proxy

import (
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
