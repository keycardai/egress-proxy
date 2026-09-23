package transparent_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/keycardai/egress-proxy/internal/policy"
	"github.com/keycardai/egress-proxy/internal/proxy"
	"github.com/keycardai/egress-proxy/internal/transparent"
)

// captured is one connection the frontend handed on, with what it recovered
// and the bytes still in front of it.
type captured struct {
	dst  proxy.Redirected
	head []byte
	err  error
}

// frontend runs a Frontend on a loopback listener with a fixed answer for
// the pre-redirect destination, and reports each connection it hands on.
// originalDst is called with the accepted connection, so a case can answer
// with the listener's own address.
func frontend(
	t *testing.T, originalDst func(net.Conn) (netip.AddrPort, error), cleartextPorts []int,
) (string, <-chan captured) {
	t.Helper()
	handed := make(chan captured, 1)
	front, err := transparent.New(transparent.Options{
		CleartextPorts: cleartextPorts,
		OriginalDst:    originalDst,
		PeekTimeout:    2 * time.Second,
		MaxConnections: 8,
		IdleTimeout:    30 * time.Second,
		Handler: func(conn net.Conn, dst proxy.Redirected) {
			defer func() { _ = conn.Close() }()
			// Reading what is left proves the peek consumed nothing: the
			// handler sees the client's own first bytes.
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			head, readErr := io.ReadAll(conn)
			if errors.Is(readErr, os.ErrDeadlineExceeded) {
				readErr = nil
			}
			handed <- captured{dst: dst, head: head, err: readErr}
		},
	})
	require.NoError(t, err, "build the frontend")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	var group errgroup.Group
	group.Go(func() error { return front.Serve(ctx, listener) })
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, group.Wait(), "Serve after cancellation")
	})
	return listener.Addr().String(), handed
}

func TestTheFrontendRecoversWhatAConnectionWasOpenedTo(t *testing.T) {
	t.Parallel()
	hello := clientHello(t, &tls.Config{ServerName: "upstream.test", MinVersion: tls.VersionTLS12})
	//nolint:gosec // G402: a fixture client that never completes a handshake
	anonymous := clientHello(t, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})

	tests := []struct {
		name string
		// original is the pre-redirect destination the recovery answers
		// with. The empty string means the listener's own address.
		original    string
		head        []byte
		wantHost    string
		wantPort    int
		wantClear   bool
		wantRefusal policy.Reason
	}{
		{
			name:     "a TLS connection naming a server",
			original: "192.0.2.77:443", head: hello,
			wantHost: "upstream.test", wantPort: 443,
		},
		{
			name:     "a TLS connection on a captured port that is not 443",
			original: "192.0.2.77:8443", head: hello,
			wantHost: "upstream.test", wantPort: 8443,
		},
		{
			name:     "a TLS connection naming no server",
			original: "192.0.2.77:443", head: anonymous,
			wantHost: "192.0.2.77", wantPort: 443, wantRefusal: policy.ReasonNoSNI,
		},
		{
			// The peek deadline is what ends this connection. Nothing names
			// a destination, so the connection is refused the way one whose
			// ClientHello carries no server_name is.
			name:     "a client that sends nothing at all",
			original: "192.0.2.77:443", head: []byte{},
			wantHost: "192.0.2.77", wantPort: 443, wantRefusal: policy.ReasonNoSNI,
		},
		{
			name:     "a client that sends a partial ClientHello and stops",
			original: "192.0.2.77:443", head: hello[:20],
			wantHost: "192.0.2.77", wantPort: 443, wantRefusal: policy.ReasonNoSNI,
		},
		{
			name:     "a client that sends nothing at all on a cleartext port",
			original: "192.0.2.77:80", head: []byte{},
			wantHost: "192.0.2.77", wantPort: 80, wantClear: true,
			wantRefusal: policy.ReasonCleartextNotForwarded,
		},
		{
			name:     "a cleartext connection naming a host",
			original: "192.0.2.77:80", head: []byte("GET /p HTTP/1.1\r\nHost: upstream.test\r\n\r\n"),
			wantHost: "upstream.test", wantPort: 80, wantClear: true,
		},
		{
			// RFC 6066 section 3 forbids an IP literal in server_name and
			// crypto/tls sends none for one, so only a Host header carries
			// an address.
			name:     "a cleartext connection whose Host is the address it was opened to",
			original: "192.0.2.77:80", head: []byte("GET /p HTTP/1.1\r\nHost: 192.0.2.77\r\n\r\n"),
			wantHost: "192.0.2.77", wantPort: 80, wantClear: true,
		},
		{
			name:     "a cleartext connection whose Host is an address it was not opened to",
			original: "192.0.2.77:80", head: []byte("GET /p HTTP/1.1\r\nHost: 198.51.100.1\r\n\r\n"),
			wantHost: "192.0.2.77", wantPort: 80, wantClear: true, wantRefusal: policy.ReasonHostMismatch,
		},
		{
			name:     "a cleartext connection whose Host names another port",
			original: "192.0.2.77:80", head: []byte("GET /p HTTP/1.1\r\nHost: upstream.test:8080\r\n\r\n"),
			wantHost: "192.0.2.77", wantPort: 80, wantClear: true, wantRefusal: policy.ReasonHostMismatch,
		},
		{
			name:     "a cleartext connection carrying no Host header",
			original: "192.0.2.77:80", head: []byte("GET /p HTTP/1.1\r\n\r\n"),
			// A cleartext connection is refused whatever its head says, so
			// one the frontend cannot read names the same reason as one it
			// can.
			wantHost: "192.0.2.77", wantPort: 80, wantClear: true,
			wantRefusal: policy.ReasonCleartextNotForwarded,
		},
		{
			name:     "a connection opened to the listener rather than redirected into it",
			original: "", head: hello,
			wantRefusal: policy.ReasonNotRedirected,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			answer := func(conn net.Conn) (netip.AddrPort, error) {
				if tc.original == "" {
					return netip.MustParseAddrPort(conn.LocalAddr().String()), nil
				}
				return netip.MustParseAddrPort(tc.original), nil
			}
			addr, handed := frontend(t, answer, []int{80})
			conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
			require.NoError(t, err, "dial the frontend")
			t.Cleanup(func() { _ = conn.Close() })
			_, err = conn.Write(tc.head)
			require.NoError(t, err, "send the head")

			got := waitCaptured(t, handed)
			require.NoError(t, got.err, "read what is left on the connection")
			assert.Equal(t, tc.head, got.head, "the peek consumed nothing")
			assert.Equal(t, tc.wantRefusal, got.dst.Refusal, "the refusal the frontend settled")
			if tc.original == "" {
				return
			}
			assert.Equal(t, tc.wantHost, got.dst.Host, "the name the client used")
			assert.Equal(t, tc.wantPort, got.dst.Port, "the port the connection was opened to")
			assert.Equal(t, tc.wantClear, got.dst.Cleartext, "whether the connection reads as cleartext")
			assert.Equal(t, tc.original, got.dst.Address.String(), "the pre-redirect address")
		})
	}
}

// TestAConnectionWithNoRecoverableDestinationIsClosed proves the frontend
// hands on nothing it cannot attribute. There is no destination to decide,
// to record or to dial, so there is nothing to refuse either.
func TestAConnectionWithNoRecoverableDestinationIsClosed(t *testing.T) {
	t.Parallel()
	refuse := func(net.Conn) (netip.AddrPort, error) { return netip.AddrPort{}, transparent.ErrNotSupported }
	addr, handed := frontend(t, refuse, nil)
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
	require.NoError(t, err, "dial the frontend")
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)), "deadline on the read")
	_, err = io.ReadAll(conn)
	require.NoError(t, err, "the frontend closed the connection")
	select {
	case got := <-handed:
		require.Fail(t, "the frontend handed on a connection it could not attribute", "%+v", got.dst)
	default:
	}
}

// TestNewRefusals pins the options a frontend cannot be built without. The
// process reads each from the document, which carries a default for it, so a
// zero here is a caller that never asked what bound it wanted.
func TestNewRefusals(t *testing.T) {
	t.Parallel()
	handler := func(net.Conn, proxy.Redirected) {}
	tests := []struct {
		name    string
		options transparent.Options
		want    string
	}{
		{
			name:    "nowhere to hand a connection",
			options: transparent.Options{MaxConnections: 1, IdleTimeout: time.Second},
			want:    "no handler",
		},
		{
			name:    "no cap on simultaneous connections",
			options: transparent.Options{Handler: handler, IdleTimeout: time.Second},
			want:    "MaxConnections must be positive",
		},
		{
			name:    "no idle bound",
			options: transparent.Options{Handler: handler, MaxConnections: 1},
			want:    "IdleTimeout must be positive",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := transparent.New(tc.options)
			require.Error(t, err, "the frontend is refused")
			assert.Contains(t, err.Error(), tc.want, "the error names the missing option")
		})
	}
}

func waitCaptured(t *testing.T, handed <-chan captured) captured {
	t.Helper()
	select {
	case got := <-handed:
		return got
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the frontend handed on no connection")
		return captured{}
	}
}

// TestTheConnectionCapHoldsUntilAConnectionCloses proves the transparent
// listener carries the same bound the CONNECT frontend does. A slot is
// taken before the accept, so a connection past the cap waits in the
// backlog rather than reaching a frontend that will not read it.
func TestTheConnectionCapHoldsUntilAConnectionCloses(t *testing.T) {
	t.Parallel()
	handed := make(chan net.Conn, 2)
	front, err := transparent.New(transparent.Options{
		MaxConnections: 1,
		IdleTimeout:    30 * time.Second,
		PeekTimeout:    time.Second,
		OriginalDst: func(net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("192.0.2.77:443"), nil
		},
		Handler: func(conn net.Conn, _ proxy.Redirected) { handed <- conn },
	})
	require.NoError(t, err, "build the frontend")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	var group errgroup.Group
	group.Go(func() error { return front.Serve(ctx, listener) })
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, group.Wait(), "Serve after cancellation")
	})

	first, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", listener.Addr().String())
	require.NoError(t, err, "the first connection")
	t.Cleanup(func() { _ = first.Close() })
	held := waitConn(t, handed)
	second, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", listener.Addr().String())
	require.NoError(t, err, "the second connection reaches the backlog")
	t.Cleanup(func() { _ = second.Close() })
	select {
	case <-handed:
		require.Fail(t, "the frontend handled a connection past the cap")
	case <-time.After(250 * time.Millisecond):
	}
	// Closing the first connection returns its slot, so the second is
	// accepted.
	require.NoError(t, held.Close(), "close the first connection")
	waitConn(t, handed)
}

func waitConn(t *testing.T, handed <-chan net.Conn) net.Conn {
	t.Helper()
	select {
	case conn := <-handed:
		return conn
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the frontend handed on no connection")
		return nil
	}
}
