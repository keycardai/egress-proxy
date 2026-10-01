package transparent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// PeekBufferSize is how far ahead the frontend looks for a ClientHello or a
// request head. It leaves room for two whole TLS records, header included:
// one record with its maximum legal payload of 2^14 bytes has to fit,
// and a ClientHello may be fragmented across records (RFC 8446 section 5.1).
//
// A ClientHello or a request head larger than this is refused rather than
// forwarded. A host-scoped policy is evaluated against the name the client
// used, so a head that cannot be read is a connection that cannot be
// decided.
const PeekBufferSize = 2 * (maxRecordPayload + recordHeaderLen)

// The TLS record framing PeekBufferSize is sized from, RFC 8446 section 5.1.
const (
	maxRecordPayload = 1 << 14
	recordHeaderLen  = 5
)

var (
	// ErrNoServerName is returned for a connection whose ClientHello has
	// no server_name extension. RFC 6066 section 3 forbids an IP literal
	// there, so a client connecting straight to an address sends none.
	ErrNoServerName = errors.New("the ClientHello has no server name")
	// ErrNoHost is returned for a cleartext request that has no usable
	// Host header.
	ErrNoHost = errors.New("the request has no Host header")
)

// errHelloRead ends the sniffing handshake once the ClientHello has been
// decoded. Nothing outside this file sees it.
var errHelloRead = errors.New("the ClientHello has been read")

// PeekServerName reads the server name from the ClientHello at the head of
// r without consuming it. Every byte it looked at is still in the reader, so
// the handshake that follows is the client's own.
//
// crypto/tls decodes the hello, so the frontend and the TLS termination
// behind it read one parser's answer. A hello crypto/tls cannot decode is a
// hello the termination would reject anyway.
func PeekServerName(ctx context.Context, r *bufio.Reader) (string, error) {
	var hello *tls.ClientHelloInfo
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = info
			return nil, errHelloRead
		},
	}
	// The handshake writes nothing and reads only what the peek hands it.
	// The read deadline the caller set on the connection is what bounds it.
	err := tls.Server(sniffConn{reader: &peekReader{reader: r}}, config).HandshakeContext(ctx)
	if hello == nil {
		return "", fmt.Errorf("read the ClientHello: %w", err)
	}
	if hello.ServerName == "" {
		return "", ErrNoServerName
	}
	return hello.ServerName, nil
}

// PeekHost reads the Host of the cleartext request at the head of r without
// consuming it. net/http parses the head, so the frontend and the request
// path agree on what the request says.
func PeekHost(r *bufio.Reader) (string, error) {
	head, err := peekRequestHead(r)
	if err != nil {
		return "", err
	}
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		return "", fmt.Errorf("the request head does not parse: %w", err)
	}
	host := strings.TrimSpace(request.Host)
	if host == "" {
		return "", ErrNoHost
	}
	return host, nil
}

// requestHeadTerminator ends a request head, RFC 9112 section 2.1.
const requestHeadTerminator = "\r\n\r\n"

// peekRequestHead returns the bytes up to and including the blank line that
// ends the request head.
//
// It never asks for more than has arrived. Each round asks for one byte past
// what is buffered and then reads back everything that is buffered, so the
// only wait is for the next byte the client sends.
func peekRequestHead(r *bufio.Reader) ([]byte, error) {
	for {
		if _, err := r.Peek(r.Buffered() + 1); err != nil {
			return nil, fmt.Errorf("read the request head: %w", err)
		}
		head, err := r.Peek(r.Buffered())
		if err != nil {
			return nil, fmt.Errorf("read the request head: %w", err)
		}
		if end := bytes.Index(head, []byte(requestHeadTerminator)); end >= 0 {
			return head[:end+len(requestHeadTerminator)], nil
		}
		if len(head) >= PeekBufferSize {
			return nil, fmt.Errorf("%w: no request head in the first %d bytes", ErrNoHost, PeekBufferSize)
		}
	}
}

// peekReader hands out the bytes at the head of a buffered reader without
// consuming them. Each Read continues where the last one stopped and the
// reader keeps every byte, bounded by the buffer size the caller gave it.
//
// A Read waits for one byte past what it has served and then hands over
// everything that has arrived, up to what it was asked for. NEVER wait for
// the whole request: crypto/tls asks for as much as its record buffer
// holds, which is more than a ClientHello, and waiting for that much holds
// every connection until the read deadline expires.
type peekReader struct {
	reader *bufio.Reader
	served int
}

func (p *peekReader) Read(out []byte) (int, error) {
	if len(out) == 0 {
		return 0, nil
	}
	if _, err := p.reader.Peek(p.served + 1); err != nil {
		return 0, err //nolint:wrapcheck // crypto/tls reads the error by type
	}
	// The Peek above succeeded, so the reader holds at least one byte past
	// what has been served and this Peek asks for no more than it holds.
	buf, _ := p.reader.Peek(min(p.reader.Buffered(), p.served+len(out)))
	n := copy(out, buf[p.served:])
	p.served += n
	return n, nil
}

// sniffConn is the connection crypto/tls handshakes against while the
// ClientHello is read. It reads from the peek, fails every write, and has no
// deadlines because nothing here blocks on the network beyond the read the
// caller already bounded.
type sniffConn struct {
	net.Conn

	reader io.Reader
}

func (c sniffConn) Read(out []byte) (int, error)   { return c.reader.Read(out) } //nolint:wrapcheck // pass through
func (sniffConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (sniffConn) SetDeadline(time.Time) error      { return nil }
func (sniffConn) SetReadDeadline(time.Time) error  { return nil }
func (sniffConn) SetWriteDeadline(time.Time) error { return nil }
func (sniffConn) LocalAddr() net.Addr              { return sniffAddr{} }
func (sniffConn) RemoteAddr() net.Addr             { return sniffAddr{} }
func (sniffConn) Close() error                     { return nil }

// sniffAddr stands in for the address of a connection that is not one.
type sniffAddr struct{}

func (sniffAddr) Network() string { return "peek" }
func (sniffAddr) String() string  { return "peek" }
