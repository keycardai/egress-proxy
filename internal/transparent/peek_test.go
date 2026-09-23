package transparent_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/transparent"
)

// recordHeaderLen is the TLS record header, RFC 8446 section 5.1.
const recordHeaderLen = 5

// maxRecordPayload is the largest payload one TLS record can hold.
const maxRecordPayload = 1 << 14

// clientHello is the bytes a real crypto/tls client sends for a
// configuration. It is captured from a handshake rather than written by
// hand, so what the peek decodes is what a client actually sends.
func clientHello(t *testing.T, config *tls.Config) []byte {
	t.Helper()
	client, server := net.Pipe()
	go func() { _ = tls.Client(client, config).HandshakeContext(t.Context()) }()
	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)), "deadline on the capture")
	buf := make([]byte, transparent.PeekBufferSize)
	n, err := server.Read(buf)
	require.NoError(t, err, "read the ClientHello")
	_ = server.Close()
	_ = client.Close()
	return buf[:n]
}

// refragment rewrites a handshake sent in one TLS record as two records
// with half of it each, which RFC 8446 section 5.1 permits and clients
// do.
func refragment(t *testing.T, record []byte) []byte {
	t.Helper()
	require.Greater(t, len(record), recordHeaderLen, "the record has a header")
	body := record[recordHeaderLen:]
	var out bytes.Buffer
	for _, half := range [][]byte{body[:len(body)/2], body[len(body)/2:]} {
		require.LessOrEqual(t, len(half), maxRecordPayload, "each half fits one record")
		length := uint16(len(half)) //nolint:gosec // G115: checked above
		out.Write([]byte{record[0], record[1], record[2], byte(length >> 8), byte(length)})
		out.Write(half)
	}
	return out.Bytes()
}

func TestPeekServerName(t *testing.T) {
	t.Parallel()
	named := clientHello(t, &tls.Config{ServerName: "upstream.test", MinVersion: tls.VersionTLS12})
	//nolint:gosec // G402: a fixture client that never completes a handshake
	anonymous := clientHello(t, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})

	tests := []struct {
		name    string
		head    []byte
		want    string
		wantErr error
	}{
		{name: "a ClientHello naming a server", head: named, want: "upstream.test"},
		{name: "the same hello fragmented across two records", head: refragment(t, named), want: "upstream.test"},
		{name: "a ClientHello naming no server", head: anonymous, wantErr: transparent.ErrNoServerName},
		{name: "a cleartext request head", head: []byte("GET / HTTP/1.1\r\nHost: upstream.test\r\n\r\n")},
		{name: "a truncated handshake record", head: named[:20]},
		{name: "nothing at all", head: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reader := bufio.NewReaderSize(bytes.NewReader(tc.head), transparent.PeekBufferSize)
			got, err := transparent.PeekServerName(t.Context(), reader)
			if tc.want == "" {
				require.Error(t, err, "a name that cannot be read is an error")
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr, "the error the caller keys on")
				}
				assert.Empty(t, got, "no name is returned with the error")
				return
			}
			require.NoError(t, err, "read the server name")
			assert.Equal(t, tc.want, got, "the server name")
			// The peek NEVER consumes: the handshake that follows is the
			// client's own.
			rest, err := io.ReadAll(reader)
			require.NoError(t, err, "read what is left")
			assert.Equal(t, tc.head, rest, "every byte the peek looked at is still in the reader")
		})
	}
}

func TestPeekHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		head string
		want string
	}{
		{
			name: "a request naming a host",
			head: "GET /path HTTP/1.1\r\nHost: upstream.test\r\n\r\n", want: "upstream.test",
		},
		{
			name: "a request naming a host and a port",
			head: "POST / HTTP/1.1\r\nHost: upstream.test:8080\r\nContent-Length: 0\r\n\r\n",
			want: "upstream.test:8080",
		},
		{
			name: "an absolute-form target, which names the host in the request line",
			head: "GET http://upstream.test/path HTTP/1.1\r\nHost: other.test\r\n\r\n", want: "upstream.test",
		},
		{name: "a request with no Host header", head: "GET / HTTP/1.1\r\n\r\n"},
		{name: "a request head that does not parse", head: "not a request\r\n\r\n"},
		{name: "a TLS record rather than a request", head: "\x16\x03\x01\x00\x05hello"},
		{name: "nothing at all", head: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reader := bufio.NewReaderSize(bytes.NewReader([]byte(tc.head)), transparent.PeekBufferSize)
			got, err := transparent.PeekHost(reader)
			if tc.want == "" {
				require.Error(t, err, "a host that cannot be read is an error")
				assert.Empty(t, got, "no host is returned with the error")
				return
			}
			require.NoError(t, err, "read the host")
			assert.Equal(t, tc.want, got, "the host")
			rest, err := io.ReadAll(reader)
			require.NoError(t, err, "read what is left")
			assert.Equal(t, tc.head, string(rest), "every byte the peek looked at is still in the reader")
		})
	}
}
