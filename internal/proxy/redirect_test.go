package proxy_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/policy"
	"github.com/keycardai/egress-proxy/internal/proxy"
)

// redirectedFrom is the pre-redirect address a captured connection has
// on its audit record. The proxy records it and never dials it.
//
//nolint:gochecknoglobals // a fixture the cases share
var redirectedFrom = netip.MustParseAddrPort("203.0.113.9:443")

// drainRecorder is a connection that records whether the proxy asked for an
// orderly close before it closed.
type drainRecorder struct {
	net.Conn

	drained bool
}

func (c *drainRecorder) DrainOnClose() { c.drained = true }

// TestARedirectedConnectionIsDecidedAndForwarded drives a captured
// connection all the way through: the connection decision, the TLS
// termination on a leaf for the recovered name, the request decision, and
// the upstream. The connection-scoped record names the pre-redirect address,
// which is what tells a captured connection from a CONNECT tunnel.
func TestARedirectedConnectionIsDecidedAndForwarded(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{})
	require.LessOrEqual(t, h.upstream.port, 65535, "the upstream port fits an address")
	address := netip.AddrPortFrom(redirectedFrom.Addr(), uint16(h.upstream.port)) //nolint:gosec // G115: checked above
	client := h.serveRedirected(t, proxy.Redirected{
		Host: upstreamHost, Port: h.upstream.port, Address: address,
	})
	conn := tls.Client(client, &tls.Config{
		ServerName: upstreamHost, RootCAs: h.authority.Pool(), MinVersion: tls.VersionTLS12,
	})
	t.Cleanup(func() { _ = conn.Close() })
	reader := bufio.NewReader(conn)
	answer := h.roundTrip(
		t,
		conn,
		reader,
		fmt.Sprintf("GET /ok/echo HTTP/1.1\r\nHost: %s\r\n\r\n", h.upstreamAuthority()),
	)
	assert.Equal(t, http.StatusOK, answer.status, "status")
	assert.Equal(t, "GET /ok/echo host="+h.upstreamAuthority(), answer.body, "what the upstream echoed")

	connection := h.sink.find(t, "the allowed connection", byReason(audit.ScopeConnection, policy.ReasonEndpointAllowed))
	assert.Equal(t, audit.Destination{
		Host: upstreamHost, Port: h.upstream.port, SNI: upstreamHost, OriginalAddress: address.String(),
	}, connection.Destination, "the connection record names the pre-redirect address")
	request := h.sink.find(t, "the allowed request", byReason(audit.ScopeRequest, policy.ReasonEndpointAllowed))
	assert.Equal(t, address.String(), request.Destination.OriginalAddress,
		"the request record holds the connection's pre-redirect address")
	assert.Equal(t, connection.ConnectionID, request.ConnectionID, "the request joins its connection")
}

// cleartextHost is the host the document covers on port 80, so a cleartext
// case reaches the rule that refuses a cleartext connection the endpoint
// list allows. Without it every cleartext case is already denied by the
// endpoint match and that rule is never exercised.
const cleartextHost = "cleartext.test"

// TestRedirectedConnectionsAreRefused pins the reason on every captured
// connection the proxy will not forward, and what the workload is told.
func TestRedirectedConnectionsAreRefused(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{endpoints: func(port int) []policy.Endpoint {
		return []policy.Endpoint{
			{Host: upstreamHost, Port: port, PathPrefix: "/ok/"},
			{Host: cleartextHost, Port: 80, PathPrefix: "/ok/"},
		}
	}})
	tests := []struct {
		name string
		dst  proxy.Redirected
		// wantStatus is the status a cleartext client reads. Zero means the
		// connection is closed with nothing written, which is what a TLS
		// client waiting for a ServerHello gets.
		wantStatus int
		wantReason policy.Reason
	}{
		{
			name:       "a name no endpoint covers",
			dst:        proxy.Redirected{Host: "denied.invalid", Port: 443, Address: redirectedFrom},
			wantReason: policy.ReasonNoMatchingEndpoint,
		},
		{
			name: "a name the platform deny list covers",
			dst: proxy.Redirected{
				Host: "169.254.169.254", Port: 443, Address: netip.MustParseAddrPort("169.254.169.254:443"),
			},
			wantReason: policy.ReasonDenyAlways,
		},
		{
			name: "a handshake that named no server",
			dst: proxy.Redirected{
				Host: "203.0.113.10", Port: 443,
				Address: netip.MustParseAddrPort("203.0.113.10:443"), Refusal: policy.ReasonNoSNI,
			},
			wantReason: policy.ReasonNoSNI,
		},
		{
			name: "a connection opened to the listener rather than redirected into it",
			dst: proxy.Redirected{
				Host: "127.0.0.1", Port: 1015,
				Address: netip.MustParseAddrPort("127.0.0.1:1015"), Refusal: policy.ReasonNotRedirected,
			},
			wantReason: policy.ReasonNotRedirected,
		},
		{
			name: "a cleartext connection to a name an endpoint covers on another port",
			dst: proxy.Redirected{
				Host: upstreamHost, Port: 80,
				Address: netip.MustParseAddrPort("203.0.113.9:80"), Cleartext: true,
			},
			wantStatus: http.StatusForbidden,
			wantReason: policy.ReasonNoMatchingEndpoint,
		},
		{
			// The endpoint list covers this host on this port, so the
			// connection decision allows it and the refusal comes from the
			// rule that forwards nothing cleartext. The reason separates this
			// case from the one above, where no endpoint covers the port.
			name: "a cleartext connection to a name and port an endpoint covers",
			dst: proxy.Redirected{
				Host: cleartextHost, Port: 80,
				Address: netip.MustParseAddrPort("203.0.113.12:80"), Cleartext: true,
			},
			wantStatus: http.StatusForbidden,
			wantReason: policy.ReasonCleartextNotForwarded,
		},
		{
			// The frontend could not read a Host header. Cleartext is
			// refused whatever the head says, so the reason is the same one
			// a readable head on a covered endpoint gets.
			name: "a cleartext connection whose head the frontend could not read",
			dst: proxy.Redirected{
				Host: "203.0.113.13", Port: 80,
				Address: netip.MustParseAddrPort("203.0.113.13:80"), Cleartext: true,
				Refusal: policy.ReasonCleartextNotForwarded,
			},
			wantStatus: http.StatusForbidden,
			wantReason: policy.ReasonCleartextNotForwarded,
		},
		{
			name: "a cleartext connection the platform deny list covers",
			dst: proxy.Redirected{
				Host: "169.254.169.254", Port: 80,
				Address: netip.MustParseAddrPort("169.254.169.254:80"), Cleartext: true,
			},
			wantStatus: http.StatusForbidden,
			wantReason: policy.ReasonDenyAlways,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := h.serveRedirected(t, tc.dst)
			body, err := io.ReadAll(client)
			require.NoError(t, err, "read what the proxy answered")

			record := h.sink.find(t, tc.name, func(r audit.Record) bool {
				return r.Scope == audit.ScopeConnection && r.Destination.OriginalAddress == tc.dst.Address.String()
			})
			assert.Equal(t, audit.Decision{Verdict: policy.VerdictDeny, Reason: tc.wantReason},
				record.Decision, "the decision on the record")
			assert.Equal(t, audit.Destination{
				Host: tc.dst.Host, Port: tc.dst.Port, OriginalAddress: tc.dst.Address.String(),
			}, record.Destination, "the destination on the record")
			assert.Zero(t, h.store.Mints(), "a refused connection mints no leaf")
			assert.Zero(t, h.upstream.connections.Load(), "a refused connection opens no upstream connection")

			if tc.wantStatus == 0 {
				assert.Empty(t, string(body), "a TLS client is answered with nothing")
				return
			}
			resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(body)), nil)
			require.NoError(t, err, "parse the refusal")
			t.Cleanup(func() { _ = resp.Body.Close() })
			assert.Equal(t, tc.wantStatus, resp.StatusCode, "status")
			assert.Equal(t, string(tc.wantReason), resp.Header.Get(proxy.HeaderReason), "the reason header")
			assert.Equal(t, record.ConnectionID, resp.Header.Get(proxy.HeaderRequestID),
				"the refusal names the record")
			assert.Equal(t, "application/problem+json", resp.Header.Get("Content-Type"), "the refusal content type")
			var problem map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&problem), "the refusal body parses as JSON")
			assert.Equal(t, string(tc.wantReason), problem["reason"], "the reason in the body")
			assert.Equal(t, "urn:keycard:request:"+record.ConnectionID, problem["instance"], "the instance in the body")
		})
	}
}

// TestARefusedRedirectedConnectionIsDrained proves the proxy asks for an
// orderly close on a refusal, so the refusal is not discarded by the RST a
// socket with unread data sends.
func TestARefusedRedirectedConnectionIsDrained(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{})
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	recorder := &drainRecorder{Conn: server}
	go h.server.ServeRedirected(recorder, proxy.Redirected{
		Host: "denied.invalid", Port: 80, Address: netip.MustParseAddrPort("203.0.113.11:80"), Cleartext: true,
	})
	_, err := io.ReadAll(client)
	require.NoError(t, err, "read the refusal")
	h.sink.find(t, "the refusal", byReason(audit.ScopeConnection, policy.ReasonNoMatchingEndpoint))
	assert.True(t, recorder.drained, "the proxy asked for an orderly close before it closed")
}

// serveRedirected hands one end of a pipe to the proxy as a captured
// connection and returns the other end.
func (h *harness) serveRedirected(t *testing.T, dst proxy.Redirected) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go h.server.ServeRedirected(server, dst)
	return client
}
