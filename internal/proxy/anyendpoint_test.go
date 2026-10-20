package proxy_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/assertion"
	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/policy"
	"github.com/keycardai/egress-proxy/internal/proxy"
)

// originSource answers every resource with one credential and keeps the
// resources it was asked for, so a test reads which resource any_endpoint
// derived from the request.
type originSource struct {
	mu    sync.Mutex
	asked []string
}

func (s *originSource) Credential(_ context.Context, resource string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, resource)
	return headerSecret, nil
}

func (s *originSource) Describe() string { return "one credential for every resource" }

func (s *originSource) resources() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.asked...)
}

// TestAnyEndpointServesEveryPathWithTheOriginAsResource pins any_endpoint
// on the request path: a path no document names is forwarded, the
// credential goes in at the one placement, the resource the source is
// asked for is the request's origin with the upstream's port, and the
// record names the origin endpoint.
func TestAnyEndpointServesEveryPathWithTheOriginAsResource(t *testing.T) {
	t.Parallel()
	source := &originSource{}
	h := start(t, harnessOptions{upstream: httpbinUpstream(), anyEndpoint: true, credentials: source})
	target := h.upstreamURL("/anything/no/document/names/this")
	answer := fetch(t, h, target, http.Header{"Authorization": []string{"Bearer placeholder"}})
	require.Equal(t, http.StatusOK, answer.status, "status: %s", answer.body)
	var got arrived
	require.NoError(t, json.Unmarshal([]byte(answer.body), &got), "decode %s", answer.body)
	assert.Equal(t, []string{"Bearer " + headerSecret}, got.Headers.Values("Authorization"), "what the upstream saw")

	origin := "https://" + net.JoinHostPort(upstreamHost, strconv.Itoa(h.upstream.port))
	assert.Equal(t, []string{origin}, source.resources(), "the resource the source was asked for")
	record := h.sink.find(t, "the allow", byPath("/anything/no/document/names/this"))
	assert.Equal(t, policy.VerdictAllow, record.Decision.Verdict)
	assert.Equal(t, policy.ReasonEndpointAllowed, record.Decision.Reason)
	assert.Equal(t, net.JoinHostPort(upstreamHost, strconv.Itoa(h.upstream.port))+"/", record.Decision.Endpoint,
		"the record names the origin endpoint")
}

// TestAnyEndpointKeepsThePlatformDenyList pins that any_endpoint opens
// nothing the deny list covers: a connection to a covered destination is
// refused before a leaf is minted, and any other host passes the
// connection decision.
func TestAnyEndpointKeepsThePlatformDenyList(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{anyEndpoint: true})
	tests := []struct {
		name       string
		authority  string
		wantStatus int
		wantReason policy.Reason
	}{
		{
			name:       "the metadata address",
			authority:  "169.254.169.254:80",
			wantStatus: http.StatusForbidden,
			wantReason: policy.ReasonDenyAlways,
		},
		{
			name:       "a DoH resolver",
			authority:  "dns.google:443",
			wantStatus: http.StatusForbidden,
			wantReason: policy.ReasonDenyAlways,
		},
		{
			name:       "a bad port",
			authority:  "denied.invalid:99999",
			wantStatus: http.StatusBadRequest,
			wantReason: policy.ReasonMalformedRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn := h.dial(t)
			answer := h.connect(t, conn, bufio.NewReader(conn), tc.authority)
			assert.Equal(t, tc.wantStatus, answer.status, "CONNECT status")
			assert.Equal(t, tc.wantReason, answer.reason(), "CONNECT reason")
			record := h.sink.find(t, tc.name, byConnection(answer.id(), tc.wantReason))
			assert.Equal(t, policy.VerdictDeny, record.Decision.Verdict, "record = %+v", record)
		})
	}
	t.Run("a host no document names", func(t *testing.T) {
		t.Parallel()
		conn := h.dial(t)
		answer := h.connect(t, conn, bufio.NewReader(conn), "anything.invalid:8443")
		assert.Equal(t, http.StatusOK, answer.status, "CONNECT status")
	})
	t.Cleanup(func() {
		assert.Zero(t, h.store.Mints(), "a denied connection minted a leaf")
	})
}

// TestOneIdentityForEveryApplication pins the selector with one source for
// every application: an assertion naming any application is served, the
// record names that application and the assertion's subject as the client,
// and the credential is the one source's.
func TestOneIdentityForEveryApplication(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pemBytes, err := assertion.MarshalPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	verifier, err := assertion.NewVerifier(pemBytes, assertionAudience, 30*time.Second)
	require.NoError(t, err)
	source := &originSource{}
	selector := credential.NewSelector()
	require.NoError(t, selector.SetEvery(credential.Selected{Source: source, SubjectIsClient: true}))
	h := start(t, harnessOptions{
		upstream: httpbinUpstream(), anyEndpoint: true,
		sandboxes: &proxy.SandboxIdentification{Header: assertionHeader, Verifier: verifier, Selector: selector},
	})
	tests := map[string]struct {
		sandbox, application, path string
	}{
		"an application nobody listed": {sandbox: "sandbox-7f3a", application: "chang-agent", path: "/anything/chang"},
		"another one":                  {sandbox: "keycard-demo", application: "review-agent", path: "/anything/review"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			header := http.Header{
				"Authorization": []string{"Bearer placeholder"},
				assertionHeader: []string{appToken(t, priv, tc.sandbox, tc.application)},
			}
			answer := fetch(t, h, h.upstreamURL(tc.path), header)
			require.Equal(t, http.StatusOK, answer.status, "status: %s", answer.body)
			var got arrived
			require.NoError(t, json.Unmarshal([]byte(answer.body), &got), "decode %s", answer.body)
			assert.Equal(t, []string{"Bearer " + headerSecret}, got.Headers.Values("Authorization"), "what the upstream saw")
			assert.Empty(t, got.Headers.Values(assertionHeader), "the assertion reached the upstream")

			record := h.sink.find(t, name, byPath(tc.path))
			assert.Equal(t, policy.VerdictAllow, record.Decision.Verdict)
			assert.Equal(t, tc.sandbox, record.SandboxID, "record sandbox")
			assert.Equal(t, tc.application, record.Application, "record application")
			require.NotNil(t, record.Identity, "record identity")
			assert.Equal(t, assertion.Subject(tc.application, "uuid-"+tc.sandbox), record.Identity.ClientID,
				"the subject is what the zone calls the client")
		})
	}
	t.Run("no assertion is still refused", func(t *testing.T) {
		t.Parallel()
		answer := fetch(t, h, h.upstreamURL("/anything/nobody"), http.Header{})
		assert.Equal(t, http.StatusForbidden, answer.status, "status")
		assert.Equal(t, policy.ReasonSandboxUnidentified, answer.reason(), "reason")
	})
}
