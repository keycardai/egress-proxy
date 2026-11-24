package proxy_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/keycardai/go-sdk/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/policy"
)

// The resources the method source holds, and the values its tokens write.
//
//nolint:gosec // G101: test fixtures, not credentials
const (
	apiKeyResource   = "https://apikey.example/"
	passwordResource = "https://password.example/"
	dpopResource     = "https://dpop.example/"
	zoneAPIKey       = "zone-api-key"
	zonePassword     = "zone-password"
	zoneUsername     = "zone-user"
)

// methodSource returns a token with a method for each resource, the way the
// exchange does for Keycard-API-Key and Keycard-Password.
type methodSource map[string]*oauth.TokenResponse

func (s methodSource) Credential(_ context.Context, resource string) (credential.Issued, error) {
	token, ok := s[resource]
	if !ok {
		return credential.Issued{}, credential.ErrUnavailable
	}
	return credential.Issued{Value: token.AccessToken, Token: token}, nil
}

func (methodSource) Describe() string { return "a source of tokens with a method" }

func zoneTokens() methodSource {
	return methodSource{
		apiKeyResource: {
			AccessToken: zoneAPIKey, TokenType: oauth.TokenTypeKeycardAPIKey,
			Method: json.RawMessage(`{"in":"header","name":"X-Api-Key"}`),
		},
		passwordResource: {
			AccessToken: zonePassword, TokenType: oauth.TokenTypeKeycardPassword, Username: zoneUsername,
			Method: json.RawMessage(`{"username":{"in":"query","name":"user"},"password":{"in":"query","name":"pass"}}`),
		},
		dpopResource: {AccessToken: zoneAPIKey, TokenType: "DPoP"},
	}
}

// methodEndpoints name a placement the method must override: a header
// placement for the API key and a query placement for the password.
func methodEndpoints(port int) []policy.Endpoint {
	return []policy.Endpoint{
		{
			Host: upstreamHost, Port: port, PathPrefix: "/anything/apikey/",
			Resource: apiKeyResource, Credential: &headerPlacement,
		},
		{
			Host: upstreamHost, Port: port, PathPrefix: "/anything/password/",
			Resource: passwordResource, Credential: &queryPlacement,
		},
		{
			Host: upstreamHost, Port: port, PathPrefix: "/anything/dpop/",
			Resource: dpopResource, Credential: &headerPlacement,
		},
	}
}

// TestAZoneMethodWinsOverTheEndpointPlacement pins what reaches the upstream
// for a token with a method. The method's place gets the credential, and the
// endpoint placement is not written.
func TestAZoneMethodWinsOverTheEndpointPlacement(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{upstream: httpbinUpstream(), endpoints: methodEndpoints, credentials: zoneTokens()})
	tests := []struct {
		name     string
		path     string
		wantArgs url.Values
		// wantHeaders are the values the upstream received under each name.
		wantHeaders map[string][]string
	}{
		{
			name: "an API key in the header the method names", path: "/anything/apikey/things?q=here",
			wantArgs: url.Values{"q": {"here"}, "key": {"placeholder"}},
			wantHeaders: map[string][]string{
				"X-Api-Key": {zoneAPIKey}, "Authorization": {"Bearer placeholder"},
			},
		},
		{
			name: "a username and password in the query parameters the method names",
			path: "/anything/password/things?q=here&pass=placeholder",
			wantArgs: url.Values{
				"q": {"here"}, "key": {"placeholder"}, "user": {zoneUsername}, "pass": {zonePassword},
			},
			wantHeaders: map[string][]string{"X-Api-Key": {"placeholder"}, "Authorization": {"Bearer placeholder"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			target := h.upstreamURL(tc.path) + "&key=placeholder"
			answer := fetch(t, h, target, http.Header{
				"Authorization": {"Bearer placeholder"}, "X-Api-Key": {"placeholder"},
			})
			require.Equal(t, http.StatusOK, answer.status, "response status, body %s", answer.body)
			var got arrived
			require.NoError(t, json.Unmarshal([]byte(answer.body), &got), "decode %s", answer.body)
			assert.Equal(t, tc.wantArgs, got.Args, "the query the upstream received")
			for name, want := range tc.wantHeaders {
				assert.Equal(t, want, got.Headers.Values(name), "the %s header the upstream received", name)
			}
		})
	}
}

// TestATokenTypeTheProxyDoesNotKnowIsRefused checks that a token_type with
// no rule for where it goes denies with credential_unavailable and never
// reaches the upstream.
func TestATokenTypeTheProxyDoesNotKnowIsRefused(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{upstream: httpbinUpstream(), endpoints: methodEndpoints, credentials: zoneTokens()})
	answer := fetch(t, h, h.upstreamURL("/anything/dpop/thing"), http.Header{"Authorization": {"Bearer placeholder"}})
	assert.Equal(t, http.StatusForbidden, answer.status, "response status")
	assert.Equal(t, policy.ReasonCredentialUnavailable, answer.reason(), "response reason")
	record := h.sink.find(t, "the DPoP request", byRequest(answer.id()))
	assert.Equal(t, policy.VerdictDeny, record.Decision.Verdict, "record verdict")
	assert.Equal(t, policy.ReasonCredentialUnavailable, record.Decision.Reason, "record reason")
	assert.Equal(t, h.upstreamAuthority()+"/anything/dpop/", record.Decision.Endpoint, "record endpoint")
	assert.Contains(t, record.Decision.Error, `unsupported_token_type for token_type "DPoP"`, "record error")
	assert.NotContains(t, record.Decision.Error, zoneAPIKey, "record error holds the credential")
	assert.Zero(t, h.upstream.connections.Load(), "a request without its credential reached the upstream")
}
