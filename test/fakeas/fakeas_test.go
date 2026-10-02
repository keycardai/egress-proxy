package fakeas_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/test/fakeas"
)

const (
	issuer   = "https://kubernetes.default.svc.cluster.local"
	audience = "keycard"
	client   = "app"
	user     = "alice"
	resource = "https://upstream.example/"
	//nolint:gosec // G101: the credential the fixture issues
	credential = "issued-credential"
	actor      = "system:serviceaccount:agents:" + user
)

// TestClientAssertionVerification pins which client assertions the server
// accepts. Every case sends the same exchange and changes only the
// assertion, so a refusal comes from the assertion check.
func TestClientAssertionVerification(t *testing.T) {
	t.Parallel()
	trusted := rsaKey(t)
	other := rsaKey(t)
	valid := jwt.Claims{
		Issuer:   issuer,
		Subject:  actor,
		Audience: jwt.Audience{audience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	with := func(change func(*jwt.Claims)) jwt.Claims {
		claims := valid
		change(&claims)
		return claims
	}

	tests := []struct {
		name string
		// verify sets Options.Assertions to a verifier that trusts the
		// trusted key.
		verify    bool
		assertion string
		// wantStatus and wantCode are the HTTP status and OAuth error code
		// of the answer. wantCode is empty for a token response.
		wantStatus int
		wantCode   string
		// wantActor is the assertion subject the server recorded.
		wantActor string
	}{
		{
			name:       "an assertion the trusted key signed is accepted",
			verify:     true,
			assertion:  signed(t, trusted, valid),
			wantStatus: http.StatusOK,
			wantActor:  actor,
		},
		{
			name:       "an assertion another key signed is refused",
			verify:     true,
			assertion:  signed(t, other, valid),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_client",
		},
		{
			name:       "an unsigned assertion is refused",
			verify:     true,
			assertion:  unsigned(t, valid),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_client",
		},
		{
			name:       "an assertion from another issuer is refused",
			verify:     true,
			assertion:  signed(t, trusted, with(func(c *jwt.Claims) { c.Issuer = "https://other.example" })),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_client",
		},
		{
			name:       "an assertion for another audience is refused",
			verify:     true,
			assertion:  signed(t, trusted, with(func(c *jwt.Claims) { c.Audience = jwt.Audience{"other"} })),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_client",
		},
		{
			name:   "an expired assertion is refused",
			verify: true,
			assertion: signed(t, trusted, with(func(c *jwt.Claims) {
				c.Expiry = jwt.NewNumericDate(time.Now().Add(-time.Hour))
			})),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_client",
		},
		{
			name:       "without a verifier an unsigned assertion is accepted",
			assertion:  unsigned(t, valid),
			wantStatus: http.StatusOK,
			wantActor:  actor,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := fakeas.Options{
				Credentials:      map[string]string{resource: credential},
				AssertionClients: []string{client},
			}
			if tc.verify {
				keys := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&trusted.PublicKey}}
				opts.Assertions = oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: audience})
			}
			zone := fakeas.New(opts)

			answer := httptest.NewRecorder()
			zone.ServeHTTP(answer, exchange(t, tc.assertion))

			assert.Equal(t, tc.wantStatus, answer.Code, "status: %s", answer.Body)
			var body struct {
				Code        string `json:"error"`
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.Unmarshal(answer.Body.Bytes(), &body), "decode %s", answer.Body)
			assert.Equal(t, tc.wantCode, body.Code, "error")
			if tc.wantCode == "" {
				assert.Equal(t, credential, body.AccessToken, "access_token")
			} else {
				assert.Empty(t, body.AccessToken, "access_token")
			}
			requests := zone.Requests()
			require.Len(t, requests, 1, "the server records the request")
			assert.Equal(t, tc.wantActor, requests[0].Actor, "the recorded actor")
			assert.Equal(t, tc.wantCode, requests[0].Error, "the recorded error")
		})
	}
}

// exchange builds the token request the proxy sends with workload identity.
func exchange(t *testing.T, assertion string) *http.Request {
	t.Helper()
	form := url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token_type":    {"urn:keycard:params:oauth:token-type:substitute-user"},
		"subject_token":         {unsigned(t, jwt.Claims{Subject: user})},
		"resource":              {resource},
		"client_id":             {client},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		fakeas.TokenPath,
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generate an RSA key")
	return key
}

// signed signs claims with RS256, the algorithm the API server uses.
func signed(t *testing.T, key *rsa.PrivateKey, claims jwt.Claims) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	require.NoError(t, err, "build the signer")
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err, "sign the assertion")
	return token
}

// unsigned builds a JWT with alg none and an empty signature.
func unsigned(t *testing.T, claims jwt.Claims) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err, "encode the claims")
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}
