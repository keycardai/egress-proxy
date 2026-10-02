package fakeas_test

import (
	"crypto/x509"
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

// notVerified starts the description of every assertion that go-oidc
// refuses. The rest is go-oidc's own error text.
const notVerified = "the client assertion does not verify: "

// answer is what the token endpoint returned.
type answer struct {
	status int
	// code is the OAuth error code. It is empty for a token response.
	code        string
	description string
}

// TestClientAssertionVerification pins which client assertions the server
// accepts. Every case sends the same exchange and changes one thing about the
// assertion or the user it asks for, so a refusal names the check that made
// it.
func TestClientAssertionVerification(t *testing.T) {
	t.Parallel()
	trusted, err := fakeas.NewSigner(issuer, audience)
	require.NoError(t, err, "build the trusted signer")
	other, err := fakeas.NewSigner(issuer, audience)
	require.NoError(t, err, "build the signer no verifier trusts")
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
		name      string
		assertion string
		// impersonated is the user the substitute-user token names.
		impersonated string
		want         answer
		// wantActor is the assertion subject the server recorded.
		wantActor string
	}{
		{
			name:         "an assertion the trusted key signed is accepted",
			assertion:    sign(t, trusted, valid),
			impersonated: user,
			want:         answer{status: http.StatusOK},
			wantActor:    actor,
		},
		{
			name:         "an assertion another key signed is refused",
			assertion:    sign(t, other, valid),
			impersonated: user,
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: notVerified + "failed to verify signature: no public keys able to verify jwt",
			},
		},
		{
			name:         "an unsigned assertion is refused",
			assertion:    unsigned(t, valid),
			impersonated: user,
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: notVerified + `oidc: malformed jwt: unexpected signature algorithm "none"; expected ["RS256"]`,
			},
		},
		{
			name:         "an HS256 assertion keyed with the trusted public key is refused",
			assertion:    signHMAC(t, trusted, valid),
			impersonated: user,
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: notVerified + `oidc: malformed jwt: unexpected signature algorithm "HS256"; expected ["RS256"]`,
			},
		},
		{
			name:         "an assertion from another issuer is refused",
			assertion:    sign(t, trusted, with(func(c *jwt.Claims) { c.Issuer = "https://other.example" })),
			impersonated: user,
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: notVerified + `oidc: id token issued by a different provider, expected "` + issuer +
					`" got "https://other.example"`,
			},
		},
		{
			name:         "an assertion for another audience is refused",
			assertion:    sign(t, trusted, with(func(c *jwt.Claims) { c.Audience = jwt.Audience{"other"} })),
			impersonated: user,
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: notVerified + `oidc: expected audience "keycard" got ["other"]`,
			},
		},
		{
			name: "an expired assertion is refused",
			assertion: sign(t, trusted, with(func(c *jwt.Claims) {
				c.Expiry = jwt.NewNumericDate(time.Unix(1700000000, 0))
			})),
			impersonated: user,
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: notVerified + "oidc: token is expired (Token Expiry: " +
					time.Unix(1700000000, 0).String() + ")",
			},
		},
		{
			// go-oidc reads a missing exp as the zero time.Time, which is in the
			// past.
			name:         "an assertion that sets no expiry is refused",
			assertion:    sign(t, trusted, with(func(c *jwt.Claims) { c.Expiry = nil })),
			impersonated: user,
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: notVerified + "oidc: token is expired (Token Expiry: " + time.Time{}.String() + ")",
			},
		},
		{
			name:         "an assertion that names no subject is refused",
			assertion:    sign(t, trusted, with(func(c *jwt.Claims) { c.Subject = "" })),
			impersonated: user,
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: "the client assertion has no sub claim",
			},
		},
		{
			name:         "a ServiceAccount named after another user is refused",
			assertion:    sign(t, trusted, valid),
			impersonated: "someone-else",
			want: answer{
				status: http.StatusForbidden, code: "access_denied",
				description: actor + " cannot act for someone-else",
			},
			wantActor: actor,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			zone := fakeas.New(fakeas.Options{
				Credentials:      map[string]string{resource: credential},
				AssertionClients: []string{client},
				Assertions:       trusted.Verifier(),
			})

			got, accessToken := post(t, zone, exchangeForm(tc.assertion, tc.impersonated))

			assert.Equal(t, tc.want, got, "the answer")
			if tc.want.code == "" {
				assert.Equal(t, credential, accessToken, "access_token")
			} else {
				assert.Empty(t, accessToken, "access_token")
			}
			requests := zone.Requests()
			require.Len(t, requests, 1, "the server records the request")
			assert.Equal(t, tc.wantActor, requests[0].Actor, "the recorded actor")
			assert.Equal(t, tc.want.code, requests[0].Error, "the recorded error")
		})
	}
}

// TestClientAuthenticationShape pins what the server does with an assertion
// request it refuses before it verifies the assertion. Every case sends an
// assertion the trusted key signed, so the refusal comes from the request
// around it.
func TestClientAuthenticationShape(t *testing.T) {
	t.Parallel()
	trusted, err := fakeas.NewSigner(issuer, audience)
	require.NoError(t, err, "build the trusted signer")
	assertion, err := trusted.Token(actor)
	require.NoError(t, err, "mint the assertion")

	tests := []struct {
		name string
		// verifier is Options.Assertions.
		verifier *oidc.IDTokenVerifier
		// form changes the exchange parameters.
		form func(url.Values)
		// basic sends client_secret_basic credentials beside the assertion.
		basic       bool
		description string
	}{
		{
			name:        "a server with no verifier accepts no assertion",
			description: "this server has no assertion verifier, so it accepts no assertion",
		},
		{
			name:     "an assertion of another type is refused",
			verifier: trusted.Verifier(),
			form: func(form url.Values) {
				form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:saml2-bearer")
			},
			description: "the client assertion type is not urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		},
		{
			name:        "an assertion without a client_id is refused",
			verifier:    trusted.Verifier(),
			form:        func(form url.Values) { form.Del("client_id") },
			description: "the client assertion sends no client_id",
		},
		{
			name:        "a client that may not use an assertion is refused",
			verifier:    trusted.Verifier(),
			form:        func(form url.Values) { form.Set("client_id", "another-app") },
			description: "another-app may not authenticate with a client assertion",
		},
		{
			name:        "an assertion beside basic credentials is refused",
			verifier:    trusted.Verifier(),
			basic:       true,
			description: "the request sends both a client assertion and basic credentials",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			zone := fakeas.New(fakeas.Options{
				Credentials:      map[string]string{resource: credential},
				ClientSecrets:    map[string]string{client: "secret"},
				AssertionClients: []string{client},
				Assertions:       tc.verifier,
			})
			form := exchangeForm(assertion, user)
			if tc.form != nil {
				tc.form(form)
			}
			req := tokenRequest(t, form)
			if tc.basic {
				req.SetBasicAuth(client, "secret")
			}
			recorder := httptest.NewRecorder()
			zone.ServeHTTP(recorder, req)
			got, accessToken := read(t, recorder)

			assert.Equal(t, answer{
				status: http.StatusUnauthorized, code: "invalid_client", description: tc.description,
			}, got, "the answer")
			assert.Empty(t, accessToken, "access_token")
			requests := zone.Requests()
			require.Len(t, requests, 1, "the server records the request")
			assert.Empty(t, requests[0].Actor, "a refused assertion names no actor")
		})
	}
}

// exchangeForm builds the token request the proxy sends with workload
// identity.
func exchangeForm(assertion, impersonated string) url.Values {
	encode := base64.RawURLEncoding.EncodeToString
	subjectToken := encode([]byte(`{"alg":"none"}`)) + "." + encode([]byte(`{"sub":"`+impersonated+`"}`)) + "."
	return url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token_type":    {"urn:keycard:params:oauth:token-type:substitute-user"},
		"subject_token":         {subjectToken},
		"resource":              {resource},
		"client_id":             {client},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
}

func tokenRequest(t *testing.T, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, fakeas.TokenPath,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// post sends one exchange to the server and reads the answer back.
func post(t *testing.T, zone *fakeas.Server, form url.Values) (answer, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	zone.ServeHTTP(recorder, tokenRequest(t, form))
	return read(t, recorder)
}

// read decodes a token endpoint answer. It returns the access token apart,
// so a case compares the rest of the answer as one value.
func read(t *testing.T, recorder *httptest.ResponseRecorder) (answer, string) {
	t.Helper()
	var body struct {
		Code        string `json:"error"`
		Description string `json:"error_description"`
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body), "decode %s", recorder.Body)
	return answer{status: recorder.Code, code: body.Code, description: body.Description}, body.AccessToken
}

func sign(t *testing.T, signer *fakeas.Signer, claims jwt.Claims) string {
	t.Helper()
	token, err := signer.Sign(claims)
	require.NoError(t, err, "sign the assertion")
	return token
}

// signHMAC signs claims with HS256, keyed with the DER encoding of the
// signer's public key. A verifier that takes the algorithm from the token
// header and the key from its key set would accept it.
func signHMAC(t *testing.T, signer *fakeas.Signer, claims jwt.Claims) string {
	t.Helper()
	secret, err := x509.MarshalPKIXPublicKey(signer.Public())
	require.NoError(t, err, "encode the public key")
	hmac, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret}, nil)
	require.NoError(t, err, "build the HS256 signer")
	token, err := jwt.Signed(hmac).Claims(claims).Serialize()
	require.NoError(t, err, "sign the HS256 assertion")
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
