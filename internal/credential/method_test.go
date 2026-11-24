package credential_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/keycardai/go-sdk/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/credential"
)

//nolint:gosec // G101: test fixtures, not credentials
const (
	apiKey       = "kc-api-key"
	password     = "kc-password"
	username     = "svc-user"
	workloadSent = "placeholder"
)

// bearerPlacement is the endpoint placement every case names. A token with a
// method must not write there.
var bearerPlacement = credential.Placement{ //nolint:gochecknoglobals // a fixture the tests share
	Kind: credential.KindHeader, Name: "Authorization", Template: "Bearer " + credential.Token,
}

// token builds a token response the way the SDK parses one.
func token(tokenType, method string) *oauth.TokenResponse {
	response := &oauth.TokenResponse{AccessToken: apiKey, TokenType: tokenType}
	if method != "" {
		response.Method = json.RawMessage(method)
	}
	return response
}

// passwordToken builds a Keycard-Password token response.
func passwordToken(method string) *oauth.TokenResponse {
	return &oauth.TokenResponse{
		AccessToken: password, TokenType: oauth.TokenTypeKeycardPassword, Username: username,
		Method: json.RawMessage(method),
	}
}

// workloadRequest is what the workload sends: a placeholder at the endpoint
// placement and at every place a method in these cases names.
func workloadRequest(t *testing.T) *http.Request {
	t.Helper()
	return request(t, "https://api.example/v1?q=here&api_key="+workloadSent, http.Header{
		"Authorization": {"Bearer " + workloadSent},
		"X-Api-Key":     {workloadSent},
		"Cookie":        {"session=abc; sid=" + workloadSent},
	})
}

// TestAMethodWinsOverThePlacement pins the outbound request for a token whose
// method says where the credential goes. The method replaces what the
// workload sent there. The endpoint placement is not written, so the
// workload's Authorization stays as it sent it unless the method names it.
func TestAMethodWinsOverThePlacement(t *testing.T) {
	t.Parallel()
	const workloadAuthorization = "Bearer " + workloadSent
	tests := []struct {
		name          string
		token         *oauth.TokenResponse
		wantQuery     string
		wantHeader    http.Header
		wantNoHeaders []string
	}{
		{
			name:      "an API key in a header",
			token:     token(oauth.TokenTypeKeycardAPIKey, `{"in":"header","name":"X-Api-Key"}`),
			wantQuery: "q=here&api_key=" + workloadSent,
			wantHeader: http.Header{
				"Authorization": {workloadAuthorization}, "X-Api-Key": {apiKey},
				"Cookie": {"session=abc; sid=" + workloadSent},
			},
		},
		{
			name:      "an API key in the query, appended after the workload parameters",
			token:     token(oauth.TokenTypeKeycardAPIKey, `{"in":"query","name":"api_key"}`),
			wantQuery: "q=here&api_key=" + apiKey,
			wantHeader: http.Header{
				"Authorization": {workloadAuthorization}, "X-Api-Key": {workloadSent},
				"Cookie": {"session=abc; sid=" + workloadSent},
			},
		},
		{
			name:      "an API key in a cookie, beside the workload cookies",
			token:     token(oauth.TokenTypeKeycardAPIKey, `{"in":"cookie","name":"sid"}`),
			wantQuery: "q=here&api_key=" + workloadSent,
			wantHeader: http.Header{
				"Authorization": {workloadAuthorization}, "X-Api-Key": {workloadSent},
				"Cookie": {"session=abc; sid=" + apiKey},
			},
		},
		{
			name:      "an API key as an Authorization scheme",
			token:     token(oauth.TokenTypeKeycardAPIKey, `{"in":"scheme","name":"Token"}`),
			wantQuery: "q=here&api_key=" + workloadSent,
			wantHeader: http.Header{
				"Authorization": {"Token " + apiKey}, "X-Api-Key": {workloadSent},
				"Cookie": {"session=abc; sid=" + workloadSent},
			},
		},
		{
			name: "an API key as an Authorization scheme with a parameter",
			token: token(oauth.TokenTypeKeycardAPIKey,
				`{"in":"scheme","name":"Token","scheme_parameter":"token"}`),
			wantQuery: "q=here&api_key=" + workloadSent,
			wantHeader: http.Header{
				"Authorization": {"Token token=" + apiKey}, "X-Api-Key": {workloadSent},
				"Cookie": {"session=abc; sid=" + workloadSent},
			},
		},
		{
			name:      "a token_type in another case",
			token:     token("keycard-api-key", `{"in":"header","name":"X-Api-Key"}`),
			wantQuery: "q=here&api_key=" + workloadSent,
			wantHeader: http.Header{
				"Authorization": {workloadAuthorization}, "X-Api-Key": {apiKey},
				"Cookie": {"session=abc; sid=" + workloadSent},
			},
		},
		{
			name: "a password and username in headers",
			token: passwordToken(`{"username":{"in":"header","name":"X-User"},` +
				`"password":{"in":"header","name":"X-Pass"}}`),
			wantQuery: "q=here&api_key=" + workloadSent,
			wantHeader: http.Header{
				"Authorization": {workloadAuthorization}, "X-Api-Key": {workloadSent},
				"Cookie": {"session=abc; sid=" + workloadSent},
				"X-User": {username}, "X-Pass": {password},
			},
		},
		{
			name: "a password and username in the query",
			token: passwordToken(`{"username":{"in":"query","name":"user"},` +
				`"password":{"in":"query","name":"api_key"}}`),
			wantQuery: "q=here&user=" + username + "&api_key=" + password,
			wantHeader: http.Header{
				"Authorization": {workloadAuthorization}, "X-Api-Key": {workloadSent},
				"Cookie": {"session=abc; sid=" + workloadSent},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issued := credential.Issued{Value: tc.token.AccessToken, Token: tc.token}
			writer, err := issued.Writer(bearerPlacement)
			require.NoError(t, err, "Writer")
			out := workloadRequest(t)
			require.NoError(t, writer.Write(out, issued.Value), "Write")
			assert.Equal(t, tc.wantQuery, out.URL.RawQuery, "outbound query")
			assert.Equal(t, tc.wantHeader, out.Header, "outbound headers")
		})
	}
}

// TestAMethodTheProxyCannotWriteIsRefused pins each refusal and its SDK
// reason. A refusal denies the request with credential_unavailable.
func TestAMethodTheProxyCannotWriteIsRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		token      *oauth.TokenResponse
		wantReason oauth.CredentialPlacementReason
		wantErr    string
	}{
		{
			name:       "an unknown token_type",
			token:      token("DPoP", ""),
			wantReason: oauth.PlacementUnsupportedTokenType, wantErr: `for token_type "DPoP"`,
		},
		{
			name:       "an API key without a method",
			token:      token(oauth.TokenTypeKeycardAPIKey, ""),
			wantReason: oauth.PlacementInvalidMethod, wantErr: "method is missing",
		},
		{
			name:       "an API key in an unknown place",
			token:      token(oauth.TokenTypeKeycardAPIKey, `{"in":"body","name":"key"}`),
			wantReason: oauth.PlacementInvalidMethod, wantErr: `method.in "body"`,
		},
		{
			name:       "a method with an unknown member",
			token:      token(oauth.TokenTypeKeycardAPIKey, `{"in":"header","name":"X-Api-Key","prefix":"k"}`),
			wantReason: oauth.PlacementInvalidMethod, wantErr: `unknown member "prefix"`,
		},
		{
			name:       "an API key in Proxy-Authorization",
			token:      token(oauth.TokenTypeKeycardAPIKey, `{"in":"header","name":"Proxy-Authorization"}`),
			wantReason: oauth.PlacementInvalidMethod, wantErr: `"Proxy-Authorization" in method.name is not allowed`,
		},
		{
			name:       "an API key in an x-forwarded- header",
			token:      token(oauth.TokenTypeKeycardAPIKey, `{"in":"header","name":"X-Forwarded-User"}`),
			wantReason: oauth.PlacementInvalidMethod, wantErr: `"X-Forwarded-User" in method.name is not allowed`,
		},
		{
			name: "an API key with a newline in a header",
			//nolint:gosec // G101: a test fixture, not a credential
			token: &oauth.TokenResponse{
				AccessToken: "key\r\nX-Injected: 1", TokenType: oauth.TokenTypeKeycardAPIKey,
				Method: json.RawMessage(`{"in":"header","name":"X-Api-Key"}`),
			},
			wantReason: oauth.PlacementInvalidCredential, wantErr: "cannot go in a header",
		},
		{
			name:       "a password method without a username entry",
			token:      passwordToken(`{"password":{"in":"header","name":"X-Pass"}}`),
			wantReason: oauth.PlacementInvalidMethod, wantErr: "does not have both username and password",
		},
		{
			name: "a password method naming one header twice, in two cases",
			token: passwordToken(`{"username":{"in":"header","name":"X-Cred"},` +
				`"password":{"in":"header","name":"x-cred"}}`),
			wantReason: oauth.PlacementInvalidMethod, wantErr: "both name header",
		},
		{
			name: "a password in a cookie",
			token: passwordToken(`{"username":{"in":"header","name":"X-User"},` +
				`"password":{"in":"cookie","name":"pass"}}`),
			wantReason: oauth.PlacementInvalidMethod, wantErr: `method.password.in "cookie"`,
		},
		{
			name: "a password token without a username",
			token: &oauth.TokenResponse{
				AccessToken: password, TokenType: oauth.TokenTypeKeycardPassword,
				Method: json.RawMessage(`{"username":{"in":"header","name":"X-User"},` +
					`"password":{"in":"header","name":"X-Pass"}}`),
			},
			wantReason: oauth.PlacementInvalidCredential, wantErr: "username is missing",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issued := credential.Issued{Value: tc.token.AccessToken, Token: tc.token}
			writer, err := issued.Writer(bearerPlacement)
			assert.Nil(t, writer, "a refused token has no writer")
			require.ErrorContains(t, err, tc.wantErr, "message")
			var placementErr *oauth.CredentialPlacementError
			require.ErrorAs(t, err, &placementErr, "Writer")
			assert.Equal(t, tc.wantReason, placementErr.Reason, "reason")
			assert.NotContains(t, err.Error(), tc.token.AccessToken, "the message never holds the credential")
		})
	}
}

// TestAnIssuedCredentialWithoutAMethodUsesThePlacement checks that a
// credential without a token response goes where the endpoint placement
// says, and that Validate still refuses one the placement cannot write.
func TestAnIssuedCredentialWithoutAMethodUsesThePlacement(t *testing.T) {
	t.Parallel()
	writer, err := credential.Issued{Value: secret}.Writer(bearerPlacement)
	require.NoError(t, err, "Writer")
	out := workloadRequest(t)
	require.NoError(t, writer.Write(out, secret), "Write")
	assert.Equal(t, "Bearer "+secret, out.Header.Get("Authorization"), "the placement header")

	_, err = credential.Issued{Value: "a\nb"}.Writer(bearerPlacement)
	require.ErrorContains(t, err, "invalid credential: contains an invalid character", "Validate")
}

// TestIssuedWireFormsCoverTheUsername checks that Redact covers both values
// a Keycard-Password token writes, in the raw form a header holds and the
// escaped form a query holds.
func TestIssuedWireFormsCoverTheUsername(t *testing.T) {
	t.Parallel()
	issued := credential.Issued{Value: "p w", Token: &oauth.TokenResponse{
		AccessToken: "p w", TokenType: oauth.TokenTypeKeycardPassword, Username: "u@x",
	}}
	forms := issued.WireForms(bearerPlacement)
	assert.Equal(t, []string{"p w", "u@x"}, forms, "WireForms")
	assert.Equal(t, "header [redacted] query ?user=[redacted]&pass=[redacted]",
		credential.Redact("header u@x query ?user=u%40x&pass=p+w", forms), "Redact")
}
