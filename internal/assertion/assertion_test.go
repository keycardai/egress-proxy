package assertion_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/assertion"
)

const (
	audience = "keycard-egress-proxy"
	issuer   = "https://extension.greendale.example"
	maxAge   = 30 * time.Second
)

// at is the instant every test signs at.
func at() time.Time { return time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC) }

// troy is the claims a review-agent sandbox named keycard-demo carries.
// Subject is left for Sign to fill.
func troy() assertion.Claims {
	return assertion.Claims{
		Issuer: issuer, Application: "review-agent", Sandbox: "keycard-demo", Workspace: "default",
		SandboxUUID: "26697100-f1ee-45cf-8ab9-8ee6fb645700", ExecPath: "/usr/bin/curl",
	}
}

// keypair returns a fresh P-256 key and a verifier that trusts it.
func keypair(t *testing.T, opts ...assertion.Option) (*ecdsa.PrivateKey, *assertion.Verifier) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pemBytes, err := assertion.MarshalPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	verifier, err := assertion.NewVerifier(pemBytes, audience, maxAge, opts...)
	require.NoError(t, err)
	return priv, verifier
}

// owned is troy with the owner the runtime recorded at create.
func owned() assertion.Claims {
	claims := troy()
	claims.Owner = "openshell-client"
	return claims
}

// TestSignAndVerifyRoundTrip pins the claim set both ways: Verify returns
// what Sign was given plus the subject Sign derived, a token with a second
// audience for the zone is accepted by a verifier that checks only its own,
// and the owner travels when set and only then.
func TestSignAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	priv, verifier := keypair(t)
	tests := map[string]struct {
		claims    assertion.Claims
		audiences []string
	}{
		"the proxy audience alone": {claims: troy(), audiences: []string{audience}},
		"the proxy and the zone audience": {
			claims: troy(), audiences: []string{audience, "https://z.example/oauth/2/token"},
		},
		"an owner": {claims: owned(), audiences: []string{audience}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			token, err := assertion.Sign(priv, tc.claims, tc.audiences, at(), maxAge)
			require.NoError(t, err)
			got, err := verifier.Verify(token, at().Add(10*time.Second))
			require.NoError(t, err)
			want := tc.claims
			want.Subject = "openshell:review-agent:26697100-f1ee-45cf-8ab9-8ee6fb645700"
			assert.Equal(t, want, got)
		})
	}
}

// TestSignedHeader pins the JOSE header the zone reads: ES256, a kid that
// is the RFC 7638 thumbprint of the public key, and typ JWT.
func TestSignedHeader(t *testing.T) {
	t.Parallel()
	priv, _ := keypair(t)
	token, err := assertion.Sign(priv, troy(), []string{audience}, at(), maxAge)
	require.NoError(t, err)
	parsed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	require.Len(t, parsed.Signatures, 1)
	header := parsed.Signatures[0].Header
	assert.Equal(t, string(jose.ES256), header.Algorithm)
	assert.Equal(t, "JWT", header.ExtraHeaders[jose.HeaderType])
	thumbprint, err := (&jose.JSONWebKey{Key: &priv.PublicKey}).Thumbprint(assertion.ThumbprintHash)
	require.NoError(t, err)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(thumbprint), header.KeyID)
}

// TestWireClaimNames pins the claim names a signer outside this module
// writes and a verifier outside it reads.
func TestWireClaimNames(t *testing.T) {
	t.Parallel()
	priv, verifier := keypair(t)
	token, err := assertion.Sign(priv, owned(), []string{audience}, at(), maxAge)
	require.NoError(t, err)
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	names := []string{
		"iss", "sub", "aud", "iat", "exp", "jti", "app", "sandbox", "workspace", "sandbox_id", "exec_path", "owner",
	}
	for _, name := range names {
		assert.Contains(t, claims, name)
	}
	assert.Equal(t, "openshell:review-agent:26697100-f1ee-45cf-8ab9-8ee6fb645700", claims["sub"])
	assert.Equal(t, "keycard-demo", claims["sandbox"])
	assert.Equal(t, "openshell-client", claims["owner"])
	assert.NotEmpty(t, claims["jti"])
	got, err := verifier.Verify(token, at())
	require.NoError(t, err)
	assert.Equal(t, "keycard-demo", got.Sandbox)
	assert.Equal(t, issuer, got.Issuer)
}

// TestVerifyToleratesClockSkew pins the leeway: a signer whose clock runs
// ahead of the proxy by less than Leeway is accepted, and so is a token read
// shortly after its expiry.
func TestVerifyToleratesClockSkew(t *testing.T) {
	t.Parallel()
	priv, verifier := keypair(t)
	token, err := assertion.Sign(priv, troy(), []string{audience}, at(), maxAge)
	require.NoError(t, err)
	_, err = verifier.Verify(token, at().Add(-assertion.Leeway/2))
	require.NoError(t, err, "issued half a leeway in the future")
	_, err = verifier.Verify(token, at().Add(maxAge+assertion.Leeway/2))
	require.NoError(t, err, "read half a leeway after expiry")
}

// TestVerifyPinsTheIssuer pins WithIssuer: a verifier given one refuses any
// other, and one given none accepts whatever the token names.
func TestVerifyPinsTheIssuer(t *testing.T) {
	t.Parallel()
	priv, pinned := keypair(t, assertion.WithIssuer(issuer))
	other := troy()
	other.Issuer = "https://chang.example"
	token, err := assertion.Sign(priv, other, []string{audience}, at(), maxAge)
	require.NoError(t, err)
	_, err = pinned.Verify(token, at())
	require.ErrorIs(t, err, assertion.ErrInvalid)
	assert.Contains(t, err.Error(), "issuer")
	expected, err := assertion.Sign(priv, troy(), []string{audience}, at(), maxAge)
	require.NoError(t, err)
	_, err = pinned.Verify(expected, at())
	require.NoError(t, err)
}

func TestVerifyRefusals(t *testing.T) {
	t.Parallel()
	priv, verifier := keypair(t)
	otherPriv, _ := keypair(t)
	sign := func(key *ecdsa.PrivateKey, aud string, ttl time.Duration) string {
		token, err := assertion.Sign(key, troy(), []string{aud}, at(), ttl)
		require.NoError(t, err)
		return token
	}
	// raw signs the claims as given, so a case can leave one out or
	// contradict another. Sign refuses to build such a token.
	raw := func(change func(standard *jwt.Claims, private map[string]any)) string {
		standard, private := wireClaims()
		change(&standard, private)
		return rawToken(t, jose.SigningKey{Algorithm: jose.ES256, Key: priv}, standard, private)
	}
	tests := map[string]struct {
		token string
		when  time.Time
		want  string
	}{
		"another key":       {token: sign(otherPriv, audience, maxAge), when: at(), want: "signature"},
		"another audience":  {token: sign(priv, "someone-else", maxAge), when: at(), want: "audience"},
		"lifetime over max": {token: sign(priv, audience, time.Hour), when: at(), want: "lifetime"},
		"expired": {
			token: sign(priv, audience, maxAge), when: at().Add(maxAge + 2*assertion.Leeway), want: "expired",
		},
		"issued in the future": {
			token: sign(priv, audience, maxAge), when: at().Add(-2 * assertion.Leeway), want: "future",
		},
		"no subject": {
			token: raw(func(s *jwt.Claims, _ map[string]any) { s.Subject = "" }), when: at(), want: "sub",
		},
		"no issuer": {
			token: raw(func(s *jwt.Claims, _ map[string]any) { s.Issuer = "" }), when: at(), want: "iss",
		},
		"no jti": {
			token: raw(func(s *jwt.Claims, _ map[string]any) { s.ID = "" }), when: at(), want: "jti",
		},
		"no app": {
			token: raw(func(_ *jwt.Claims, p map[string]any) { delete(p, "app") }), when: at(), want: "app",
		},
		"no sandbox name": {
			token: raw(func(_ *jwt.Claims, p map[string]any) { delete(p, "sandbox") }), when: at(), want: "sandbox claim",
		},
		"no sandbox id": {
			token: raw(func(_ *jwt.Claims, p map[string]any) { delete(p, "sandbox_id") }), when: at(), want: "sandbox_id",
		},
		"a subject for another application": {
			token: raw(func(s *jwt.Claims, _ map[string]any) { s.Subject = "openshell:chang-agent:" + troy().SandboxUUID }),
			when:  at(), want: "sub",
		},
		"a subject for another sandbox": {
			token: raw(func(s *jwt.Claims, _ map[string]any) { s.Subject = "openshell:review-agent:other" }),
			when:  at(), want: "sub",
		},
		"not a token":         {token: "troy.barnes", when: at(), want: "parse"},
		"empty":               {token: "", when: at(), want: "parse"},
		"symmetric algorithm": {token: hs256Token(t), when: at(), want: "parse"},
		"eddsa":               {token: eddsaToken(t), when: at(), want: "parse"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := verifier.Verify(tc.token, tc.when)
			require.ErrorIs(t, err, assertion.ErrInvalid)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), "eyJ", "the error never quotes the token")
		})
	}
}

// wireClaims is a complete, valid claim set in wire form.
func wireClaims() (jwt.Claims, map[string]any) {
	claims := troy()
	standard := jwt.Claims{
		Issuer:   issuer,
		Subject:  "openshell:review-agent:" + claims.SandboxUUID,
		Audience: jwt.Audience{audience},
		IssuedAt: jwt.NewNumericDate(at()),
		Expiry:   jwt.NewNumericDate(at().Add(maxAge)),
		ID:       "jti-abed",
	}
	private := map[string]any{
		"app": claims.Application, "sandbox": claims.Sandbox, "workspace": claims.Workspace,
		"sandbox_id": claims.SandboxUUID, "exec_path": claims.ExecPath,
	}
	return standard, private
}

// rawToken signs the claims exactly as given.
func rawToken(t *testing.T, key jose.SigningKey, standard jwt.Claims, private map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(key, nil)
	require.NoError(t, err)
	token, err := jwt.Signed(signer).Claims(standard).Claims(private).Serialize()
	require.NoError(t, err)
	return token
}

// hs256Token is a token signed with a symmetric key. The verifier pins
// ES256, so this must fail at parse, before any key is consulted.
func hs256Token(t *testing.T) string {
	t.Helper()
	standard, private := wireClaims()
	key := []byte("greendale-community-college-1972")
	return rawToken(t, jose.SigningKey{Algorithm: jose.HS256, Key: key}, standard, private)
}

// eddsaToken is a token under the algorithm an earlier signer used. The
// zone refuses Ed25519, so the verifier does too.
func eddsaToken(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	standard, private := wireClaims()
	return rawToken(t, jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, standard, private)
}

func TestNewVerifierRefusals(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		pem  []byte
		want string
	}{
		"not pem":             {pem: []byte("troy barnes"), want: "PEM"},
		"an rsa key":          {pem: pkixPEM(t, rsaPublic(t)), want: "P-256"},
		"an ed25519 key":      {pem: pkixPEM(t, ed25519Public(t)), want: "P-256"},
		"another ecdsa curve": {pem: pkixPEM(t, ecdsaPublic(t, elliptic.P384())), want: "P-256"},
		"empty":               {pem: nil, want: "PEM"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := assertion.NewVerifier(tc.pem, audience, maxAge)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func pkixPEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func rsaPublic(t *testing.T) *rsa.PublicKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &key.PublicKey
}

func ed25519Public(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub
}

func ecdsaPublic(t *testing.T, curve elliptic.Curve) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return &key.PublicKey
}

// TestSignRefusals pins that Sign builds no token the verifier would refuse
// for a missing claim.
func TestSignRefusals(t *testing.T) {
	t.Parallel()
	priv, _ := keypair(t)
	without := func(change func(*assertion.Claims)) assertion.Claims {
		claims := troy()
		change(&claims)
		return claims
	}
	proxy := []string{audience}
	tests := map[string]struct {
		claims    assertion.Claims
		audiences []string
		want      string
	}{
		"no issuer": {claims: without(func(c *assertion.Claims) { c.Issuer = "" }), audiences: proxy, want: "issuer"},
		"no application": {
			claims:    without(func(c *assertion.Claims) { c.Application = "" }),
			audiences: proxy,
			want:      "application",
		},
		"no sandbox": {
			claims:    without(func(c *assertion.Claims) { c.Sandbox = "" }),
			audiences: proxy,
			want:      "sandbox name",
		},
		"no sandbox id": {
			claims:    without(func(c *assertion.Claims) { c.SandboxUUID = "" }),
			audiences: proxy,
			want:      "sandbox id",
		},
		"no audience": {claims: troy(), audiences: nil, want: "audience"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := assertion.Sign(priv, tc.claims, tc.audiences, at(), maxAge)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestTokenContext pins the request-scoped carrier for the raw token.
func TestTokenContext(t *testing.T) {
	t.Parallel()
	_, ok := assertion.TokenFromContext(t.Context())
	assert.False(t, ok, "a bare context carries no token")
	ctx := assertion.WithToken(t.Context(), "eyJ.troy.barnes")
	got, ok := assertion.TokenFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "eyJ.troy.barnes", got)
}
