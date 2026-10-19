package fakeas_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/assertion"
	"github.com/keycardai/egress-proxy/test/fakeas"
)

const reviewSubject = "openshell:review-agent:7f3a"

// extension publishes one P-256 key the way the OpenShell extension does.
type extension struct {
	key *ecdsa.PrivateKey
	url string
}

// newExtension starts the issuer. Its discovery names its own URL as the
// issuer, and its key set carries the key under its RFC 7638 kid.
func newExtension(t *testing.T) *extension {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kid, err := assertion.KeyID(&key.PublicKey)
	require.NoError(t, err)
	ext := &extension{key: key}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": ext.url, "jwks_uri": ext.url + "/jwks.json"})
		case "/jwks.json":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: &key.PublicKey, KeyID: kid, Use: "sig", Algorithm: string(jose.ES256)},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	ext.url = server.URL
	return ext
}

// token signs a sandbox assertion under the extension's key for subject.
func (e *extension) token(t *testing.T, subject string, change func(*jwt.Claims)) string {
	t.Helper()
	claims := jwt.Claims{
		Issuer: e.url, Subject: subject, Audience: jwt.Audience{"keycard-egress-proxy"}, ID: "jti-troy",
		IssuedAt: jwt.NewNumericDate(time.Now()), Expiry: jwt.NewNumericDate(time.Now().Add(30 * time.Second)),
	}
	if change != nil {
		change(&claims)
	}
	return signES256(t, e.key, claims)
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, claims jwt.Claims) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	require.NoError(t, err)
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func workloadForm(token string) url.Values {
	return url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {token},
		"resource":              {resource},
	}
}

// TestWorkloadGrant pins the client_credentials path: the issuer is
// discovered from the assertion, the key found by kid, ES256 verified, the
// subject matched against the patterns, and the token names the matched
// application.
func TestWorkloadGrant(t *testing.T) {
	t.Parallel()
	ext := newExtension(t)
	other := newExtension(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	zone := fakeas.New(fakeas.Options{
		Credentials:      map[string]string{resource: credential},
		WorkloadSubjects: map[string]string{"openshell:review-agent:*": "review-agent", "openshell:exact:1": "exact"},
	})
	tests := map[string]struct {
		form      url.Values
		want      answer
		wantToken string
		wantActor string
	}{
		"a prefix pattern matches": {
			form: workloadForm(ext.token(t, reviewSubject, nil)), want: answer{status: http.StatusOK},
			wantToken: "review-agent:" + credential, wantActor: reviewSubject,
		},
		"an exact pattern matches": {
			form: workloadForm(ext.token(t, "openshell:exact:1", nil)), want: answer{status: http.StatusOK},
			wantToken: "exact:" + credential, wantActor: "openshell:exact:1",
		},
		"no pattern matches": {
			form: workloadForm(ext.token(t, "openshell:chang-agent:9c5d", nil)),
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: "no application credential matches openshell:chang-agent:9c5d",
			},
			wantActor: "openshell:chang-agent:9c5d",
		},
		"an exact pattern does not match a longer subject": {
			form: workloadForm(ext.token(t, "openshell:exact:12", nil)),
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: "no application credential matches openshell:exact:12",
			},
			wantActor: "openshell:exact:12",
		},
		"a key the issuer does not publish": {
			form: workloadForm(signES256(t, otherKey, jwt.Claims{
				Issuer: ext.url, Subject: reviewSubject, IssuedAt: jwt.NewNumericDate(time.Now()),
				Expiry: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			})),
			want: answer{status: http.StatusUnauthorized, code: "invalid_client"},
		},
		"another issuer's key": {
			form: workloadForm(other.token(t, reviewSubject, func(c *jwt.Claims) { c.Issuer = ext.url })),
			want: answer{status: http.StatusUnauthorized, code: "invalid_client"},
		},
		"an issuer that does not discover": {
			form: workloadForm(ext.token(t, reviewSubject, func(c *jwt.Claims) { c.Issuer = "http://127.0.0.1:1" })),
			want: answer{status: http.StatusUnauthorized, code: "invalid_client"},
		},
		"no issuer": {
			form: workloadForm(ext.token(t, reviewSubject, func(c *jwt.Claims) { c.Issuer = "" })),
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: "the client assertion has no iss claim",
			},
		},
		"expired": {
			form: workloadForm(ext.token(t, reviewSubject, func(c *jwt.Claims) {
				c.Expiry = jwt.NewNumericDate(time.Now().Add(-time.Minute))
			})),
			want: answer{status: http.StatusUnauthorized, code: "invalid_client"},
		},
		"no iat": {
			form: workloadForm(ext.token(t, reviewSubject, func(c *jwt.Claims) { c.IssuedAt = nil })),
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: "the client assertion has no iat claim",
			},
		},
		"sub equal to iss": {
			form: workloadForm(ext.token(t, ext.url, nil)),
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: "the client assertion's sub must be set and differ from iss",
			},
		},
		"a client_id beside the assertion": {
			form: with(workloadForm(ext.token(t, reviewSubject, nil)), "client_id", "review"),
			want: answer{
				status: http.StatusBadRequest, code: "invalid_request",
				description: "a client assertion names its client by its subject and sends no client_id",
			},
		},
		"the wrong assertion type": {
			form: with(workloadForm(ext.token(t, reviewSubject, nil)), "client_assertion_type", "saml"),
			want: answer{status: http.StatusUnauthorized, code: "invalid_client"},
		},
		"no assertion": {
			form: url.Values{"grant_type": {"client_credentials"}, "resource": {resource}},
			want: answer{
				status: http.StatusUnauthorized, code: "invalid_client",
				description: "the client_credentials grant sends no client assertion",
			},
		},
		"a resource no policy grants": {
			form: with(workloadForm(ext.token(t, reviewSubject, nil)), "resource", "https://other.example/"),
			want: answer{
				status: http.StatusForbidden, code: "access_denied",
				description: "no policy grants https://other.example/",
			},
			wantActor: reviewSubject,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, token := post(t, zone, tc.form)
			assert.Equal(t, tc.want.status, got.status, "status: %+v", got)
			assert.Equal(t, tc.want.code, got.code, "error code: %+v", got)
			if tc.want.description != "" {
				assert.Equal(t, tc.want.description, got.description, "description")
			}
			assert.Equal(t, tc.wantToken, token, "the token names the application")
			record := lastRequest(t, zone, tc.form.Get("client_assertion"))
			assert.Equal(t, tc.wantActor, record.Actor, "the recorded actor")
			assert.Equal(t, tc.form.Get("client_id"), record.ClientID, "the recorded client id is what was posted")
		})
	}
}

// with sets one form value.
func with(form url.Values, key, value string) url.Values {
	form.Set(key, value)
	return form
}

// lastRequest finds the record for the assertion the form sent. Cases run
// in parallel, so the records interleave.
func lastRequest(t *testing.T, zone *fakeas.Server, token string) fakeas.Request {
	t.Helper()
	for _, record := range zone.Requests() {
		if record.Form.Get("client_assertion") == token {
			return record
		}
	}
	t.Fatalf("no record for the request")
	return fakeas.Request{}
}
