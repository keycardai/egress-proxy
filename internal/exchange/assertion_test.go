package exchange_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/assertion"
	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/exchange"
)

// jwtBearer is the client assertion type the zone reads.
const jwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec // G101: a URN

// tokenAnswer is what the fake zone's token endpoint returns.
type tokenAnswer struct {
	status    int
	body      map[string]any
	expiresIn int
}

// assertionZone is a zone that takes a client_credentials grant with a
// jwt-bearer client assertion. It counts token requests and keeps the last
// form it read.
type assertionZone struct {
	url    string
	roots  *x509.CertPool
	hits   atomic.Int64
	answer tokenAnswer
	last   atomicForm
}

type atomicForm struct {
	value atomic.Pointer[map[string][]string]
}

func (f *atomicForm) set(form map[string][]string) { f.value.Store(&form) }
func (f *atomicForm) get() map[string][]string     { return *f.value.Load() }

func newAssertionZone(t *testing.T, answer tokenAnswer) *assertionZone {
	t.Helper()
	zone := &assertionZone{answer: answer}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": zone.url, "token_endpoint": zone.url + "/oauth2/token",
			})
		case "/oauth2/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			zone.hits.Add(1)
			zone.last.set(r.PostForm)
			w.WriteHeader(zone.answer.status)
			body := zone.answer.body
			if body == nil {
				body = map[string]any{
					"access_token": "issued-for-" + r.PostForm.Get("resource"), "token_type": "Bearer",
					"expires_in": zone.answer.expiresIn,
				}
			}
			_ = json.NewEncoder(w).Encode(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	zone.url = server.URL
	zone.roots = x509.NewCertPool()
	zone.roots.AddCert(server.Certificate())
	return zone
}

func (z *assertionZone) source(t *testing.T) *exchange.AssertionSource {
	t.Helper()
	source, err := exchange.NewAssertionSource(exchange.AssertionOptions{ZoneURL: z.url, Roots: z.roots})
	require.NoError(t, err)
	return source
}

// ownerSource builds the source that exchanges for the sandbox owner.
func (z *assertionZone) ownerSource(t *testing.T) *exchange.AssertionSource {
	t.Helper()
	source, err := exchange.NewAssertionSource(exchange.AssertionOptions{
		ZoneURL: z.url, Roots: z.roots, ImpersonateOwner: true,
	})
	require.NoError(t, err)
	return source
}

// sandboxToken signs an assertion for a review-agent sandbox that names no
// owner. The source reads only the claims, so the key is fresh every time.
func sandboxToken(t *testing.T, sandboxUUID string) string {
	t.Helper()
	return ownedToken(t, sandboxUUID, "")
}

// ownedToken signs an assertion for a review-agent sandbox whose owner has
// the Keycard user id ownerID. An empty id leaves the claim out.
func ownedToken(t *testing.T, sandboxUUID, ownerID string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	token, err := assertion.Sign(key, assertion.Claims{
		Issuer: "https://extension.greendale.example", Application: "review-agent",
		Sandbox: "keycard-demo", SandboxUUID: sandboxUUID, Owner: "troy.barnes", OwnerID: ownerID,
	}, []string{"keycard-egress-proxy"}, time.Now(), 30*time.Second)
	require.NoError(t, err)
	return token
}

// TestAssertionSourceSendsTheForm pins the wire form: a client_credentials
// grant, the assertion as a jwt-bearer client assertion, the resource, and
// no client_id or scope.
func TestAssertionSourceSendsTheForm(t *testing.T) {
	t.Parallel()
	zone := newAssertionZone(t, tokenAnswer{status: http.StatusOK, expiresIn: 300})
	token := sandboxToken(t, "7f3a")
	got, err := zone.source(t).Credential(assertion.WithToken(t.Context(), token), resource)
	require.NoError(t, err)
	assert.Equal(t, "issued-for-"+resource, got)
	form := zone.last.get()
	assert.Equal(t, []string{"client_credentials"}, form["grant_type"])
	assert.Equal(t, []string{jwtBearer}, form["client_assertion_type"])
	assert.Equal(t, []string{token}, form["client_assertion"])
	assert.Equal(t, []string{resource}, form["resource"])
	assert.NotContains(t, form, "client_id")
	assert.NotContains(t, form, "scope")
}

// TestAssertionSourceCaches pins the cache: one zone request per subject
// and resource while the token lives, a new one once it is within the
// margin of expiry, and none at all for a response without expires_in.
func TestAssertionSourceCaches(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		expiresIn int
		second    string
		resource  string
		elapsed   time.Duration
		wantHits  int64
	}{
		"the same subject and resource": {
			expiresIn: 300, second: "7f3a", resource: resource, wantHits: 1,
		},
		"another sandbox of the same application": {
			expiresIn: 300, second: "8b4c", resource: resource, wantHits: 2,
		},
		"another resource": {
			expiresIn: 300, second: "7f3a", resource: "https://other.example/", wantHits: 2,
		},
		"within the margin of expiry": {
			expiresIn: 300, second: "7f3a", resource: resource, elapsed: 280 * time.Second, wantHits: 2,
		},
		"no expires_in": {
			expiresIn: 0, second: "7f3a", resource: resource, wantHits: 2,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			zone := newAssertionZone(t, tokenAnswer{status: http.StatusOK, expiresIn: tc.expiresIn})
			source := zone.source(t)
			now := time.Now()
			exchange.SetClock(source, func() time.Time { return now })
			_, err := source.Credential(assertion.WithToken(t.Context(), sandboxToken(t, "7f3a")), resource)
			require.NoError(t, err)
			exchange.SetClock(source, func() time.Time { return now.Add(tc.elapsed) })
			second := assertion.WithToken(t.Context(), sandboxToken(t, tc.second))
			_, err = source.Credential(second, tc.resource)
			require.NoError(t, err)
			assert.Equal(t, tc.wantHits, zone.hits.Load(), "token requests the zone saw")
		})
	}
}

// TestAssertionSourceFailures pins the two failure classes and the
// programming error of a call without a token on the context.
func TestAssertionSourceFailures(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		answer  tokenAnswer
		noToken bool
		want    error
		wantMsg string
		// wantDetail is the prose the refusal carries. An OAuth answer with
		// no error_description carries its code.
		wantDetail string
	}{
		"invalid_client is a policy refusal": {
			answer: tokenAnswer{
				status: http.StatusUnauthorized,
				body:   map[string]any{"error": "invalid_client", "error_description": "no subject matches"},
			},
			want: credential.ErrExchangeDenied, wantMsg: "no subject matches", wantDetail: "no subject matches",
		},
		"access_denied is a policy refusal": {
			answer: tokenAnswer{
				status: http.StatusForbidden,
				body:   map[string]any{"error": "access_denied", "error_description": "no grant"},
			},
			want: credential.ErrExchangeDenied, wantMsg: "no grant", wantDetail: "no grant",
		},
		"a missing grant of the owner's is authorization_required": {
			answer: tokenAnswer{
				status: http.StatusForbidden,
				body: map[string]any{
					"error":             "insufficient_authorization",
					"error_description": "User authorization is required for resource " + resource + ".",
				},
			},
			want: credential.ErrAuthorizationRequired, wantMsg: "User authorization is required",
			wantDetail: "User authorization is required for resource " + resource + ". " +
				"Run 'keycard auth resource " + resource + "' as that person, then retry.",
		},
		"a server error is a failure": {
			answer: tokenAnswer{status: http.StatusInternalServerError, body: map[string]any{"error": "server_error"}},
			want:   credential.ErrExchangeFailed, wantMsg: "server_error", wantDetail: "server_error",
		},
		"no token on the context": {
			answer: tokenAnswer{status: http.StatusOK, expiresIn: 300}, noToken: true,
			want: credential.ErrExchangeFailed, wantMsg: "no sandbox assertion",
			wantDetail: "no sandbox assertion on the request context",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			zone := newAssertionZone(t, tc.answer)
			ctx := t.Context()
			if !tc.noToken {
				ctx = assertion.WithToken(ctx, sandboxToken(t, "7f3a"))
			}
			_, err := zone.source(t).Credential(ctx, resource)
			require.ErrorIs(t, err, tc.want)
			assert.Contains(t, err.Error(), tc.wantMsg)
			assert.Equal(t, tc.wantDetail, credential.Detail(err), "the detail the refusal carries")
			assert.NotContains(t, err.Error(), "eyJ", "the error never quotes the token")
			assert.NotContains(t, credential.Detail(err), "eyJ", "the detail never quotes the token")
			if tc.noToken {
				assert.Zero(t, zone.hits.Load(), "a call without a token reaches no zone")
			}
		})
	}
}

// TestAssertionSourceRefusesACleartextZone pins that the source is built
// for https alone, so the assertion never goes over cleartext.
func TestAssertionSourceRefusesACleartextZone(t *testing.T) {
	t.Parallel()
	_, err := exchange.NewAssertionSource(exchange.AssertionOptions{ZoneURL: "http://zone.example"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

// TestAssertionSourceDescribe pins the announcement, which names the zone
// and the mechanism and nothing a request carries.
func TestAssertionSourceDescribe(t *testing.T) {
	t.Parallel()
	zone := newAssertionZone(t, tokenAnswer{status: http.StatusOK, expiresIn: 300})
	assert.Equal(t, "sandbox assertions exchanged at "+zone.url+" as the sandbox (client_credentials, jwt-bearer)",
		zone.source(t).Describe())
}

// TestOwnerSourceSendsTheForm pins the wire form of the exchange for the
// sandbox owner: a token exchange whose subject is the substitute-user
// token for the assertion's owner_id, the assertion as a jwt-bearer client
// assertion, the resource, and no client_id, scope or actor_token.
func TestOwnerSourceSendsTheForm(t *testing.T) {
	t.Parallel()
	zone := newAssertionZone(t, tokenAnswer{status: http.StatusOK, expiresIn: 300})
	token := ownedToken(t, "7f3a", user)
	got, err := zone.ownerSource(t).Credential(assertion.WithToken(t.Context(), token), resource)
	require.NoError(t, err)
	assert.Equal(t, "issued-for-"+resource, got)
	form := zone.last.get()
	assert.Equal(t, []string{"urn:ietf:params:oauth:grant-type:token-exchange"}, form["grant_type"])
	assert.Equal(t, []string{substituteUser(t, user)}, form["subject_token"])
	assert.Equal(t, []string{"urn:keycard:params:oauth:token-type:substitute-user"}, form["subject_token_type"])
	assert.Equal(t, []string{jwtBearer}, form["client_assertion_type"])
	assert.Equal(t, []string{token}, form["client_assertion"])
	assert.Equal(t, []string{resource}, form["resource"])
	assert.NotContains(t, form, "client_id")
	assert.NotContains(t, form, "scope")
	assert.NotContains(t, form, "actor_token")
}

// TestOwnerSourceRefusesAnAssertionWithoutAnOwner pins that an assertion
// with no owner_id is refused before any exchange as credential_unavailable,
// with a detail that says so.
func TestOwnerSourceRefusesAnAssertionWithoutAnOwner(t *testing.T) {
	t.Parallel()
	zone := newAssertionZone(t, tokenAnswer{status: http.StatusOK, expiresIn: 300})
	_, err := zone.ownerSource(t).Credential(assertion.WithToken(t.Context(), sandboxToken(t, "7f3a")), resource)
	require.ErrorIs(t, err, credential.ErrUnavailable)
	require.NotErrorIs(t, err, credential.ErrExchangeDenied)
	require.NotErrorIs(t, err, credential.ErrExchangeFailed)
	assert.Equal(t, "the assertion names no owner", credential.Detail(err), "the detail the refusal carries")
	assert.NotContains(t, err.Error(), "eyJ", "the error never quotes the token")
	assert.Zero(t, zone.hits.Load(), "an assertion without an owner reaches no zone")
}

// TestOwnerSourceCachesPerOwner pins that the cache keys on the owner as
// well as the subject and the resource.
func TestOwnerSourceCachesPerOwner(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		second   string
		owner    string
		wantHits int64
	}{
		"the same subject and owner":      {second: "7f3a", owner: user, wantHits: 1},
		"the same subject, another owner": {second: "7f3a", owner: "abed", wantHits: 2},
		"another subject, the same owner": {second: "8b4c", owner: user, wantHits: 2},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			zone := newAssertionZone(t, tokenAnswer{status: http.StatusOK, expiresIn: 300})
			source := zone.ownerSource(t)
			_, err := source.Credential(assertion.WithToken(t.Context(), ownedToken(t, "7f3a", user)), resource)
			require.NoError(t, err)
			_, err = source.Credential(assertion.WithToken(t.Context(), ownedToken(t, tc.second, tc.owner)), resource)
			require.NoError(t, err)
			assert.Equal(t, tc.wantHits, zone.hits.Load(), "token requests the zone saw")
		})
	}
}

// TestOwnerSourceFailures pins that a zone refusal of the owner exchange
// keeps the two classes: the impersonation codes are policy refusals, and
// anything else is a failure.
func TestOwnerSourceFailures(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		answer     tokenAnswer
		want       error
		wantDetail string
	}{
		"unauthorized_client is a policy refusal": {
			answer: tokenAnswer{
				status: http.StatusForbidden,
				body:   map[string]any{"error": "unauthorized_client", "error_description": "review-agent cannot act for troy"},
			},
			want: credential.ErrExchangeDenied, wantDetail: "review-agent cannot act for troy",
		},
		"invalid_grant is a policy refusal": {
			answer: tokenAnswer{
				status: http.StatusBadRequest,
				body:   map[string]any{"error": "invalid_grant", "error_description": "no such user"},
			},
			want: credential.ErrExchangeDenied, wantDetail: "no such user",
		},
		"invalid_client is a policy refusal": {
			answer: tokenAnswer{
				status: http.StatusUnauthorized,
				body:   map[string]any{"error": "invalid_client", "error_description": "no subject matches"},
			},
			want: credential.ErrExchangeDenied, wantDetail: "no subject matches",
		},
		"a server error is a failure": {
			answer: tokenAnswer{status: http.StatusInternalServerError, body: map[string]any{"error": "server_error"}},
			want:   credential.ErrExchangeFailed, wantDetail: "server_error",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			zone := newAssertionZone(t, tc.answer)
			_, err := zone.ownerSource(t).Credential(assertion.WithToken(t.Context(), ownedToken(t, "7f3a", user)), resource)
			require.ErrorIs(t, err, tc.want)
			assert.Equal(t, tc.wantDetail, credential.Detail(err), "the detail the refusal carries")
			assert.NotContains(t, err.Error(), "eyJ", "the error never quotes the token")
		})
	}
}

// TestOwnerSourceDescribe pins the announcement for the owner exchange.
func TestOwnerSourceDescribe(t *testing.T) {
	t.Parallel()
	zone := newAssertionZone(t, tokenAnswer{status: http.StatusOK, expiresIn: 300})
	assert.Equal(t, "sandbox assertions exchanged at "+zone.url+" for the sandbox owner (token-exchange, jwt-bearer)",
		zone.ownerSource(t).Describe())
}
