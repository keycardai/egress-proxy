package proxy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/assertion"
	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/policy"
	"github.com/keycardai/egress-proxy/internal/proxy"
)

const (
	assertionHeader   = "X-Keycard-Sandbox-Assertion"
	assertionAudience = "keycard-egress-proxy"
	demoSecret        = "demo-sekrit"     //nolint:gosec // G101: a test fixture
	researchSecret    = "research-sekrit" //nolint:gosec // G101: a test fixture
	reviewSecret      = "review-sekrit"   //nolint:gosec // G101: a test fixture
	studySecret       = "study-sekrit"    //nolint:gosec // G101: a test fixture
)

// sandboxHarness starts a proxy that identifies sandboxes. Two sandboxes
// and two applications map to four static credentials for the header
// resource; the plain endpoint names no credential. With applications
// false the document lists the two sandboxes alone, so the sandbox map
// answers.
func sandboxHarness(t *testing.T, applications bool) (*harness, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pemBytes, err := assertion.MarshalPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	verifier, err := assertion.NewVerifier(pemBytes, assertionAudience, 30*time.Second)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "credentials.yaml")
	body := "version: 1\ncredentials:\n" +
		"  - resource: " + headerResource + "\n    sandbox: keycard-demo\n    value: " + demoSecret + "\n" +
		"  - resource: " + headerResource + "\n    sandbox: troy-research\n    value: " + researchSecret + "\n" +
		"  - resource: " + headerResource + "\n    application: review-agent\n    value: " + reviewSecret + "\n" +
		"  - resource: " + headerResource + "\n    application: study-group\n    value: " + studySecret + "\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	file, err := credential.LoadStaticFile(path)
	require.NoError(t, err)
	selector := credential.NewSelector()
	for _, name := range []string{"keycard-demo", "troy-research"} {
		require.NoError(t, selector.Add(credential.SandboxKey{Name: name, Workspace: "default"},
			credential.Selected{Source: file.ForSandbox(name), ClientID: name + "-app"}))
	}
	if applications {
		for _, name := range []string{"review-agent", "study-group"} {
			require.NoError(t, selector.AddApplication(name,
				credential.Selected{Source: file.ForApplication(name), ClientID: name + "-app"}))
		}
	}
	h := start(t, harnessOptions{
		upstream: httpbinUpstream(), endpoints: credentialEndpoints,
		sandboxes: &proxy.SandboxIdentification{Header: assertionHeader, Verifier: verifier, Selector: selector},
	})
	return h, priv
}

// origin is the upstream's https origin as the workload addresses it.
func origin(h *harness) string {
	return "https://" + net.JoinHostPort(upstreamHost, strconv.Itoa(h.upstream.port))
}

// token signs an assertion for a sandbox under the review-agent
// application, valid now.
func token(t *testing.T, key *ecdsa.PrivateKey, sandbox string) string {
	t.Helper()
	return appToken(t, key, sandbox, "review-agent")
}

// appToken signs an assertion for a sandbox that names its application,
// valid now.
func appToken(t *testing.T, key *ecdsa.PrivateKey, sandbox, application string) string {
	t.Helper()
	return ownedToken(t, key, sandbox, application, "")
}

// ownedToken signs an assertion that also names the principal who created
// the sandbox. An empty owner leaves the claim out.
func ownedToken(t *testing.T, key *ecdsa.PrivateKey, sandbox, application, owner string) string {
	t.Helper()
	return ownerIDToken(t, key, sandbox, application, owner, "")
}

// ownerIDToken signs an assertion that names the owner and the Keycard user
// id the runtime resolved for them. An empty id leaves the claim out.
func ownerIDToken(t *testing.T, key *ecdsa.PrivateKey, sandbox, application, owner, ownerID string) string {
	t.Helper()
	claims := assertion.Claims{
		Issuer: "https://extension.greendale.example", Application: application,
		Sandbox: sandbox, Workspace: "default", SandboxUUID: "uuid-" + sandbox, ExecPath: "/usr/bin/curl",
		Owner: owner, OwnerID: ownerID,
	}
	signed, err := assertion.Sign(key, claims, []string{assertionAudience}, time.Now(), 30*time.Second)
	require.NoError(t, err)
	return signed
}

// TestSandboxIdentityRefusals pins the two refusals: no verifiable
// assertion, and a verified assertion for a sandbox the map does not name.
func TestSandboxIdentityRefusals(t *testing.T) {
	t.Parallel()
	h, priv := sandboxHarness(t, true)
	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	base := origin(h) + "/anything/header/"
	tests := map[string]struct {
		header          http.Header
		wantReason      policy.Reason
		wantSandbox     string
		wantUUID        string
		wantApplication string
	}{
		"no assertion": {
			header: http.Header{}, wantReason: policy.ReasonSandboxUnidentified, wantSandbox: "sbx-test",
		},
		"two assertions": {
			header: http.Header{assertionHeader: []string{
				token(t, priv, "keycard-demo"), token(t, priv, "keycard-demo"),
			}},
			wantReason: policy.ReasonSandboxUnidentified, wantSandbox: "sbx-test",
		},
		"a forged value": {
			header:     http.Header{assertionHeader: []string{"keycard-demo"}},
			wantReason: policy.ReasonSandboxUnidentified, wantSandbox: "sbx-test",
		},
		"another issuer's key": {
			header:     http.Header{assertionHeader: []string{token(t, otherPriv, "keycard-demo")}},
			wantReason: policy.ReasonSandboxUnidentified, wantSandbox: "sbx-test",
		},
		"a sub that names another application": {
			header:     http.Header{assertionHeader: []string{mixedToken(t, priv, "keycard-demo", "chang-agent")}},
			wantReason: policy.ReasonSandboxUnidentified, wantSandbox: "sbx-test",
		},
		// The app claim wins, so a mapped sandbox does not rescue an
		// unmapped application.
		"an unmapped application on a mapped sandbox": {
			header:     http.Header{assertionHeader: []string{appToken(t, priv, "keycard-demo", "chang-agent")}},
			wantReason: policy.ReasonApplicationUnknown, wantSandbox: "keycard-demo", wantUUID: "uuid-keycard-demo",
			wantApplication: "chang-agent",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			target := base + name
			answer := fetch(t, h, target, tc.header)
			assert.Equal(t, http.StatusForbidden, answer.status, "status")
			assert.Equal(t, tc.wantReason, answer.reason(), "reason")
			record := h.sink.find(t, name, byRequest(answer.id()))
			assert.Equal(t, tc.wantReason, record.Decision.Reason, "record reason")
			assert.Equal(t, tc.wantSandbox, record.SandboxID, "record sandbox")
			assert.Equal(t, tc.wantUUID, record.SandboxUUID, "record sandbox uuid")
			assert.Equal(t, tc.wantApplication, record.Application, "record application")
			assert.NotContains(t, record.Decision.Error, "eyJ", "a token in the record")
		})
	}
}

// TestApplicationIdentitySelectsTheCredential pins that the app claim
// selects the application's credential whatever the sandbox name, an
// unmapped sandbox included, and the record names sandbox, application and
// the owner the assertion carried, which is absent when it carried none.
func TestApplicationIdentitySelectsTheCredential(t *testing.T) {
	t.Parallel()
	h, priv := sandboxHarness(t, true)
	base := origin(h)
	tests := map[string]struct {
		sandbox           string
		application       string
		owner             string
		path              string
		wantAuthorization []string
	}{
		"the first application's credential": {
			sandbox: "keycard-demo", application: "review-agent", owner: "troy.barnes", path: "/anything/header/review",
			wantAuthorization: []string{"Bearer " + reviewSecret},
		},
		"the second application's credential": {
			sandbox: "troy-research", application: "study-group", path: "/anything/header/study",
			wantAuthorization: []string{"Bearer " + studySecret},
		},
		"a sandbox the map does not name, under a mapped application": {
			sandbox: "sandbox-7f3a", application: "review-agent", path: "/anything/header/fresh",
			wantAuthorization: []string{"Bearer " + reviewSecret},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			header := http.Header{
				"Authorization": []string{"Bearer placeholder"},
				assertionHeader: []string{ownedToken(t, priv, tc.sandbox, tc.application, tc.owner)},
			}
			answer := fetch(t, h, base+tc.path, header)
			require.Equal(t, http.StatusOK, answer.status, "status: %s", answer.body)
			var got arrived
			require.NoError(t, json.Unmarshal([]byte(answer.body), &got), "decode %s", answer.body)
			assert.Equal(t, tc.wantAuthorization, got.Headers.Values("Authorization"), "what the upstream saw")
			assert.Empty(t, got.Headers.Values(assertionHeader), "the assertion reached the upstream")

			record := h.sink.find(t, name, byPath(tc.path))
			assert.Equal(t, policy.VerdictAllow, record.Decision.Verdict)
			assert.Equal(t, tc.sandbox, record.SandboxID, "record sandbox")
			assert.Equal(t, "uuid-"+tc.sandbox, record.SandboxUUID, "record sandbox uuid")
			assert.Equal(t, tc.application, record.Application, "record application")
			assert.Equal(t, tc.owner, record.OnBehalfOf, "record on behalf of")
			require.NotNil(t, record.Identity, "record identity")
			assert.Equal(t, tc.application+"-app", record.Identity.ClientID)
		})
	}
}

// TestSandboxIdentitySelectsTheCredential pins that a document listing no
// applications selects by sandbox: each sandbox gets its own credential
// whatever application it claims, the assertion header never reaches the
// upstream, and the record names the sandbox, the application and the
// identity.
func TestSandboxIdentitySelectsTheCredential(t *testing.T) {
	t.Parallel()
	h, priv := sandboxHarness(t, false)
	base := origin(h)
	tests := map[string]struct {
		sandbox           string
		path              string
		sent              http.Header
		wantAuthorization []string
	}{
		"the first sandbox's credential": {
			sandbox: "keycard-demo", path: "/anything/header/demo",
			sent:              http.Header{"Authorization": []string{"Bearer placeholder"}},
			wantAuthorization: []string{"Bearer " + demoSecret},
		},
		"the second sandbox's credential": {
			sandbox: "troy-research", path: "/anything/header/research",
			wantAuthorization: []string{"Bearer " + researchSecret},
		},
		"an endpoint with no credential still strips the header": {
			sandbox: "keycard-demo", path: "/anything/plain/thing",
			sent:              http.Header{"Authorization": []string{"Bearer placeholder"}},
			wantAuthorization: []string{"Bearer placeholder"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			header := tc.sent.Clone()
			if header == nil {
				header = http.Header{}
			}
			header.Set(assertionHeader, token(t, priv, tc.sandbox))
			answer := fetch(t, h, base+tc.path, header)
			require.Equal(t, http.StatusOK, answer.status, "status: %s", answer.body)
			var got arrived
			require.NoError(t, json.Unmarshal([]byte(answer.body), &got), "decode %s", answer.body)
			assert.Equal(t, tc.wantAuthorization, got.Headers.Values("Authorization"), "what the upstream saw")
			assert.Empty(t, got.Headers.Values(assertionHeader), "the assertion reached the upstream")

			record := h.sink.find(t, name, byPath(tc.path))
			assert.Equal(t, audit.ScopeRequest, record.Scope)
			assert.Equal(t, policy.VerdictAllow, record.Decision.Verdict)
			assert.Equal(t, tc.sandbox, record.SandboxID, "record sandbox")
			assert.Equal(t, "uuid-"+tc.sandbox, record.SandboxUUID, "record sandbox uuid")
			assert.Equal(t, "review-agent", record.Application, "record application")
			require.NotNil(t, record.Identity, "record identity")
			assert.Equal(t, tc.sandbox+"-app", record.Identity.ClientID)
		})
	}
}

// TestSandboxOnlyDocumentRefusesAnUnmappedSandbox pins sandbox_unknown: a
// document listing no applications answers from the sandbox map alone, and
// a sandbox outside it is refused whatever application it claims.
func TestSandboxOnlyDocumentRefusesAnUnmappedSandbox(t *testing.T) {
	t.Parallel()
	h, priv := sandboxHarness(t, false)
	header := http.Header{assertionHeader: []string{token(t, priv, "pierce")}}
	answer := fetch(t, h, origin(h)+"/anything/header/pierce", header)
	assert.Equal(t, http.StatusForbidden, answer.status, "status")
	assert.Equal(t, policy.ReasonSandboxUnknown, answer.reason(), "reason")
	record := h.sink.find(t, "pierce", byRequest(answer.id()))
	assert.Equal(t, policy.ReasonSandboxUnknown, record.Decision.Reason, "record reason")
	assert.Equal(t, "pierce", record.SandboxID, "record sandbox")
	assert.Equal(t, "uuid-pierce", record.SandboxUUID, "record sandbox uuid")
	assert.Equal(t, "review-agent", record.Application, "record application")
}

// mixedToken signs a token whose sub names another application than its
// app claim. Sign builds no such token, so the test writes the claims
// itself.
func mixedToken(t *testing.T, key *ecdsa.PrivateKey, sandbox, subjectApplication string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	require.NoError(t, err)
	signed, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: "https://extension.greendale.example", Subject: assertion.Subject(subjectApplication, "uuid-"+sandbox),
		Audience: jwt.Audience{assertionAudience}, ID: "jti-troy",
		IssuedAt: jwt.NewNumericDate(time.Now()), Expiry: jwt.NewNumericDate(time.Now().Add(30 * time.Second)),
	}).Claims(map[string]any{
		"app": "review-agent", "sandbox": sandbox, "sandbox_id": "uuid-" + sandbox,
	}).Serialize()
	require.NoError(t, err)
	return signed
}

// TestSandboxIdentityAttributesAPolicyRefusal pins that a request the
// endpoint list refuses is still attributed to its sandbox, so the audit
// stream answers which sandbox probed a forbidden path.
func TestSandboxIdentityAttributesAPolicyRefusal(t *testing.T) {
	t.Parallel()
	h, priv := sandboxHarness(t, true)
	header := http.Header{assertionHeader: []string{token(t, priv, "troy-research")}}
	answer := fetch(t, h, origin(h)+"/anything/unlisted/path", header)
	require.Equal(t, http.StatusForbidden, answer.status)
	assert.Equal(t, policy.ReasonNoMatchingEndpoint, answer.reason())
	record := h.sink.find(t, "refusal", byRequest(answer.id()))
	assert.Equal(t, "troy-research", record.SandboxID, "the refusal names the sandbox")
	assert.Equal(t, "uuid-troy-research", record.SandboxUUID)
}

// TestSandboxIdentityLeavesConnectionRecordsAlone pins that the
// connection-scoped record keeps the process sandbox, because a CONNECT
// carries no header to identify one.
func TestSandboxIdentityLeavesConnectionRecordsAlone(t *testing.T) {
	t.Parallel()
	h, priv := sandboxHarness(t, true)
	header := http.Header{assertionHeader: []string{token(t, priv, "keycard-demo")}}
	answer := fetch(t, h, origin(h)+"/anything/header/conn", header)
	require.Equal(t, http.StatusOK, answer.status)
	request := h.sink.find(t, "request", byPath("/anything/header/conn"))
	connection := h.sink.find(t, "connection", byConnection(request.ConnectionID, policy.ReasonEndpointAllowed))
	assert.Equal(t, "sbx-test", connection.SandboxID)
	assert.Empty(t, connection.SandboxUUID)
	assert.Nil(t, connection.Identity)
}

// TestOwnerImpersonationNamesTheUser pins the record of an identity that
// exchanges for the sandbox owner: identity.user is the assertion's
// owner_id beside the subject as identity.client_id, and on_behalf_of stays
// the owner as the runtime named them. A source that acts as the sandbox
// alone records no user, whatever the assertion carries.
func TestOwnerImpersonationNamesTheUser(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pemBytes, err := assertion.MarshalPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	verifier, err := assertion.NewVerifier(pemBytes, assertionAudience, 30*time.Second)
	require.NoError(t, err)
	selector := credential.NewSelector()
	require.NoError(t, selector.AddApplication("review-agent", credential.Selected{
		Source: fixedSource{reviewSecret}, SubjectIsClient: true, ImpersonatesOwner: true,
	}))
	require.NoError(t, selector.AddApplication("study-group", credential.Selected{
		Source: fixedSource{studySecret}, SubjectIsClient: true,
	}))
	h := start(t, harnessOptions{
		upstream: httpbinUpstream(), endpoints: credentialEndpoints,
		sandboxes: &proxy.SandboxIdentification{Header: assertionHeader, Verifier: verifier, Selector: selector},
	})
	tests := map[string]struct {
		application string
		ownerID     string
		path        string
		wantUser    string
	}{
		"the owner is impersonated": {
			application: "review-agent", ownerID: "igmua2g0fwapl21qll7tczdw7t", path: "/anything/header/owner",
			wantUser: "igmua2g0fwapl21qll7tczdw7t",
		},
		"the sandbox acts as itself": {
			application: "study-group", ownerID: "igmua2g0fwapl21qll7tczdw7t", path: "/anything/header/sandbox",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			header := http.Header{assertionHeader: []string{
				ownerIDToken(t, priv, "keycard-demo", tc.application, "troy.barnes", tc.ownerID),
			}}
			answer := fetch(t, h, origin(h)+tc.path, header)
			require.Equal(t, http.StatusOK, answer.status, "status: %s", answer.body)

			record := h.sink.find(t, name, byPath(tc.path))
			assert.Equal(t, "troy.barnes", record.OnBehalfOf, "record on behalf of")
			require.NotNil(t, record.Identity, "record identity")
			assert.Equal(t, "openshell:"+tc.application+":uuid-keycard-demo", record.Identity.ClientID)
			assert.Equal(t, tc.wantUser, record.Identity.User, "record identity user")
		})
	}
}

// fixedSource answers one credential for every resource.
type fixedSource struct{ value string }

func (s fixedSource) Credential(context.Context, string) (string, error) { return s.value, nil }

func (fixedSource) Describe() string { return "one credential for every resource" }
