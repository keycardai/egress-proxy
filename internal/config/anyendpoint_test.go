package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/config"
	"github.com/keycardai/egress-proxy/internal/credential"
)

// noEndpoints is a document with nothing reachable, for any_endpoint to
// stand in for the list.
const noEndpoints = "version: 1\nsandbox:\n  id: sbx-1\n"

// bearerAnyEndpoint puts a bearer token into Authorization on every request.
const bearerAnyEndpoint = "any_endpoint:\n  credential:\n" +
	"    placement: {kind: header, name: Authorization, template: \"Bearer {credential}\"}\n"

// everyApplicationDoc is one identity for every application: the assertion
// exchange on the top-level identity, which needs sandbox_assertion.
const everyApplicationDoc = assertionDoc + "identity:\n  zone_url: https://z\n  client_assertion: sandbox\n"

func TestParseAnyEndpoint(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		doc           string
		wantPlacement *credential.Placement
	}{
		"with a credential": {
			doc: noEndpoints + bearerAnyEndpoint,
			wantPlacement: &credential.Placement{
				Kind: credential.KindHeader, Name: "Authorization", Template: "Bearer {credential}",
			},
		},
		"without a credential": {doc: noEndpoints + "any_endpoint: {}\n"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Parse([]byte(tc.doc), config.Overrides{})
			require.NoError(t, err, "Parse")
			require.NotNil(t, cfg.AnyEndpoint, "any_endpoint is set")
			assert.Empty(t, cfg.Endpoints, "no endpoint list")
			assert.Equal(t, tc.wantPlacement, cfg.AnyEndpointPlacement(), "the placement")
		})
	}
	cfg, err := config.Parse([]byte(minimal), config.Overrides{})
	require.NoError(t, err, "Parse")
	assert.Nil(t, cfg.AnyEndpointPlacement(), "no any_endpoint, no placement")
}

func TestParseRefusesInvalidAnyEndpoint(t *testing.T) {
	t.Parallel()
	runParseRefusals(t, []parseRefusal{
		{
			name:    "beside an endpoint list",
			doc:     minimal + bearerAnyEndpoint,
			wantErr: "any_endpoint and endpoints both say what the sandbox can reach; configure one",
		},
		{
			name:    "beside the allowlist resolver",
			doc:     noEndpoints + bearerAnyEndpoint + "listen:\n  dns_port: 53\n",
			wantErr: "any_endpoint cannot be set with listen.dns_port",
		},
		{
			name:    "a placement kind this build does not write",
			doc:     noEndpoints + "any_endpoint:\n  credential:\n    placement: {kind: cookie, name: session}\n",
			wantErr: `any_endpoint: placement.kind "cookie" must be header, query or basic`,
		},
		{
			name: "a header placement with no token in its template",
			doc: noEndpoints + "any_endpoint:\n  credential:\n" +
				"    placement: {kind: header, name: Authorization, template: Bearer}\n",
			wantErr: "any_endpoint: a header placement template must contain {credential}",
		},
		{
			name: "a header placement naming Host",
			doc: noEndpoints + "any_endpoint:\n  credential:\n" +
				"    placement: {kind: header, name: Host, template: \"{credential}\"}\n",
			wantErr: "any_endpoint: a header placement cannot name Host",
		},
	})
}

// TestConfigDigestCoversAnyEndpoint pins that the switch and its placement
// are in the config digest: two proxies that differ in either answer a
// request differently.
func TestConfigDigestCoversAnyEndpoint(t *testing.T) {
	t.Parallel()
	digestOf := func(t *testing.T, doc string) string {
		t.Helper()
		cfg, err := config.Parse([]byte(doc), config.Overrides{})
		require.NoError(t, err, "Parse:\n%s", doc)
		return cfg.ConfigDigest
	}
	base := digestOf(t, noEndpoints+bearerAnyEndpoint)
	tests := map[string]struct {
		doc      string
		wantSame bool
	}{
		"the same document": {doc: noEndpoints + bearerAnyEndpoint, wantSame: true},
		"no credential":     {doc: noEndpoints + "any_endpoint: {}\n"},
		"another placement": {
			doc: noEndpoints + "any_endpoint:\n  credential:\n    placement: {kind: query, name: key}\n",
		},
		"an endpoint list instead":  {doc: minimal},
		"nothing reachable instead": {doc: noEndpoints},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := digestOf(t, tc.doc)
			if tc.wantSame {
				assert.Equal(t, base, got, "the digest")
			} else {
				assert.NotEqual(t, base, got, "the digest")
			}
		})
	}
}

// TestParseIdentityForEveryApplication pins the top-level identity that
// exchanges as the asserted sandbox for every application: accepted with
// sandbox_assertion and no entry, with the owner impersonation beside it,
// and refused without sandbox_assertion.
func TestParseIdentityForEveryApplication(t *testing.T) {
	t.Parallel()
	cfg, err := config.Parse([]byte(minimal+everyApplicationDoc), config.Overrides{})
	require.NoError(t, err, "Parse")
	r := require.New(t)
	r.NotNil(cfg.Identity)
	assert.Equal(t, config.ClientAssertionSandbox, cfg.Identity.ClientAssertion)
	assert.Equal(t, config.SourceExchange, cfg.CredentialSource(), "the assertion exchange is an exchange")
	assert.Empty(t, cfg.Applications, "no entry per application")

	owner, err := config.Parse(
		[]byte(minimal+everyApplicationDoc+"  impersonate: {sandbox_owner: true}\n"),
		config.Overrides{},
	)
	require.NoError(t, err, "Parse the owner document")
	assert.True(t, owner.Identity.Impersonate.SandboxOwner, "the owner is impersonated")

	runParseRefusals(t, []parseRefusal{
		{
			name:    "without sandbox_assertion",
			doc:     minimal + "identity:\n  zone_url: https://z\n  client_assertion: sandbox\n",
			wantErr: "identity.client_assertion needs a per-request sandbox assertion; set sandbox_assertion",
		},
		{
			name: "a top-level identity that is not the assertion exchange, with no entry",
			doc: minimal + assertionDoc + "identity:\n  zone_url: https://z\n  client_id: c\n" +
				"  client_secret_file: /s\n  impersonate: {user: troy}\n",
			wantErr: "sandbox_assertion requires at least one entry in sandboxes or applications, " +
				"or an identity with client_assertion: sandbox",
		},
		{
			name: "beside an application entry",
			doc: minimal + everyApplicationDoc + "applications:\n  - name: review-agent\n    identity:\n" +
				"      zone_url: https://z\n      client_assertion: sandbox\n",
			wantErr: "identity and applications both name a credential source; configure one",
		},
	})
}

// TestConfigDigestCoversTheIdentityForEveryApplication pins that one
// identity for every application and one per application digest apart.
func TestConfigDigestCoversTheIdentityForEveryApplication(t *testing.T) {
	t.Parallel()
	every, err := config.Parse([]byte(minimal+everyApplicationDoc), config.Overrides{})
	require.NoError(t, err, "Parse")
	perApplication, err := config.Parse([]byte(minimal+assertionDoc+
		"applications:\n  - name: review-agent\n    identity:\n      zone_url: https://z\n      client_assertion: sandbox\n"),
		config.Overrides{})
	require.NoError(t, err, "Parse")
	assert.NotEqual(t, every.ConfigDigest, perApplication.ConfigDigest, "the digest")
}
