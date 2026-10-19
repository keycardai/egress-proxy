package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/config"
)

// assertionDoc turns the sandbox assertion on with every default.
const assertionDoc = "sandbox_assertion:\n  issuer_key_file: /etc/keycard/middleware.pub\n"

// twoSandboxesDoc maps two sandboxes to two client-secret identities.
const twoSandboxesDoc = "sandboxes:\n" +
	"  - name: keycard-demo\n    identity:\n      zone_url: https://z\n      client_id: demo\n" +
	"      client_secret_file: /s/demo\n      impersonate: {user: troy}\n" +
	"  - name: troy-research\n    workspace: study-group\n    identity:\n      zone_url: https://z\n" +
	"      client_id: research\n      client_secret_file: /s/research\n      impersonate: {user: abed}\n"

func TestParseSandboxIdentityAppliesDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := config.Parse([]byte(minimal+assertionDoc+twoSandboxesDoc), config.Overrides{})
	require.NoError(t, err, "Parse")
	r := require.New(t)
	r.NotNil(cfg.SandboxAssertion, "sandbox_assertion is set")
	assert.Equal(t, "X-Keycard-Sandbox-Assertion", cfg.SandboxAssertion.Header, "the default header")
	assert.Equal(t, "keycard-egress-proxy", cfg.SandboxAssertion.Audience, "the default audience")
	assert.Equal(t, 30*time.Second, cfg.SandboxAssertion.MaxAge.Duration(), "the default max_age")
	r.Len(cfg.Sandboxes, 2)
	assert.Equal(t, "default", cfg.Sandboxes[0].Workspace, "the default workspace")
	assert.Equal(t, "study-group", cfg.Sandboxes[1].Workspace, "a named workspace")
	assert.Equal(t, config.SourceExchange, cfg.CredentialSource(), "per-sandbox identities are an exchange")
	assert.Equal(t, "research", cfg.Sandboxes[1].Identity.ClientID)
}

// twoApplicationsDoc maps two applications to two client-secret identities.
const twoApplicationsDoc = "applications:\n" +
	"  - name: review-agent\n    identity:\n      zone_url: https://z\n      client_id: review\n" +
	"      client_secret_file: /s/review\n      impersonate: {user: troy}\n" +
	"  - name: research-agent\n    identity:\n      zone_url: https://z\n" +
	"      client_id: research\n      client_secret_file: /s/research\n      impersonate: {user: abed}\n"

// TestParseApplications pins that applications select an exchange identity
// like sandboxes do, alone or beside them.
func TestParseApplications(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		doc              string
		wantSource       config.CredentialSourceKind
		wantApplications int
		wantSandboxes    int
		wantCreators     []string
	}{
		"applications alone": {
			doc: minimal + assertionDoc + twoApplicationsDoc, wantSource: config.SourceExchange, wantApplications: 2,
		},
		"applications beside sandboxes": {
			doc:        minimal + assertionDoc + twoApplicationsDoc + twoSandboxesDoc,
			wantSource: config.SourceExchange, wantApplications: 2, wantSandboxes: 2,
		},
		"applications with a static source name no identity": {
			doc: minimal + assertionDoc + "credentials:\n  static_file: /creds.yaml\n" +
				"applications:\n  - name: review-agent\n",
			wantSource: config.SourceStaticFile, wantApplications: 1,
		},
		"creators are accepted and kept": {
			doc: minimal + assertionDoc + "credentials:\n  static_file: /creds.yaml\n" +
				"applications:\n  - name: review-agent\n    creators: [troy, abed]\n",
			wantSource: config.SourceStaticFile, wantApplications: 1,
			wantCreators: []string{"troy", "abed"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Parse([]byte(tc.doc), config.Overrides{})
			require.NoError(t, err, "Parse")
			assert.Equal(t, tc.wantSource, cfg.CredentialSource())
			assert.Len(t, cfg.Applications, tc.wantApplications)
			assert.Len(t, cfg.Sandboxes, tc.wantSandboxes)
			assert.Equal(t, "review-agent", cfg.Applications[0].Name)
			assert.Equal(t, tc.wantCreators, cfg.Applications[0].Creators, "creators as written")
		})
	}
}

func TestParseRefusesInvalidApplications(t *testing.T) {
	t.Parallel()
	runParseRefusals(t, []parseRefusal{
		{
			name:    "applications without the assertion",
			doc:     minimal + twoApplicationsDoc,
			wantErr: "applications requires sandbox_assertion",
		},
		{
			name: "a repeated name",
			doc: minimal + assertionDoc + "credentials:\n  static_file: /c\n" +
				"applications:\n  - name: review-agent\n  - name: review-agent\n",
			wantErr: `applications[1]: name "review-agent" repeats applications[0]`,
		},
		{
			name: "an empty creator",
			doc: minimal + assertionDoc + "credentials:\n  static_file: /c\n" +
				"applications:\n  - name: review-agent\n    creators: [troy, \" \"]\n",
			wantErr: "applications[0].creators[1]: a creator must be a non-empty string",
		},
		{
			name: "a repeated creator",
			doc: minimal + assertionDoc + "credentials:\n  static_file: /c\n" +
				"applications:\n  - name: review-agent\n    creators: [troy, abed, troy]\n",
			wantErr: `applications[0].creators[2]: "troy" repeats creators[0]`,
		},
		{
			name:    "an empty name",
			doc:     minimal + assertionDoc + "credentials:\n  static_file: /c\napplications:\n  - identity:\n",
			wantErr: "applications[0]: name must be a non-empty string without whitespace",
		},
		{
			name: "an identity beside a static file",
			doc: minimal + assertionDoc + "credentials:\n  static_file: /c\n" +
				"applications:\n  - name: review-agent\n    identity:\n      zone_url: https://z\n" +
				"      client_id: review\n      client_secret_file: /s\n      impersonate: {user: troy}\n",
			wantErr: "applications[0].identity and credentials.static_file both name a credential source",
		},
		{
			name: "an invalid identity",
			doc: minimal + assertionDoc + "applications:\n  - name: review-agent\n    identity:\n" +
				"      zone_url: https://z\n      client_id: review\n      impersonate: {user: troy}\n",
			wantErr: "applications[0].identity names no client authentication",
		},
		{
			name: "no identity and no static file",
			doc:  minimal + assertionDoc + "applications:\n  - name: review-agent\n",
			wantErr: "applications[0] names no identity and credentials.static_file is unset; " +
				"the application has no credential source",
		},
		{
			name:    "a top-level identity beside applications",
			doc:     minimal + identityDoc + assertionDoc + twoApplicationsDoc,
			wantErr: "identity and applications both name a credential source; configure one",
		},
	})
}

func TestParseSandboxesWithAStaticSourceNameNoIdentity(t *testing.T) {
	t.Parallel()
	doc := minimal + assertionDoc + "credentials:\n  static_file: /creds.yaml\n" +
		"sandboxes:\n  - name: keycard-demo\n  - name: troy-research\n"
	cfg, err := config.Parse([]byte(doc), config.Overrides{})
	require.NoError(t, err, "Parse")
	assert.Equal(t, config.SourceStaticFile, cfg.CredentialSource())
	assert.Nil(t, cfg.Sandboxes[0].Identity)
}

func TestParseConnectAuthFile(t *testing.T) {
	t.Parallel()
	cfg, err := config.Parse([]byte(minimal), config.Overrides{ConnectAuthFile: "/run/secrets/connect-auth"})
	require.NoError(t, err, "Parse")
	assert.Equal(t, "/run/secrets/connect-auth", cfg.Listen.ConnectAuthFile)
	assert.Contains(t, cfg.Overridden, "listen.connect_auth_file")
}

func TestParseRefusesInvalidSandboxIdentity(t *testing.T) {
	t.Parallel()
	runParseRefusals(t, []parseRefusal{
		{
			name:    "sandboxes without the assertion",
			doc:     minimal + twoSandboxesDoc,
			wantErr: "sandboxes requires sandbox_assertion",
		},
		{
			name:    "the assertion without sandboxes",
			doc:     minimal + assertionDoc,
			wantErr: "sandbox_assertion requires at least one entry in sandboxes",
		},
		{
			name: "a repeated name and workspace",
			doc: minimal + assertionDoc + "credentials:\n  static_file: /c\n" +
				"sandboxes:\n  - name: keycard-demo\n  - name: keycard-demo\n    workspace: default\n",
			wantErr: `sandboxes[1]: name "keycard-demo" in workspace "default" repeats sandboxes[0]`,
		},
		{
			name:    "an empty name",
			doc:     minimal + assertionDoc + "credentials:\n  static_file: /c\nsandboxes:\n  - workspace: default\n",
			wantErr: "sandboxes[0]: name must be a non-empty string without whitespace",
		},
		{
			name: "an identity with both client authentication mechanisms",
			doc: minimal + assertionDoc + "sandboxes:\n  - name: keycard-demo\n    identity:\n" +
				"      zone_url: https://z\n      client_id: demo\n      client_secret_file: /s\n" +
				"      workload_token_file: /t\n      impersonate: {user: troy}\n",
			wantErr: "sandboxes[0].identity.workload_token_file and sandboxes[0].identity.client_secret_file both",
		},
		{
			name: "an identity beside a static file",
			doc: minimal + assertionDoc + "credentials:\n  static_file: /c\n" +
				"sandboxes:\n  - name: keycard-demo\n    identity:\n      zone_url: https://z\n" +
				"      client_id: demo\n      client_secret_file: /s\n      impersonate: {user: troy}\n",
			wantErr: "sandboxes[0].identity and credentials.static_file both name a credential source",
		},
		{
			name:    "no identity and no static file",
			doc:     minimal + assertionDoc + "sandboxes:\n  - name: keycard-demo\n",
			wantErr: "sandboxes[0] names no identity and credentials.static_file is unset",
		},
		{
			name:    "a top-level identity beside sandboxes",
			doc:     minimal + identityDoc + assertionDoc + twoSandboxesDoc,
			wantErr: "identity and sandboxes both name a credential source; configure one",
		},
		{
			name:    "a relative key file",
			doc:     minimal + "sandbox_assertion:\n  issuer_key_file: middleware.pub\n" + twoSandboxesDoc,
			wantErr: `sandbox_assertion.issuer_key_file "middleware.pub" must be an absolute path`,
		},
		{
			name:    "no key file",
			doc:     minimal + "sandbox_assertion:\n  audience: a\n" + twoSandboxesDoc,
			wantErr: "sandbox_assertion.issuer_key_file is empty",
		},
		{
			name: "a max_age above five minutes",
			doc: minimal + "sandbox_assertion:\n  issuer_key_file: /k\n  max_age: 10m\n" +
				twoSandboxesDoc,
			wantErr: "sandbox_assertion.max_age 10m0s must be between 1s and 5m0s",
		},
		{
			name:    "a header name that is not a token",
			doc:     minimal + "sandbox_assertion:\n  issuer_key_file: /k\n  header: \"X Keycard\"\n" + twoSandboxesDoc,
			wantErr: `sandbox_assertion.header "X Keycard" is not a header name`,
		},
		{
			name:    "a relative connect auth file",
			doc:     minimal + "listen:\n  connect_auth_file: connect-auth\n",
			wantErr: `listen.connect_auth_file "connect-auth" must be an absolute path`,
		},
		{
			// A redirected connection carries no Proxy-Authorization, so the
			// credential would guard one frontend and not the other.
			name:    "a connect auth file with a transparent frontend",
			doc:     minimal + "listen:\n  connect_auth_file: /run/secrets/connect-auth\n  transparent_port: 1015\n",
			wantErr: "listen.connect_auth_file cannot be set with listen.transparent_port",
		},
	})
}

// workloadDoc maps two applications to the sandbox assertion itself: the
// proxy exchanges as the asserted sandbox and holds no credential per
// application.
const workloadDoc = "applications:\n" +
	"  - name: review-agent\n    identity:\n      zone_url: https://z\n      client_assertion: sandbox\n" +
	"  - name: research-agent\n    identity:\n      zone_url: https://z\n      client_assertion: sandbox\n"

// TestParseClientAssertion pins the workload identity shape: an application
// identity made of a zone and client_assertion: sandbox alone, and an
// optional issuer the assertion must name.
func TestParseClientAssertion(t *testing.T) {
	t.Parallel()
	doc := minimal + "sandbox_assertion:\n  issuer_key_file: /etc/keycard/extension.pub\n" +
		"  issuer: https://extension.greendale.example\n" + workloadDoc
	cfg, err := config.Parse([]byte(doc), config.Overrides{})
	require.NoError(t, err, "Parse")
	r := require.New(t)
	r.NotNil(cfg.SandboxAssertion)
	assert.Equal(t, "https://extension.greendale.example", cfg.SandboxAssertion.Issuer)
	r.Len(cfg.Applications, 2)
	assert.Equal(t, config.ClientAssertionSandbox, cfg.Applications[0].Identity.ClientAssertion)
	assert.Empty(t, cfg.Applications[0].Identity.ClientID)
	assert.Equal(t, config.SourceExchange, cfg.CredentialSource(), "the assertion exchange is an exchange")
}

func TestParseRefusesInvalidClientAssertion(t *testing.T) {
	t.Parallel()
	runParseRefusals(t, []parseRefusal{
		{
			name: "a value other than sandbox",
			doc: minimal + assertionDoc + "applications:\n  - name: review-agent\n    identity:\n" +
				"      zone_url: https://z\n      client_assertion: chang\n",
			wantErr: `applications[0].identity.client_assertion "chang" is not "sandbox"`,
		},
		{
			name: "a client id beside the assertion",
			doc: minimal + assertionDoc + "applications:\n  - name: review-agent\n    identity:\n" +
				"      zone_url: https://z\n      client_assertion: sandbox\n      client_id: review\n",
			wantErr: "applications[0].identity.client_id cannot be set with client_assertion",
		},
		{
			name: "a client secret file beside the assertion",
			doc: minimal + assertionDoc + "applications:\n  - name: review-agent\n    identity:\n" +
				"      zone_url: https://z\n      client_assertion: sandbox\n      client_secret_file: /s\n",
			wantErr: "applications[0].identity.client_secret_file cannot be set with client_assertion",
		},
		{
			name: "a workload token file beside the assertion",
			doc: minimal + assertionDoc + "applications:\n  - name: review-agent\n    identity:\n" +
				"      zone_url: https://z\n      client_assertion: sandbox\n      workload_token_file: /t\n",
			wantErr: "applications[0].identity.workload_token_file cannot be set with client_assertion",
		},
		{
			name: "an impersonated user beside the assertion",
			doc: minimal + assertionDoc + "applications:\n  - name: review-agent\n    identity:\n" +
				"      zone_url: https://z\n      client_assertion: sandbox\n      impersonate: {user: troy}\n",
			wantErr: "applications[0].identity.impersonate.user cannot be set with client_assertion",
		},
		{
			name: "no zone beside the assertion",
			doc: minimal + assertionDoc + "applications:\n  - name: review-agent\n    identity:\n" +
				"      client_assertion: sandbox\n",
			wantErr: `applications[0].identity.zone_url "" must be an absolute https URL`,
		},
		{
			name:    "the assertion on the top-level identity",
			doc:     minimal + "identity:\n  zone_url: https://z\n  client_assertion: sandbox\n",
			wantErr: "identity.client_assertion needs a per-request sandbox assertion; use it under applications",
		},
		{
			name: "an issuer that is not a URL",
			doc: minimal + "sandbox_assertion:\n  issuer_key_file: /k\n  issuer: greendale\n" +
				workloadDoc,
			wantErr: `sandbox_assertion.issuer "greendale" must be an absolute URL`,
		},
	})
}

// TestConfigDigestCoversClientAssertion pins that the mechanism and the
// pinned issuer are in the config digest.
func TestConfigDigestCoversClientAssertion(t *testing.T) {
	t.Parallel()
	digestOf := func(t *testing.T, doc string) string {
		t.Helper()
		cfg, err := config.Parse([]byte(doc), config.Overrides{})
		require.NoError(t, err, "Parse:\n%s", doc)
		return cfg.ConfigDigest
	}
	base := digestOf(t, minimal+assertionDoc+workloadDoc)
	tests := map[string]struct {
		doc      string
		wantSame bool
	}{
		"the same document": {doc: minimal + assertionDoc + workloadDoc, wantSame: true},
		"a client secret in place of the assertion": {
			doc: minimal + assertionDoc + "applications:\n" +
				"  - name: review-agent\n    identity:\n      zone_url: https://z\n      client_id: review\n" +
				"      client_secret_file: /s/review\n      impersonate: {user: troy}\n" +
				"  - name: research-agent\n    identity:\n      zone_url: https://z\n      client_assertion: sandbox\n",
			wantSame: false,
		},
		"a pinned issuer": {
			doc: minimal + "sandbox_assertion:\n  issuer_key_file: /etc/keycard/middleware.pub\n" +
				"  issuer: https://extension.greendale.example\n" + workloadDoc,
			wantSame: false,
		},
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

func TestConfigDigestCoversSandboxIdentity(t *testing.T) {
	t.Parallel()
	digestOf := func(t *testing.T, doc string, overrides config.Overrides) string {
		t.Helper()
		cfg, err := config.Parse([]byte(doc), overrides)
		require.NoError(t, err, "Parse:\n%s", doc)
		return cfg.ConfigDigest
	}
	base := digestOf(t, minimal+assertionDoc+twoSandboxesDoc, config.Overrides{})
	tests := map[string]struct {
		doc       string
		overrides config.Overrides
		wantSame  bool
	}{
		"the same document": {doc: minimal + assertionDoc + twoSandboxesDoc, wantSame: true},
		"sandboxes in another order": {
			doc: minimal + assertionDoc + "sandboxes:\n" +
				"  - name: troy-research\n    workspace: study-group\n    identity:\n      zone_url: https://z\n" +
				"      client_id: research\n      client_secret_file: /s/research\n      impersonate: {user: abed}\n" +
				"  - name: keycard-demo\n    identity:\n      zone_url: https://z\n      client_id: demo\n" +
				"      client_secret_file: /s/demo\n      impersonate: {user: troy}\n",
			wantSame: true,
		},
		"another audience": {
			doc: minimal + "sandbox_assertion:\n  issuer_key_file: /etc/keycard/middleware.pub\n" +
				"  audience: other\n" + twoSandboxesDoc,
			wantSame: false,
		},
		"another key file": {
			doc:      minimal + "sandbox_assertion:\n  issuer_key_file: /other.pub\n" + twoSandboxesDoc,
			wantSame: false,
		},
		"another user for one sandbox": {
			doc: minimal + assertionDoc + "sandboxes:\n" +
				"  - name: keycard-demo\n    identity:\n      zone_url: https://z\n      client_id: demo\n" +
				"      client_secret_file: /s/demo\n      impersonate: {user: pierce}\n" +
				"  - name: troy-research\n    workspace: study-group\n    identity:\n      zone_url: https://z\n" +
				"      client_id: research\n      client_secret_file: /s/research\n      impersonate: {user: abed}\n",
			wantSame: false,
		},
		"a connect auth file": {
			doc:       minimal + assertionDoc + twoSandboxesDoc,
			overrides: config.Overrides{ConnectAuthFile: "/run/secrets/connect-auth"},
			wantSame:  false,
		},
		"an application added": {
			doc:      minimal + assertionDoc + twoSandboxesDoc + twoApplicationsDoc,
			wantSame: false,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := digestOf(t, tc.doc, tc.overrides)
			if tc.wantSame {
				assert.Equal(t, base, got, "the digest")
			} else {
				assert.NotEqual(t, base, got, "the digest")
			}
		})
	}
}

// TestConfigDigestCoversApplications pins that the application map is in the
// config digest in a canonical order, so two proxies with different maps
// never share one and document order changes nothing.
func TestConfigDigestCoversApplications(t *testing.T) {
	t.Parallel()
	digestOf := func(t *testing.T, doc string) string {
		t.Helper()
		cfg, err := config.Parse([]byte(doc), config.Overrides{})
		require.NoError(t, err, "Parse:\n%s", doc)
		return cfg.ConfigDigest
	}
	base := digestOf(t, minimal+assertionDoc+twoApplicationsDoc)
	tests := map[string]struct {
		doc      string
		wantSame bool
	}{
		"the same document": {doc: minimal + assertionDoc + twoApplicationsDoc, wantSame: true},
		"applications in another order": {
			doc: minimal + assertionDoc + "applications:\n" +
				"  - name: research-agent\n    identity:\n      zone_url: https://z\n" +
				"      client_id: research\n      client_secret_file: /s/research\n      impersonate: {user: abed}\n" +
				"  - name: review-agent\n    identity:\n      zone_url: https://z\n      client_id: review\n" +
				"      client_secret_file: /s/review\n      impersonate: {user: troy}\n",
			wantSame: true,
		},
		"another user for one application": {
			doc: minimal + assertionDoc + "applications:\n" +
				"  - name: review-agent\n    identity:\n      zone_url: https://z\n      client_id: review\n" +
				"      client_secret_file: /s/review\n      impersonate: {user: pierce}\n" +
				"  - name: research-agent\n    identity:\n      zone_url: https://z\n" +
				"      client_id: research\n      client_secret_file: /s/research\n      impersonate: {user: abed}\n",
			wantSame: false,
		},
		"a sandbox added": {
			doc:      minimal + assertionDoc + twoApplicationsDoc + twoSandboxesDoc,
			wantSame: false,
		},
		// creators decides who may create a sandbox, which the sandbox
		// runtime enforces. The proxy answers every request the same with
		// or without the list, so it stays out of the digest.
		"creators added to one application": {
			doc: minimal + assertionDoc + "applications:\n" +
				"  - name: review-agent\n    creators: [troy, abed]\n    identity:\n" +
				"      zone_url: https://z\n      client_id: review\n" +
				"      client_secret_file: /s/review\n      impersonate: {user: troy}\n" +
				"  - name: research-agent\n    identity:\n      zone_url: https://z\n" +
				"      client_id: research\n      client_secret_file: /s/research\n      impersonate: {user: abed}\n",
			wantSame: true,
		},
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
