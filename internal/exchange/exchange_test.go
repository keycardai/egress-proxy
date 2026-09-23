package exchange_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/exchange"
	"github.com/keycardai/egress-proxy/test/fakeas"
)

// The identity used by the fixture.
const (
	user         = "igmua2g0fwapl21qll7tczdw7t"
	clientID     = "app-cred-1"
	clientSecret = "s3cr3t-from-the-zone"
	resource     = "https://api.github.com/"
	granted      = "gho_the_upstream_credential"
)

// zone starts a fake authorization server and returns the server and its URL.
func zone(t *testing.T, opts fakeas.Options) (*fakeas.Server, string) {
	t.Helper()
	if opts.Credentials == nil {
		opts.Credentials = map[string]string{resource: granted}
	}
	server := fakeas.New(opts)
	httpServer := httptest.NewServer(server)
	t.Cleanup(httpServer.Close)
	return server, httpServer.URL
}

// TestTheWireForm checks each exchange parameter. The zone reads these names,
// so they define the contract with it.
func TestTheWireForm(t *testing.T) {
	t.Parallel()
	server, zoneURL := zone(t, fakeas.Options{ClientSecrets: map[string]string{clientID: clientSecret}})
	source, err := exchange.New(exchange.Options{
		ZoneURL: zoneURL, ClientID: clientID, ImpersonateUser: user, ClientSecret: clientSecret,
	})
	require.NoError(t, err, "New")

	value, err := source.Credential(t.Context(), resource)
	require.NoError(t, err, "Credential")
	assert.Equal(t, granted, value, "the credential the zone issued")

	requests := server.Requests()
	require.Len(t, requests, 1, "one exchange per call")
	form := requests[0].Form

	//nolint:gosec // G101: protocol URNs, not credentials
	wantForm := map[string]string{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      substituteUser(t, user),
		"subject_token_type": "urn:keycard:params:oauth:token-type:substitute-user",
		"resource":           resource,
	}
	for key, want := range wantForm {
		assert.Equal(t, want, form.Get(key), "form parameter %s", key)
	}
	// The secret uses the Authorization header. It reaches no form parameter or
	// request log.
	for _, key := range []string{"client_secret", "client_id", "actor_token", "actor_token_type", "scope", "audience"} {
		assert.NotContains(t, form, key, "the form must not carry %s", key)
	}
	assert.Len(t, form, len(wantForm), "the form carries exactly the parameters pinned above")
	assert.Equal(t, clientID, requests[0].ClientID, "the client the zone authenticated")
	assert.Equal(t, user, requests[0].Subject, "the impersonated user")
}

// substituteUser is the unsigned subject token that the exchange sends. The
// trailing dot marks the absent signature.
func substituteUser(t *testing.T, subject string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"sub": subject})
	require.NoError(t, err, "encode the claims")
	encode := base64.RawURLEncoding.EncodeToString
	return encode([]byte(`{"typ":"vnd.kc.su+jwt","alg":"none"}`)) + "." + encode(payload) + "."
}

// TestFailuresAreTwoClasses records the reason for each failure. A zone
// policy refusal is access_denied. Every other failure is exchange_failed.
func TestFailuresAreTwoClasses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// secret authenticates the client. An empty value uses the known secret.
		secret string
		// zoneOpts configures the fake server. A nil handler uses the fixture.
		zoneOpts fakeas.Options
		// handler replaces the fixture server.
		handler http.Handler
		// unreachable points the source at an unused address.
		unreachable  bool
		resource     string
		wantErr      error
		wantExchange int
	}{
		{
			name:         "the zone's policy does not grant the resource",
			resource:     "https://not-granted.example/",
			wantErr:      credential.ErrAccessDenied,
			wantExchange: 1,
		},
		{
			name:   "the client secret is not the one the zone holds",
			secret: "not-the-secret",
			// invalid_client is not a policy denial. The proxy did not
			// authenticate, so it did not read policy.
			wantErr:      credential.ErrExchangeFailed,
			wantExchange: 1,
		},
		{
			name:         "discovery finds no metadata",
			handler:      http.NotFoundHandler(),
			wantErr:      credential.ErrExchangeFailed,
			wantExchange: 0,
		},
		{
			name:         "the zone is unreachable",
			unreachable:  true,
			wantErr:      credential.ErrExchangeFailed,
			wantExchange: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.zoneOpts.ClientSecrets = map[string]string{clientID: clientSecret}
			server, zoneURL := zone(t, tc.zoneOpts)
			if tc.handler != nil {
				replaced := httptest.NewServer(tc.handler)
				t.Cleanup(replaced.Close)
				zoneURL = replaced.URL
			}
			if tc.unreachable {
				zoneURL = "http://" + closedAddress(t)
			}
			secret := tc.secret
			if secret == "" {
				secret = clientSecret
			}
			source, err := exchange.New(exchange.Options{
				ZoneURL: zoneURL, ClientID: clientID, ImpersonateUser: user, ClientSecret: secret,
			})
			require.NoError(t, err, "New")

			want := tc.resource
			if want == "" {
				want = resource
			}
			value, err := source.Credential(t.Context(), want)
			require.ErrorIs(t, err, tc.wantErr, "the failure class")
			assert.Empty(t, value, "a failed exchange yields no credential")
			assert.Len(t, server.Requests(), tc.wantExchange, "exchanges the zone saw")
		})
	}
}

// closedAddress returns a loopback address with no listener.
func closedAddress(t *testing.T) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err, "reserve a port")
	address := listener.Addr().String()
	require.NoError(t, listener.Close(), "release the port")
	return address
}

// TestADeniedRequestMakesNoExchange checks that a resource no endpoint asks
// for reaches no zone.
func TestADeniedRequestMakesNoExchange(t *testing.T) {
	t.Parallel()
	server, zoneURL := zone(t, fakeas.Options{ClientSecrets: map[string]string{clientID: clientSecret}})
	source, err := exchange.New(exchange.Options{
		ZoneURL: zoneURL, ClientID: clientID, ImpersonateUser: user, ClientSecret: clientSecret,
	})
	require.NoError(t, err, "New")
	assert.Empty(t, server.Requests(), "constructing the source reaches no zone")

	_, err = source.Credential(t.Context(), resource)
	require.NoError(t, err, "Credential")
	assert.Len(t, server.Requests(), 1, "one exchange for one call")
}

// TestTheBudgetBoundsAnExchange checks that a quiet zone cannot hold a proxy
// request open after it accepts the request.
func TestTheBudgetBoundsAnExchange(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	server, _ := zone(t, fakeas.Options{ClientSecrets: map[string]string{clientID: clientSecret}})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == fakeas.TokenPath {
			<-release
			return
		}
		server.ServeHTTP(w, r)
	}))
	// Close runs last. It waits for the stalled handler, which the release
	// callback lets go.
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(release) })
	// The metadata names the slow server that fronts the fixture.
	source, err := exchange.New(exchange.Options{
		ZoneURL: slow.URL, ClientID: clientID, ImpersonateUser: user, ClientSecret: clientSecret,
		Timeout: 200 * time.Millisecond,
	})
	require.NoError(t, err, "New")

	start := time.Now()
	_, err = source.Credential(context.WithoutCancel(t.Context()), resource)
	require.ErrorIs(t, err, credential.ErrExchangeFailed, "a spent budget is exchange_failed")
	assert.Less(t, time.Since(start), 5*time.Second, "the budget ends the exchange")
}

// TestADeniedZoneAddressIsNotDialed checks the deny list on the zone leg. A
// denied address reaches no socket, so the client secret is never offered.
func TestADeniedZoneAddressIsNotDialed(t *testing.T) {
	t.Parallel()
	_, zoneURL := zone(t, fakeas.Options{ClientSecrets: map[string]string{clientID: clientSecret}})
	source, err := exchange.New(exchange.Options{
		ZoneURL: zoneURL, ClientID: clientID, ImpersonateUser: user, ClientSecret: clientSecret,
		DenyAddr: func(addr netip.Addr) bool { return addr.IsLoopback() },
	})
	require.NoError(t, err, "New")

	_, err = source.Credential(t.Context(), resource)
	require.ErrorIs(t, err, credential.ErrExchangeFailed, "a denied address fails the exchange")
	assert.ErrorContains(t, err, "deny list", "the message names why")
}

// TestNewRefusals rejects configuration that the source cannot use at
// start-up rather than on the first request.
func TestNewRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    exchange.Options
		wantErr string
	}{
		{
			name:    "no client secret",
			opts:    exchange.Options{ImpersonateUser: user},
			wantErr: "names no client secret",
		},
		{
			name: "a workload token file, which this build does not read",
			//nolint:gosec // G101: a path, not a credential
			opts:    exchange.Options{ImpersonateUser: user, WorkloadTokenFile: "/var/run/secrets/keycard/token"},
			wantErr: "which this build does not read",
		},
		{
			name:    "no user to impersonate",
			opts:    exchange.Options{ClientSecret: clientSecret},
			wantErr: "names no user to impersonate",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := tc.opts
			opts.ZoneURL, opts.ClientID = "https://zone.example", clientID
			source, err := exchange.New(opts)
			require.Error(t, err, "New must refuse this configuration")
			require.ErrorContains(t, err, tc.wantErr, "the message names the problem")
			assert.Nil(t, source, "a refused configuration yields no source")
		})
	}
}

// TestDescribeNamesTheSourceAndNoSecret checks the text that the start-up log
// and /info print. It must contain no value that outlives a request.
func TestDescribeNamesTheSourceAndNoSecret(t *testing.T) {
	t.Parallel()
	source, err := exchange.New(exchange.Options{
		ZoneURL: "https://zone.example", ClientID: clientID, ImpersonateUser: user, ClientSecret: clientSecret,
	})
	require.NoError(t, err, "New")

	describe := source.Describe()
	for _, want := range []string{"https://zone.example", user, "client secret"} {
		assert.Contains(t, describe, want, "Describe names %s", want)
	}
	assert.NotContains(t, describe, clientSecret, "Describe NEVER carries the client secret")
}

// TestTheZoneIssuerMustMatchTheConfiguredZone checks RFC 8414 section 3.3. A
// server with another issuer is not the zone in the document, so the exchange
// does not post a token to it.
func TestTheZoneIssuerMustMatchTheConfiguredZone(t *testing.T) {
	t.Parallel()
	// The metadata names another issuer, which RFC 8414 section 3.3 makes a
	// mismatch. The constant needs no handler encoding.
	const metadata = `{"issuer":"https://other.example","token_endpoint":"https://other.example/token"}`
	impostor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(metadata))
	}))
	t.Cleanup(impostor.Close)

	source, err := exchange.New(exchange.Options{
		ZoneURL: impostor.URL, ClientID: clientID, ImpersonateUser: user, ClientSecret: clientSecret,
	})
	require.NoError(t, err, "New")

	_, err = source.Credential(t.Context(), resource)
	require.ErrorIs(t, err, credential.ErrExchangeFailed, "an issuer mismatch is exchange_failed")
	assert.ErrorContains(t, err, "does not match", "the message names the mismatch")
}
