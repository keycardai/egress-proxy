package exchange_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
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

// zone is a fake authorization server over TLS. The exchange refuses a
// cleartext zone, so every fixture here serves https.
type fakeZone struct {
	// server records the token requests that reached the fixture.
	server *fakeas.Server
	url    string
	roots  *x509.CertPool
	// stop closes the listener. A test calls it to make the zone unreachable
	// at the URL the source already holds.
	stop func()
}

// newZone starts a fixture. front, when set, answers the token endpoint in
// place of the fixture. Discovery still comes from the fixture, so the
// metadata names this server as its issuer.
func newZone(t *testing.T, front http.HandlerFunc) *fakeZone {
	t.Helper()
	fixture := fakeas.New(fakeas.Options{
		Credentials:   map[string]string{resource: granted},
		ClientSecrets: map[string]string{clientID: clientSecret},
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if front != nil && r.URL.Path == fakeas.TokenPath {
			front(w, r)
			return
		}
		fixture.ServeHTTP(w, r)
	})
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return &fakeZone{server: fixture, url: server.URL, roots: roots, stop: server.Close}
}

// source builds a Source against the zone. Each option argument adjusts the
// configuration before New reads it.
func (z *fakeZone) source(t *testing.T, adjust ...func(*exchange.Options)) *exchange.Source {
	t.Helper()
	opts := exchange.Options{
		ZoneURL: z.url, ClientID: clientID, ImpersonateUser: user,
		ClientSecret: clientSecret, Roots: z.roots,
	}
	for _, apply := range adjust {
		apply(&opts)
	}
	source, err := exchange.New(opts)
	require.NoError(t, err, "New")
	return source
}

// TestTheWireForm checks each exchange parameter. The zone reads these names,
// so they define the contract with it.
func TestTheWireForm(t *testing.T) {
	t.Parallel()
	zone := newZone(t, nil)
	source := zone.source(t)

	value, err := source.Credential(t.Context(), resource)
	require.NoError(t, err, "Credential")
	assert.Equal(t, granted, value, "the credential the zone issued")

	requests := zone.server.Requests()
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
		assert.NotContains(t, form, key, "the form must not include %s", key)
	}
	assert.Len(t, form, len(wantForm), "the form holds exactly the parameters pinned above")
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
// policy refusal is exchange_denied. Every other failure is exchange_failed.
// Each case points the source at the fixture, so the exchange count says
// whether the zone was asked for a token.
func TestFailuresAreTwoClasses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// secret authenticates the client. An empty value uses the known secret.
		secret string
		// stall holds the token endpoint open until the case ends, so only
		// the budget can end the exchange.
		stall bool
		// noMetadata makes discovery answer 404 and leaves the token endpoint
		// on the fixture, so a token request would still be recorded.
		noMetadata bool
		// unreachable closes the zone before the exchange.
		unreachable bool
		timeout     time.Duration
		resource    string
		wantErr     error
		// wantExchange is the number of token requests the fixture recorded.
		wantExchange int
	}{
		{
			name:         "the zone's policy does not grant the resource",
			resource:     "https://not-granted.example/",
			wantErr:      credential.ErrExchangeDenied,
			wantExchange: 1,
		},
		{
			name:   "the client secret is not the one the zone holds",
			secret: "not-the-secret",
			// invalid_client is not a policy denial. The proxy did not
			// authenticate, so the zone did not read policy.
			wantErr:      credential.ErrExchangeFailed,
			wantExchange: 1,
		},
		{
			name:         "discovery finds no metadata",
			noMetadata:   true,
			wantErr:      credential.ErrExchangeFailed,
			wantExchange: 0,
		},
		{
			name:         "the zone is unreachable",
			unreachable:  true,
			wantErr:      credential.ErrExchangeFailed,
			wantExchange: 0,
		},
		{
			name:         "the zone accepts the request and never answers",
			stall:        true,
			timeout:      200 * time.Millisecond,
			wantErr:      credential.ErrExchangeFailed,
			wantExchange: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var front http.HandlerFunc
			release := make(chan struct{})
			if tc.stall {
				front = func(http.ResponseWriter, *http.Request) { <-release }
			}
			zone := newZone(t, front)
			if tc.noMetadata {
				zone = newZoneWithoutMetadata(t)
			}
			// Closing the listener waits for the stalled handler, so let it
			// go first. Cleanups run in reverse order of registration.
			t.Cleanup(func() { close(release) })
			source := zone.source(t, func(o *exchange.Options) {
				if tc.secret != "" {
					o.ClientSecret = tc.secret
				}
				o.Timeout = tc.timeout
			})
			if tc.unreachable {
				zone.stop()
			}

			want := tc.resource
			if want == "" {
				want = resource
			}
			// A spent budget must not cancel with the caller's context.
			value, err := source.Credential(context.WithoutCancel(t.Context()), want)
			require.ErrorIs(t, err, tc.wantErr, "the failure class")
			assert.Empty(t, value, "a failed exchange yields no credential")
			assert.Len(t, zone.server.Requests(), tc.wantExchange, "token requests the zone recorded")
		})
	}
}

// newZoneWithoutMetadata answers discovery with 404 and leaves the token
// endpoint on the fixture. A token request would be recorded, so an exchange
// count of zero proves that failed discovery stops the exchange.
func newZoneWithoutMetadata(t *testing.T) *fakeZone {
	t.Helper()
	zone := newZone(t, nil)
	fixture := zone.server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == fakeas.MetadataPath {
			http.NotFound(w, r)
			return
		}
		fixture.ServeHTTP(w, r)
	})
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return &fakeZone{server: fixture, url: server.URL, roots: roots, stop: server.Close}
}

// TestAPolicyRefusalIsExchangeDenied pins the OAuth error codes that mean the
// zone read its policy and said no. Each one denies with 403, so an agent
// does not retry a refusal that will not change. The SDK documents
// unauthorized_client and invalid_grant for this grant in
// oauth/impersonate.go.
func TestAPolicyRefusalIsExchangeDenied(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		code    string
		status  int
		wantErr error
	}{
		{
			name:    "the zone's policy does not grant the resource",
			code:    "access_denied",
			status:  http.StatusForbidden,
			wantErr: credential.ErrExchangeDenied,
		},
		{
			name:    "this client may not impersonate",
			code:    "unauthorized_client",
			status:  http.StatusBadRequest,
			wantErr: credential.ErrExchangeDenied,
		},
		{
			name:    "the user is unknown or not impersonatable",
			code:    "invalid_grant",
			status:  http.StatusBadRequest,
			wantErr: credential.ErrExchangeDenied,
		},
		{
			name:    "the client did not authenticate",
			code:    "invalid_client",
			status:  http.StatusUnauthorized,
			wantErr: credential.ErrExchangeFailed,
		},
		{
			name:    "the zone rejected the request shape",
			code:    "invalid_request",
			status:  http.StatusBadRequest,
			wantErr: credential.ErrExchangeFailed,
		},
		{
			name:    "the zone failed on its own",
			code:    "server_error",
			status:  http.StatusInternalServerError,
			wantErr: credential.ErrExchangeFailed,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			zone := newZone(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"error":%q,"error_description":"the zone said so"}`, tc.code)
			})

			value, err := zone.source(t).Credential(t.Context(), resource)
			require.ErrorIs(t, err, tc.wantErr, "the failure class for %s", tc.code)
			assert.Empty(t, value, "a failed exchange yields no credential")
		})
	}
}

// TestTheExchangeRefusesAnUnsafeZone checks the limits on the leg that offers
// the client secret. A zone that answers discovery still cannot move the
// exchange to cleartext, to another location, or past the response limit.
func TestTheExchangeRefusesAnUnsafeZone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// metadata answers discovery in place of the fixture.
		metadata http.HandlerFunc
		// front answers the token endpoint in place of the fixture.
		front http.HandlerFunc
		// wantMessage names the refusal in the error text.
		wantMessage string
	}{
		{
			name: "the token endpoint redirects",
			front: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/somewhere-else", http.StatusTemporaryRedirect)
			},
			wantMessage: "redirected the exchange",
		},
		{
			name: "the token response is larger than the limit",
			front: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer"}`, strings.Repeat("a", 70<<10))
			},
			wantMessage: "64 KiB",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture := fakeas.New(fakeas.Options{
				Credentials:   map[string]string{resource: granted},
				ClientSecrets: map[string]string{clientID: clientSecret},
			})
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case tc.metadata != nil && r.URL.Path == fakeas.MetadataPath:
					tc.metadata(w, r)
				case tc.front != nil && r.URL.Path == fakeas.TokenPath:
					tc.front(w, r)
				default:
					fixture.ServeHTTP(w, r)
				}
			})
			server := httptest.NewTLSServer(handler)
			t.Cleanup(server.Close)
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())

			source, err := exchange.New(exchange.Options{
				ZoneURL: server.URL, ClientID: clientID, ImpersonateUser: user,
				ClientSecret: clientSecret, Roots: roots,
			})
			require.NoError(t, err, "New")

			value, err := source.Credential(t.Context(), resource)
			require.ErrorIs(t, err, credential.ErrExchangeFailed, "an unsafe zone is exchange_failed")
			assert.Empty(t, value, "a refused exchange yields no credential")
			assert.NotContains(t, err.Error(), clientSecret, "the message NEVER includes the client secret")
			require.ErrorContains(t, err, tc.wantMessage, "the message names the refusal")
		})
	}
}

// TestTheTokenEndpointMustBeHTTPS checks the scheme of the endpoint that
// discovery names. RFC 8414 section 3.3 ties the issuer to the zone and says
// nothing about token_endpoint, so metadata with a matching issuer can still
// name a cleartext endpoint. The exchange must send the client secret to no
// such endpoint.
func TestTheTokenEndpointMustBeHTTPS(t *testing.T) {
	t.Parallel()
	// sink speaks cleartext and records anything that arrives. Nothing must.
	var mu sync.Mutex
	var sunk []string
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sunk = append(sunk, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer"}`, "stolen")
	}))
	t.Cleanup(sink.Close)

	// Binding the listener first fixes the issuer before any handler runs, so
	// the metadata names it without reading the request.
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err, "bind the zone listener")
	issuer := "https://" + listener.Addr().String()

	// The issuer matches the zone the proxy configured. Only the token
	// endpoint points away, at the cleartext sink.
	zone := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":"%s/oauth2/token"}`, issuer, sink.URL)
	}))
	require.NoError(t, zone.Listener.Close(), "release the default listener")
	zone.Listener = listener
	zone.StartTLS()
	t.Cleanup(zone.Close)
	require.Equal(t, issuer, zone.URL, "the served URL is the issuer the metadata names")
	roots := x509.NewCertPool()
	roots.AddCert(zone.Certificate())

	source, err := exchange.New(exchange.Options{
		ZoneURL: zone.URL, ClientID: clientID, ImpersonateUser: user,
		ClientSecret: clientSecret, Roots: roots,
	})
	require.NoError(t, err, "New")

	value, err := source.Credential(t.Context(), resource)
	require.ErrorIs(t, err, credential.ErrExchangeFailed, "a cleartext token endpoint is exchange_failed")
	assert.Empty(t, value, "the sink's token must not become a credential")

	mu.Lock()
	reached := append([]string(nil), sunk...)
	mu.Unlock()
	assert.Empty(t, reached, "the exchange NEVER opens a cleartext connection to the token endpoint")
	require.ErrorContains(t, err, "must be https", "the message names the refusal")
}

// TestTheSourceReachesTheZoneOnlyOnCredential checks that building a source
// makes no request, and that one call makes one exchange.
func TestTheSourceReachesTheZoneOnlyOnCredential(t *testing.T) {
	t.Parallel()
	zone := newZone(t, nil)
	source := zone.source(t)
	assert.Empty(t, zone.server.Requests(), "constructing the source reaches no zone")

	_, err := source.Credential(t.Context(), resource)
	require.NoError(t, err, "Credential")
	assert.Len(t, zone.server.Requests(), 1, "one exchange for one call")
}

// TestADeniedZoneAddressIsNotDialed checks the deny list on the zone leg. A
// denied address reaches no socket, so the client secret is never offered.
func TestADeniedZoneAddressIsNotDialed(t *testing.T) {
	t.Parallel()
	zone := newZone(t, nil)
	source := zone.source(t, func(o *exchange.Options) {
		o.DenyAddr = func(addr netip.Addr) bool { return addr.IsLoopback() }
	})

	_, err := source.Credential(t.Context(), resource)
	require.ErrorIs(t, err, credential.ErrExchangeFailed, "a denied address fails the exchange")
	assert.Empty(t, zone.server.Requests(), "a denied address reaches no exchange")
	require.ErrorContains(t, err, "deny list", "the message names why")
}

// TestNewRefusals rejects configuration that the source cannot use at
// start-up rather than on the first request.
func TestNewRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts exchange.Options
		// zoneURL overrides the default https zone.
		zoneURL string
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
		{
			name:    "a cleartext zone, which would put the secret on the wire",
			opts:    exchange.Options{ImpersonateUser: user, ClientSecret: clientSecret},
			zoneURL: "http://zone.example",
			wantErr: "the zone must be https",
		},
		{
			name:    "a zone with no scheme",
			opts:    exchange.Options{ImpersonateUser: user, ClientSecret: clientSecret},
			zoneURL: "zone.example",
			wantErr: "the zone must be https",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := tc.opts
			opts.ZoneURL, opts.ClientID = "https://zone.example", clientID
			if tc.zoneURL != "" {
				opts.ZoneURL = tc.zoneURL
			}
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
	assert.NotContains(t, describe, clientSecret, "Describe NEVER includes the client secret")
}

// TestTheZoneIssuerMustMatchTheConfiguredZone checks RFC 8414 section 3.3. A
// server with another issuer is not the zone in the document, so the exchange
// does not post a token to it.
func TestTheZoneIssuerMustMatchTheConfiguredZone(t *testing.T) {
	t.Parallel()
	// The metadata names another issuer, which RFC 8414 section 3.3 makes a
	// mismatch. The constant needs no handler encoding.
	const metadata = `{"issuer":"https://other.example","token_endpoint":"https://other.example/token"}`
	impostor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(metadata))
	}))
	t.Cleanup(impostor.Close)
	roots := x509.NewCertPool()
	roots.AddCert(impostor.Certificate())

	source, err := exchange.New(exchange.Options{
		ZoneURL: impostor.URL, ClientID: clientID, ImpersonateUser: user,
		ClientSecret: clientSecret, Roots: roots,
	})
	require.NoError(t, err, "New")

	_, err = source.Credential(t.Context(), resource)
	require.ErrorIs(t, err, credential.ErrExchangeFailed, "an issuer mismatch is exchange_failed")
	assert.ErrorContains(t, err, "does not match", "the message names the mismatch")
}
