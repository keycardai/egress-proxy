// Package exchange mints an upstream credential for one resource with an RFC
// 8693 token exchange against a Keycard zone.
//
// The exchange impersonates the user named by identity.impersonate.user. Its
// subject_token is an unsigned substitute-user JWT, so the proxy sends no
// signature. The zone's policy must refuse an unauthorized user.
//
// This build authenticates with client_secret_basic. A client secret names no
// ServiceAccount, so a zone that accepts it permits impersonation based on the
// secret alone. This build refuses identity.workload_token_file.
package exchange

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/keycardai/go-sdk/oauth"

	"github.com/keycardai/egress-proxy/internal/credential"
)

// substituteUserHeader is the JOSE header for the unsigned substitute-user
// token. The type is the vendor media type that the zone reads.
const substituteUserHeader = `{"typ":"vnd.kc.su+jwt","alg":"none"}`

// accessDenied is the OAuth error code that the zone returns when its policy
// refuses the exchange.
const accessDenied = "access_denied"

// DefaultTimeout is the budget for one exchange when Options sets no value.
// It covers discovery and the token request.
const DefaultTimeout = 10 * time.Second

// dialTimeout and tlsHandshakeTimeout limit the zone connection. A zone that
// accepts a socket and then goes quiet cannot hold a request past the budget.
const (
	dialTimeout         = 5 * time.Second
	tlsHandshakeTimeout = 5 * time.Second
)

var (
	errConfigure = errors.New("configure the token exchange")
	errDenied    = errors.New("the address is on the platform deny list")
)

// Options configures a Source. ClientSecret authenticates the client.
type Options struct {
	// ZoneURL is the issuer URL for RFC 8414 discovery.
	ZoneURL string
	// ClientID is the application credential that the proxy uses.
	ClientID string
	// ImpersonateUser is the IAM user public ID for each exchange.
	ImpersonateUser string
	// WorkloadTokenFile is the projected ServiceAccount token. This build does
	// not read it and refuses a configuration that names it.
	WorkloadTokenFile string
	// ClientSecret is the application credential secret. The proxy reads it
	// once, so a rotated secret takes effect after restart.
	ClientSecret string
	// Timeout is the budget for one exchange. Zero selects DefaultTimeout.
	Timeout time.Duration
	// Roots verifies the zone. Nil selects the system roots.
	Roots *x509.CertPool
	// DenyAddr reports whether an address is on the platform deny list. The
	// exchange refuses to connect to a covered address. Nil skips the check.
	DenyAddr func(netip.Addr) bool
}

// Source mints a credential for each resource. It satisfies credential.Source.
type Source struct {
	client      *oauth.TokenExchangeClient
	application oauth.ApplicationCredential
	// subject is the substitute-user token. The process does not change the
	// impersonated user, so it builds the token once.
	subject  string
	timeout  time.Duration
	describe string
}

// New builds the source without reading from the network. If the zone is
// unreachable at start-up, requests fail instead of stopping the process.
func New(opts Options) (*Source, error) {
	application, describe, err := opts.application()
	if err != nil {
		return nil, err
	}
	subject, err := substituteUserToken(opts.ImpersonateUser)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	httpClient := &http.Client{Transport: opts.transport(), Timeout: timeout}
	clientOpts := []oauth.TokenExchangeClientOption{oauth.WithTokenExchangeHTTPClient(httpClient)}
	// A client secret supplies its basic-auth pair here. An assertion supplies
	// no pair and puts the assertion on the form instead.
	if auth := application.Auth(opts.ZoneURL); auth != nil {
		clientOpts = append(clientOpts, oauth.WithClientCredentials(auth.ClientID, auth.ClientSecret))
	}
	return &Source{
		client:      oauth.NewTokenExchangeClient(opts.ZoneURL, clientOpts...),
		application: application,
		subject:     subject,
		timeout:     timeout,
		describe: fmt.Sprintf("a Keycard token exchange at %s impersonating %s, %s",
			opts.ZoneURL, opts.ImpersonateUser, describe),
	}, nil
}

// application builds the client credential and the phrase that Describe uses.
// The interface lets the workload identity mechanism provide another form.
//
//nolint:ireturn // the SDK models a client credential as this interface
func (o Options) application() (oauth.ApplicationCredential, string, error) {
	switch {
	case o.WorkloadTokenFile != "":
		return nil, "", fmt.Errorf(
			"%w: it names identity.workload_token_file, which this build does not read; "+
				"authenticate with identity.client_secret_file", errConfigure,
		)
	case o.ClientSecret == "":
		return nil, "", fmt.Errorf("%w: it names no client secret", errConfigure)
	}
	application, err := oauth.NewClientSecret(o.ClientID, o.ClientSecret)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", errConfigure, err)
	}
	return application, "authenticated by a client secret", nil
}

// transport connects to the zone with TLS 1.2 or later, the configured roots,
// no proxy, and the deny list on every resolved address.
func (o Options) transport() *http.Transport {
	denyAddr := o.DenyAddr
	dialer := &net.Dialer{
		Timeout: dialTimeout,
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			if denyAddr == nil {
				return nil
			}
			addrPort, err := netip.ParseAddrPort(address)
			if err != nil || denyAddr(addrPort.Addr()) {
				return fmt.Errorf("%w: %s", errDenied, address)
			}
			return nil
		},
	}
	return &http.Transport{
		Proxy:               nil,
		DialContext:         dialer.DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.Roots},
		TLSHandshakeTimeout: tlsHandshakeTimeout,
	}
}

// Credential exchanges for the resource's access token. It returns
// credential.ErrAccessDenied or credential.ErrExchangeFailed for a failure.
// The proxy maps each error to the denial reason with the same name.
func (s *Source) Credential(ctx context.Context, resource string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// The client credential uses no prepare options.
	request, err := s.application.PrepareTokenExchangeRequest(ctx, s.subject, resource, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %w", credential.ErrExchangeFailed, err)
	}
	// PrepareTokenExchangeRequest types the subject as an access token. This
	// exchange sends the substitute-user type.
	request.SubjectTokenType = oauth.SubstituteUserTokenType

	response, err := s.client.ExchangeToken(ctx, *request)
	if err != nil {
		return "", classify(err)
	}
	return response.AccessToken, nil
}

// Describe names the zone, the user, and the mechanism. It never includes the
// client secret or the workload token.
func (s *Source) Describe() string {
	return s.describe
}

// classify maps an exchange failure to the Source error vocabulary. A zone
// policy refusal is access_denied. Every other failure is exchange_failed.
// The proxy cannot know the zone's answer for those failures.
func classify(err error) error {
	var oauthErr *oauth.OAuthError
	if errors.As(err, &oauthErr) && oauthErr.ErrorCode == accessDenied {
		return fmt.Errorf("%w: %s", credential.ErrAccessDenied, oauthErr.Message)
	}
	return fmt.Errorf("%w: %w", credential.ErrExchangeFailed, err)
}

// substituteUserToken builds the unsigned JWT that names the impersonated
// user. The trailing dot marks the absent signature segment.
//
// TokenExchangeClient.Impersonate does not send a client_id form parameter. A
// token-federation application credential needs that parameter, so the
// exchange builds the form here.
func substituteUserToken(user string) (string, error) {
	if user == "" {
		return "", fmt.Errorf("%w: it names no user to impersonate", errConfigure)
	}
	payload, err := json.Marshal(struct {
		Sub string `json:"sub"`
	}{Sub: user})
	if err != nil {
		return "", fmt.Errorf("%w: encode the substitute-user token: %w", errConfigure, err)
	}
	return oauth.Base64URLEncode([]byte(substituteUserHeader)) + "." + oauth.Base64URLEncode(payload) + ".", nil
}
