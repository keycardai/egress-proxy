// Package exchange mints the upstream credential for one resource with an
// RFC 8693 token exchange against a Keycard zone.
//
// The exchange impersonates the user that identity.impersonate.user names.
// Its subject_token is an unsigned substitute-user JWT carrying that user id,
// so the proxy signs nothing and can put any user id on the wire. The zone's
// policy is what refuses a wrong one, which is why the client authentication
// below is the whole of the proxy's authority.
//
// This build authenticates the client with a client secret, sent as
// client_secret_basic. A secret names no ServiceAccount, so a zone that
// accepts one permits impersonation on the strength of the secret alone and
// its policy cannot narrow the exchange to one user. The build refuses
// identity.workload_token_file, which it does not read.
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

// substituteUserHeader is the JOSE header of the unsigned substitute-user
// token. The type is the vendor media type the zone reads.
const substituteUserHeader = `{"typ":"vnd.kc.su+jwt","alg":"none"}`

// accessDenied is the OAuth error code the zone answers with when its policy
// refuses the exchange.
const accessDenied = "access_denied"

// DefaultTimeout is the budget for one exchange when Options names none. It
// covers discovery and the token request together.
const DefaultTimeout = 10 * time.Second

// dialTimeout and tlsHandshakeTimeout bound the legs of a connection to the
// zone, so a zone that accepts a socket and then goes quiet cannot hold a
// request past the exchange budget.
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
	// ZoneURL is the issuer RFC 8414 discovery runs against.
	ZoneURL string
	// ClientID is the application credential the proxy authenticates as.
	ClientID string
	// ImpersonateUser is the IAM user public id every exchange acts for.
	ImpersonateUser string
	// WorkloadTokenFile is the projected ServiceAccount token. This build
	// does not read one and refuses a configuration that names it, rather
	// than authenticating with a secret the document did not ask it to use.
	WorkloadTokenFile string
	// ClientSecret is the application credential's secret. It is read once,
	// so a rotated secret takes effect on the next start.
	ClientSecret string
	// Timeout is the budget for one exchange. Zero means DefaultTimeout.
	Timeout time.Duration
	// Roots verifies the zone. Nil means the system roots.
	Roots *x509.CertPool
	// DenyAddr reports whether an address is one the platform deny list
	// covers. The exchange refuses to connect to one, so a zone URL that
	// resolves into the cluster or onto the metadata address reaches no
	// socket. Nil applies no check.
	DenyAddr func(netip.Addr) bool
}

// Source mints a credential per resource. It satisfies credential.Source.
type Source struct {
	client      *oauth.TokenExchangeClient
	application oauth.ApplicationCredential
	// subject is the substitute-user token. The impersonated user does not
	// change while the process runs, so the token is built once.
	subject  string
	timeout  time.Duration
	describe string
}

// New builds the source. It reads nothing from the network, so a zone that
// is unreachable at start-up denies requests rather than stopping the
// process.
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
	// A credential that authenticates with a secret answers its basic-auth
	// pair here. One that authenticates with an assertion answers nil and
	// puts the assertion on the form instead.
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

// application builds the client credential and the phrase Describe names it
// with. The interface is the seam the workload identity mechanism fills.
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

// transport is the leg to the zone: TLS 1.2 or better against Roots, no
// proxy, and the deny list on every resolved address.
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

// Credential exchanges for the resource's access token. Every failure is one
// of credential.ErrAccessDenied and credential.ErrExchangeFailed, which the
// proxy maps to the denial reason of the same name.
func (s *Source) Credential(ctx context.Context, resource string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// The client credential reads no prepare options, so they are nil.
	request, err := s.application.PrepareTokenExchangeRequest(ctx, s.subject, resource, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %w", credential.ErrExchangeFailed, err)
	}
	// PrepareTokenExchangeRequest types the subject as an access token,
	// which is what every other grant sends. Impersonation sends the
	// substitute-user type.
	request.SubjectTokenType = oauth.SubstituteUserTokenType

	response, err := s.client.ExchangeToken(ctx, *request)
	if err != nil {
		return "", classify(err)
	}
	return response.AccessToken, nil
}

// Describe names the zone, the user and the mechanism. It NEVER includes the
// client secret or the workload token.
func (s *Source) Describe() string {
	return s.describe
}

// classify maps an exchange failure onto the Source error vocabulary. The
// zone's policy refusing the exchange is access_denied. Everything else is
// exchange_failed, including a discovery failure, an unreachable zone and a
// spent budget, because the proxy does not know what the zone would have
// answered.
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
// The SDK builds this token inside TokenExchangeClient.Impersonate, which
// sends no client_id form parameter. A token-federation application
// credential is resolved by that parameter, so the exchange posts the form
// itself and builds the token here.
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
