// Package exchange mints an upstream credential for one resource with an RFC
// 8693 token exchange against a Keycard zone.
//
// The exchange impersonates the user named by identity.impersonate.user. Its
// subject_token is an unsigned substitute-user JWT, so the proxy sends no
// signature. The zone's policy must refuse an unauthorized user.
//
// Workload identity sends the projected ServiceAccount token as an RFC 7523
// client assertion. The zone policy ties that ServiceAccount to one user. A
// client secret uses client_secret_basic without any binding to the
// ServiceAccount, so a zone that accepts it permits impersonation based on the
// secret alone. Use workload identity in a Kubernetes cluster deployment.
//
// AssertionSource is the other mechanism, with no credential held by the
// proxy: a client_credentials grant that the request's sandbox assertion
// authenticates, or a token exchange for the sandbox owner the assertion
// names, authenticated the same way.
package exchange

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/keycardai/go-sdk/oauth"

	"github.com/keycardai/egress-proxy/internal/credential"
)

// These are the OAuth error codes that mean the zone refused on policy. The
// zone returns access_denied when its policy does not grant the resource,
// unauthorized_client when this client may not impersonate, and invalid_grant
// when the user is unknown or not impersonatable. Each refusal is permanent.
const (
	codeAccessDenied       = "access_denied"
	codeUnauthorizedClient = "unauthorized_client"
	codeInvalidGrant       = "invalid_grant"
)

// codeAuthorizationRequired is the zone's answer when the person the
// exchange acts for holds no grant for the resource's provider
// (draft-ietf-oauth-first-party-apps). It is not a policy refusal: the
// person authorizes the resource once, with the Keycard CLI, and the same
// exchange then succeeds.
const codeAuthorizationRequired = "insufficient_authorization"

// schemeHTTPS is the only scheme the exchange connects with. Client
// authentication goes to the zone, so cleartext would put it on the wire.
const schemeHTTPS = "https"

// maxResponseSize limits a response from the zone. A token response holds the
// access token, a refresh token, and any authorization details the zone
// returns, so the limit sits well above the size of one token.
const maxResponseSize = 1 << 20

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
	errCleartext = errors.New("the zone must be https")
	errRedirect  = errors.New("the zone redirected the exchange")
	errTooLarge  = errors.New("the zone answered with more than 1 MiB")
)

// Options configures a Source. Exactly one of WorkloadTokenFile and
// ClientSecret authenticates the client.
type Options struct {
	// ZoneURL is the issuer URL for RFC 8414 discovery. It must be https.
	ZoneURL string
	// ClientID is the application credential that the proxy uses.
	ClientID string
	// ImpersonateUser is the IAM user public ID for each exchange.
	ImpersonateUser string
	// WorkloadTokenFile is the projected ServiceAccount token. It must name a
	// path that credential.CheckTokenFile accepts. The kubelet rewrites the
	// token once it passes 80% of its lifetime, which defaults to one hour,
	// and the pod keeps running across the rewrite. The proxy therefore reads
	// the file for every exchange. The kubelet swaps the file atomically, so a
	// read never sees a partial write.
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
	zone     string
	timeout  time.Duration
	describe string
}

// New builds the source without reading from the network. If the zone is
// unreachable at start-up, requests fail instead of stopping the process.
func New(opts Options) (*Source, error) {
	if err := checkZoneURL(opts.ZoneURL); err != nil {
		return nil, err
	}
	application, describe, err := opts.application()
	if err != nil {
		return nil, err
	}
	if opts.ImpersonateUser == "" {
		return nil, fmt.Errorf("%w: it names no user to impersonate", errConfigure)
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	httpClient := newHTTPClient(timeout, opts.Roots, opts.DenyAddr)
	clientOpts := []oauth.TokenExchangeClientOption{oauth.WithTokenExchangeHTTPClient(httpClient)}
	// A client secret authenticates with its basic-auth pair.
	if auth := application.Auth(opts.ZoneURL); auth != nil {
		clientOpts = append(clientOpts, oauth.WithClientCredentials(auth.ClientID, auth.ClientSecret))
	}
	return &Source{
		client:      oauth.NewTokenExchangeClient(opts.ZoneURL, clientOpts...),
		application: application,
		subject:     substituteUserToken(opts.ImpersonateUser),
		zone:        opts.ZoneURL,
		timeout:     timeout,
		describe: fmt.Sprintf("a Keycard token exchange at %s impersonating %s, %s",
			opts.ZoneURL, opts.ImpersonateUser, describe),
	}, nil
}

// checkZoneURL refuses a zone that the exchange must not authenticate to.
// internal/config applies the same rule, and this check covers a source that
// another caller builds.
func checkZoneURL(zone string) error {
	parsed, err := url.Parse(zone)
	if err != nil {
		return fmt.Errorf("%w: identity.zone_url does not parse: %w", errConfigure, err)
	}
	if parsed.Scheme != schemeHTTPS {
		return fmt.Errorf("%w: %w, not %q", errConfigure, errCleartext, zone)
	}
	return nil
}

// newHTTPClient is the client every exchange reaches the zone with: the
// guarded transport, the budget, and no redirects. Discovery names the token
// endpoint, and a redirect away from it would move client authentication to
// another host.
func newHTTPClient(timeout time.Duration, roots *x509.CertPool, denyAddr func(netip.Addr) bool) *http.Client {
	return &http.Client{
		Transport: guard{base: transport(roots, denyAddr)},
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("%w to %s", errRedirect, req.URL.Redacted())
		},
	}
}

// application builds the client credential and the description text. It
// refuses a configuration that names neither mechanism, and one that names
// both.
//
//nolint:ireturn // the SDK uses one interface for both mechanisms
func (o Options) application() (oauth.ApplicationCredential, string, error) {
	switch {
	case o.WorkloadTokenFile != "" && o.ClientSecret != "":
		return nil, "", fmt.Errorf(
			"%w: it names a workload token file and a client secret; configure one", errConfigure,
		)
	case o.WorkloadTokenFile != "":
		return o.workloadIdentity()
	case o.ClientSecret != "":
		application, err := oauth.NewClientSecret(o.ClientID, o.ClientSecret)
		if err != nil {
			return nil, "", fmt.Errorf("%w: %w", errConfigure, err)
		}
		return application, "authenticated by a client secret", nil
	default:
		return nil, "", fmt.Errorf("%w: it names no workload token file and no client secret", errConfigure)
	}
}

// workloadIdentity authenticates with the projected ServiceAccount token. The
// client ID goes on the form beside the assertion, because the token-federation
// credential identifies the client by that parameter.
//
//nolint:ireturn // the SDK uses one interface for both mechanisms
func (o Options) workloadIdentity() (oauth.ApplicationCredential, string, error) {
	if err := credential.CheckTokenFile(errConfigure, o.WorkloadTokenFile); err != nil {
		//nolint:wrapcheck // CheckTokenFile wraps errConfigure, which callers match on
		return nil, "", err
	}
	tokens, err := oauth.NewFileTokenSource(oauth.WithFileTokenPath(o.WorkloadTokenFile))
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", errConfigure, err)
	}
	application, err := oauth.NewWorkloadIdentity(tokens, oauth.WithWorkloadClientID(o.ClientID))
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", errConfigure, err)
	}
	return application, "authenticated by the workload token at " + o.WorkloadTokenFile, nil
}

// transport connects to the zone with TLS 1.2 or later, the configured roots,
// no proxy, and the deny list on every resolved address.
func transport(roots *x509.CertPool, denyAddr func(netip.Addr) bool) *http.Transport {
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
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: tlsHandshakeTimeout,
	}
}

// guard refuses a cleartext request and limits the size of every response.
// Discovery and the token request both go through it, so metadata that names
// an http token_endpoint reaches no socket.
type guard struct {
	base http.RoundTripper
}

func (g guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != schemeHTTPS {
		return nil, fmt.Errorf("%w: %s", errCleartext, req.URL.Redacted())
	}
	response, err := g.base.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("reach the zone: %w", err)
	}
	response.Body = &limitedBody{body: response.Body, left: maxResponseSize}
	return response, nil
}

// limitedBody reads at most maxResponseSize bytes and fails past that. It
// reads one byte beyond the limit to tell a body at the limit from a longer
// one.
type limitedBody struct {
	body io.ReadCloser
	left int64
}

func (b *limitedBody) Read(buf []byte) (int, error) {
	if b.left < 0 {
		return 0, errTooLarge
	}
	if int64(len(buf)) > b.left+1 {
		buf = buf[:b.left+1]
	}
	read, err := b.body.Read(buf)
	b.left -= int64(read)
	if b.left < 0 {
		return 0, errTooLarge
	}
	if err != nil {
		//nolint:wrapcheck // io.EOF must stay unwrapped so a reader stops
		return read, err
	}
	return read, nil
}

func (b *limitedBody) Close() error {
	if err := b.body.Close(); err != nil {
		return fmt.Errorf("close the zone response: %w", err)
	}
	return nil
}

// Credential exchanges for the resource's access token. It returns
// credential.ErrExchangeDenied or credential.ErrExchangeFailed for a failure.
// The proxy maps each error to the denial reason with the same name.
func (s *Source) Credential(ctx context.Context, resource string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Both mechanisms ignore the prepare options, so they are nil.
	request, err := s.application.PrepareTokenExchangeRequest(ctx, s.subject, resource, nil)
	if err != nil {
		return "", failed("the client authentication was not prepared", err)
	}
	// PrepareTokenExchangeRequest types the subject as an access token. This
	// exchange sends the substitute-user type.
	request.SubjectTokenType = oauth.SubstituteUserTokenType

	response, err := s.client.ExchangeToken(ctx, *request)
	if err != nil {
		return "", classify(err, refusedOnPolicy, s.zone, resource)
	}
	return response.AccessToken, nil
}

// Describe names the zone, the user, and the mechanism. It never includes the
// client secret or the workload token.
func (s *Source) Describe() string {
	return s.describe
}

// classify maps an exchange failure to the source error vocabulary. A zone
// policy refusal, which refused says by its code, is exchange_denied, which
// denies with 403, because a retry gets the same answer. Every other failure
// is exchange_failed, which denies with 502. The proxy does not know the
// zone's answer for those.
//
// An OAuth answer carries its error_description as the detail, whichever
// class it falls in. The description is the zone's prose about its policy
// and never holds a credential.
func classify(err error, refused func(code string) bool, zone, resource string) error {
	var oauthErr *oauth.OAuthError
	if !errors.As(err, &oauthErr) {
		return failed(failureDetail(err), err)
	}
	switch {
	case oauthErr.ErrorCode == codeAuthorizationRequired:
		return &credential.ExchangeError{
			Class:  credential.ErrAuthorizationRequired,
			Detail: strings.TrimSpace(oauthErr.Message + " " + authorizationHint(zone, resource)),
			Cause:  err,
		}
	case refused(oauthErr.ErrorCode):
		return &credential.ExchangeError{Class: credential.ErrExchangeDenied, Detail: oauthErr.Message, Cause: err}
	default:
		return &credential.ExchangeError{Class: credential.ErrExchangeFailed, Detail: oauthErr.Message, Cause: err}
	}
}

// authorizationHint is the sentence that tells the person how to authorize
// the resource: the Keycard CLI's own consent command, the one it prints for
// the same answer. The zone id is the first label of the zone's host, which
// is how the CLI names a zone. The agent reading the refusal cannot run it;
// the person it acts for can.
func authorizationHint(zone, resource string) string {
	parsed, err := url.Parse(zone)
	if err != nil || parsed.Hostname() == "" || net.ParseIP(parsed.Hostname()) != nil {
		return fmt.Sprintf("Run 'keycard auth resource %s' as that person, then retry.", resource)
	}
	zoneID, _, _ := strings.Cut(parsed.Hostname(), ".")
	return fmt.Sprintf("Run 'keycard auth resource %s --zone %s' as that person, then retry.", resource, zoneID)
}

// failed is an exchange_failed error with the detail the refusal carries.
func failed(detail string, cause error) error {
	return &credential.ExchangeError{Class: credential.ErrExchangeFailed, Detail: detail, Cause: cause}
}

// failureDetail names the class of a failure the zone did not describe. It
// gives the status of a non-token answer, the budget, or one of this
// package's own refusals, and never an address or a response body.
func failureDetail(err error) string {
	var httpErr *oauth.HTTPError
	switch {
	case errors.As(err, &httpErr) && httpErr.Status > 0:
		return "the zone answered " + strconv.Itoa(httpErr.Status)
	case errors.Is(err, context.DeadlineExceeded):
		return "the exchange ran past its budget"
	}
	for _, refusal := range []error{errRedirect, errCleartext, errTooLarge, errDenied} {
		if errors.Is(err, refusal) {
			return refusal.Error()
		}
	}
	return "the exchange did not complete"
}

// refusedOnPolicy reports whether an OAuth error code means the zone read its
// policy and said no.
func refusedOnPolicy(code string) bool {
	switch code {
	case codeAccessDenied, codeUnauthorizedClient, codeInvalidGrant:
		return true
	default:
		return false
	}
}
