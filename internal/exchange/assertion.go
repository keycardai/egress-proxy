package exchange

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/keycardai/go-sdk/oauth"

	"github.com/keycardai/egress-proxy/internal/assertion"
	"github.com/keycardai/egress-proxy/internal/credential"
)

// jwtBearer is the client assertion type of RFC 7523 section 2.2.
const jwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec // G101: a URN

// codeInvalidClient is the OAuth error code the zone answers when no
// application credential matches the assertion's subject, when the issuer is
// unknown, and when the signature or the expiry fails. The zone opens a
// session per assertion and matches the subject against its credentials, so
// the answer is its policy and a retry gets the same one.
const codeInvalidClient = "invalid_client"

// cacheMargin is how long before a token's expiry the cache stops serving
// it, so a request never leaves with a token the upstream is about to
// refuse.
const cacheMargin = 30 * time.Second

// maxCached bounds the token cache. One entry per subject, owner and
// resource, and a subject is one sandbox, so the bound is many sandboxes.
const maxCached = 4096

var (
	errNoAssertion = errors.New("no sandbox assertion on the request context")
	errClaims      = errors.New("read the assertion claims")
	errNoOwner     = errors.New("the assertion names no owner")
)

// AssertionOptions configures an AssertionSource.
type AssertionOptions struct {
	// ZoneURL is the issuer URL for RFC 8414 discovery. It must be https.
	ZoneURL string
	// Timeout is the budget for one exchange. Zero selects DefaultTimeout.
	Timeout time.Duration
	// Roots verifies the zone. Nil selects the system roots.
	Roots *x509.CertPool
	// DenyAddr reports whether an address is on the platform deny list. The
	// exchange refuses to connect to a covered address. Nil skips the check.
	DenyAddr func(netip.Addr) bool
	// ImpersonateOwner exchanges for the sandbox owner the assertion names
	// in owner_id: an RFC 8693 token exchange, authenticated by the
	// assertion, whose subject is the substitute-user token for that id. An
	// assertion that names no owner is refused before any exchange.
	ImpersonateOwner bool
}

// AssertionSource mints a credential for each resource with a grant that
// the request's sandbox assertion authenticates: a client_credentials grant
// as the sandbox itself, or a token exchange for the sandbox owner. The
// proxy holds no credential of its own: the assertion is the client
// assertion, and the zone's policy decides which application the sandbox is
// and whether it may act for the owner. It satisfies credential.Source.
type AssertionSource struct {
	// sandbox answers the client_credentials grant as the sandbox. owner
	// answers the token exchange for the sandbox owner. Exactly one is set.
	sandbox  *oauth.ClientCredentialsClient
	owner    *oauth.TokenExchangeClient
	timeout  time.Duration
	describe string
	now      func() time.Time

	mu    sync.Mutex
	cache map[cacheKey]cached
}

// cacheKey is one sandbox's token for one resource, for the owner it acts
// for. The zone opens a session per assertion, so the cache keeps the
// sessions bounded.
type cacheKey struct {
	subject  string
	owner    string
	resource string
}

type cached struct {
	token string
	// until is when the cache stops serving the token: its expiry less
	// cacheMargin.
	until time.Time
}

// NewAssertionSource builds the source without reading from the network.
func NewAssertionSource(opts AssertionOptions) (*AssertionSource, error) {
	if err := checkZoneURL(opts.ZoneURL); err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	httpClient := newHTTPClient(timeout, opts.Roots, opts.DenyAddr)
	source := &AssertionSource{timeout: timeout, now: time.Now, cache: make(map[cacheKey]cached)}
	switch {
	case opts.ImpersonateOwner:
		source.owner = oauth.NewTokenExchangeClient(opts.ZoneURL, oauth.WithTokenExchangeHTTPClient(httpClient))
		source.describe = "sandbox assertions exchanged at " + opts.ZoneURL +
			" for the sandbox owner (token-exchange, jwt-bearer)"
	default:
		source.sandbox = oauth.NewClientCredentialsClient(opts.ZoneURL, oauth.WithCCHTTPClient(httpClient))
		source.describe = "sandbox assertions exchanged at " + opts.ZoneURL +
			" as the sandbox (client_credentials, jwt-bearer)"
	}
	return source, nil
}

// Credential presents the request's assertion to the zone and returns the
// access token for the resource. A call with no assertion on the context is
// a programming error, reported as credential.ErrExchangeFailed. An
// assertion that names no owner, where the source exchanges for the owner,
// is credential.ErrUnavailable. The token is served from the cache while it
// lives.
func (s *AssertionSource) Credential(ctx context.Context, resource string) (string, error) {
	token, ok := assertion.TokenFromContext(ctx)
	if !ok || token == "" {
		return "", failed(errNoAssertion.Error(), errNoAssertion)
	}
	claims, err := claimsOf(token)
	if err != nil {
		return "", failed("the assertion claims were not read", err)
	}
	if s.owner != nil && claims.ownerID == "" {
		return "", &credential.ExchangeError{
			Class: credential.ErrUnavailable, Detail: errNoOwner.Error(), Cause: errNoOwner,
		}
	}
	key := cacheKey{subject: claims.subject, owner: claims.ownerID, resource: resource}
	if issued, ok := s.lookup(key); ok {
		return issued, nil
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	response, err := s.request(ctx, token, claims.ownerID, resource)
	if err != nil {
		return "", err
	}
	s.store(key, response.AccessToken, response.ExpiresIn)
	return response.AccessToken, nil
}

// Describe names the zone and the mechanism. Nothing a request carries is
// in it.
func (s *AssertionSource) Describe() string {
	return s.describe
}

// request posts the grant the source is built for, with the assertion as
// its jwt-bearer client assertion and no client_id: the zone names the
// client by the assertion's subject.
func (s *AssertionSource) request(ctx context.Context, token, ownerID, resource string) (*oauth.TokenResponse, error) {
	var response *oauth.TokenResponse
	var err error
	switch {
	case s.owner != nil:
		response, err = s.owner.ExchangeToken(ctx, oauth.TokenExchangeRequest{
			Resource:            resource,
			SubjectToken:        substituteUserToken(ownerID),
			SubjectTokenType:    oauth.SubstituteUserTokenType,
			ClientAssertion:     token,
			ClientAssertionType: jwtBearer,
		})
	default:
		response, err = s.sandbox.RequestToken(ctx, oauth.ClientCredentialsRequest{
			Resource:            resource,
			ClientAssertion:     token,
			ClientAssertionType: jwtBearer,
		})
	}
	if err != nil {
		return nil, classify(err, refusedOnSubject)
	}
	return response, nil
}

// lookup returns the cached token for the key while it lives.
func (s *AssertionSource) lookup(key cacheKey) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[key]
	if !ok || !s.now().Before(entry.until) {
		return "", false
	}
	return entry.token, true
}

// store caches the token until its expiry less the margin. A response with
// no lifetime, or one inside the margin, is not cached. When the cache is
// full it drops the expired entries first, and keeps the token out when it
// is still full.
func (s *AssertionSource) store(key cacheKey, token string, expiresIn int) {
	lifetime := time.Duration(expiresIn) * time.Second
	if lifetime <= cacheMargin {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.cache) >= maxCached {
		for stale, entry := range s.cache {
			if !now.Before(entry.until) {
				delete(s.cache, stale)
			}
		}
	}
	if len(s.cache) >= maxCached {
		return
	}
	s.cache[key] = cached{token: token, until: now.Add(lifetime - cacheMargin)}
}

// refusedOnSubject reports whether an OAuth error code means the zone
// matched the assertion against its policy and said no. It covers the
// codes refusedOnPolicy covers and invalid_client.
func refusedOnSubject(code string) bool {
	return code == codeInvalidClient || refusedOnPolicy(code)
}

// assertionClaims is what the source reads from the token: the subject for
// the cache key, and the owner id the owner exchange acts for.
type assertionClaims struct {
	subject string
	ownerID string
}

// claimsOf reads the sub and owner_id claims. The proxy verified the token
// before the request reached a source, so the signature is not checked
// again here.
func claimsOf(token string) (assertionClaims, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return assertionClaims{}, fmt.Errorf("%w: %w", errClaims, err)
	}
	var standard jwt.Claims
	var private struct {
		OwnerID string `json:"owner_id"`
	}
	if err := parsed.UnsafeClaimsWithoutVerification(&standard, &private); err != nil {
		return assertionClaims{}, fmt.Errorf("%w: %w", errClaims, err)
	}
	if standard.Subject == "" {
		return assertionClaims{}, fmt.Errorf("%w: no sub claim", errClaims)
	}
	return assertionClaims{subject: standard.Subject, ownerID: private.OwnerID}, nil
}
