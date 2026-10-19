// Package fakeas is an authorization server fixture for the unit, acceptance
// and e2e tests. It answers RFC 8414 discovery and the RFC 8693 token exchange
// that the proxy posts, applies the impersonation rule from the zone policy,
// and keeps every request for tests to read.
//
// It authenticates clients with client_secret_basic or a client assertion, and
// refuses a request that sends both. It verifies each client assertion with
// Options.Assertions. It never verifies the substitute-user token, which is
// unsigned.
//
// It also answers the grants a sandbox assertion authenticates, the way the
// Keycard STS does: it discovers the assertion's issuer, verifies ES256
// against the published key, and matches the subject against
// Options.WorkloadSubjects. That is the client_credentials grant for the
// sandbox itself, and the token exchange for a user in
// Options.ImpersonableUsers.
package fakeas

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

// MetadataPath is the RFC 8414 discovery path. TokenPath is the path that the
// metadata advertises.
const (
	MetadataPath = "/.well-known/oauth-authorization-server"
	TokenPath    = "/oauth2/token" //nolint:gosec // G101: a path, not a credential
)

// These are the wire values that the exchange sends.
//
//nolint:gosec // G101: protocol URNs, not credentials
const (
	grantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	grantClientCredentials = "client_credentials"
	subjectTypeSubstitute  = "urn:keycard:params:oauth:token-type:substitute-user"
	assertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	issuedTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
)

// These are the RFC 6749 section 5.2 error codes that the server returns.
const (
	codeInvalidRequest   = "invalid_request"
	codeInvalidClient    = "invalid_client"
	codeInvalidGrant     = "invalid_grant"
	codeUnsupportedGrant = "unsupported_grant_type"
	codeAccessDenied     = "access_denied"
)

// expiresIn is the token lifetime in seconds.
const expiresIn = 300

// jwtSegments is the number of dot-separated JWT segments. The third segment
// is empty for an unsigned token.
const jwtSegments = 3

// defaultNamespace is the ServiceAccount namespace that the impersonation
// rule uses when Options does not set one.
const defaultNamespace = "agents"

// Options configures a Server.
type Options struct {
	// Credentials maps each resource to the access token that the server issues.
	// The server returns access_denied for an unmapped resource.
	Credentials map[string]string
	// Namespace is the ServiceAccount namespace that the impersonation rule uses.
	// The default is "agents".
	Namespace string
	// ClientSecrets maps each client ID to its client_secret_basic secret. An
	// empty map accepts no client secret.
	ClientSecrets map[string]string
	// AssertionClients lists the client IDs that may authenticate with a client
	// assertion. An empty slice accepts no assertion.
	AssertionClients []string
	// Assertions checks the signature, issuer, audience and expiry of each
	// client assertion. When it is nil, the server refuses every assertion.
	Assertions *oidc.IDTokenVerifier
	// WorkloadSubjects maps a subject pattern, exact or with a trailing
	// asterisk, to the application a client_credentials assertion with a
	// matching subject acts as. An empty map accepts no such grant.
	WorkloadSubjects map[string]string
	// ImpersonableUsers lists the users an application a WorkloadSubjects
	// pattern names may act for in a token exchange. An empty slice lets
	// such an application act for no one.
	ImpersonableUsers []string
	// IssuerHTTPClient fetches discovery and the key set from an
	// assertion's issuer. Nil selects http.DefaultClient.
	IssuerHTTPClient *http.Client
}

// Request contains one token request as the server read it.
type Request struct {
	// Form contains the posted parameters. The client secret uses the
	// Authorization header, so it is not in this field.
	Form url.Values
	// ClientID is the authenticated client ID from basic credentials or the
	// client_id parameter.
	ClientID string
	// Actor is the verified subject of the client assertion. It is empty when
	// the request uses a client secret or the server refused the assertion.
	Actor string
	// Application is the application a WorkloadSubjects pattern matched the
	// actor to. It is empty for every other client.
	Application string
	// HasBasic reports whether the request sent an Authorization header with
	// basic credentials.
	HasBasic bool
	// Subject is the user named by the substitute-user token.
	Subject string
	// Error is the OAuth error code that the server returned. It is empty for a
	// successful token response.
	Error string
}

// Server answers discovery and token requests.
type Server struct {
	opts Options

	mu       sync.Mutex
	requests []Request
}

// New builds a server. Mount it on any listener. The server reads its issuer
// from each request, so it needs no address in advance.
func New(opts Options) *Server {
	if opts.Namespace == "" {
		opts.Namespace = defaultNamespace
	}
	return &Server{opts: opts}
}

// Requests returns the token requests in the order that the server read them.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// LogExchanges wraps a server and writes one line per token request it
// read, in the order the server read them. A test counts the exchanges an
// allowed request made and reads back which user and resource the zone was
// asked for.
//
// The line NEVER holds the issued credential or the client secret.
func LogExchanges(zone *Server, log io.Writer) http.Handler {
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen := len(zone.Requests())
		zone.ServeHTTP(w, r)
		for _, request := range zone.Requests()[seen:] {
			fmt.Fprintf(log, "exchange client=%s actor=%q subject=%s resource=%s error=%q\n",
				request.ClientID, request.Actor, request.Subject, request.Form.Get("resource"), request.Error)
		}
	})
}

// ServeHTTP routes discovery and token requests. It returns 404 for every
// other path.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case MetadataPath:
		s.metadata(w, r)
	case TokenPath:
		s.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

// metadata answers RFC 8414 discovery. It builds the issuer from the request
// so the issuer matches the URL that the client requested.
func (s *Server) metadata(w http.ResponseWriter, r *http.Request) {
	issuer := issuerOf(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"token_endpoint":                        issuer + TokenPath,
		"grant_types_supported":                 []string{grantTokenExchange},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "private_key_jwt"},
	})
}

// token answers the exchange and records every request. A test can confirm
// that a denied proxy request reached no exchange.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if refusal := requestShape(r); refusal != nil {
		writeDenial(w, *refusal)
		return
	}
	basicID, basicSecret, hasBasic := r.BasicAuth()
	record := Request{
		Form:     r.PostForm,
		ClientID: r.PostForm.Get("client_id"),
		HasBasic: hasBasic,
		Subject:  claimSub(r.PostForm.Get("subject_token")),
	}
	if hasBasic {
		record.ClientID = basicID
	}

	response := map[string]any{"token_type": "Bearer", "expires_in": expiresIn}
	var refusal *denial
	switch r.PostForm.Get("grant_type") {
	case grantClientCredentials:
		refusal = s.workload(r.Context(), &record, hasBasic, response)
	default:
		var value string
		value, refusal = s.issue(r.Context(), &record, basicSecret)
		response["access_token"] = value
		response["issued_token_type"] = issuedTypeAccessToken
	}
	if refusal != nil {
		record.Error = refusal.Code
	}
	s.mu.Lock()
	s.requests = append(s.requests, record)
	s.mu.Unlock()

	if refusal != nil {
		writeDenial(w, *refusal)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// workload answers the client_credentials grant a sandbox assertion
// authenticates. It fills the response with the access token and the
// client, which is the assertion's subject, and sets record.Actor to that
// subject. The token is the matched application's name and the resource's
// credential joined by a colon, so a test reads which application the zone
// matched from what reached the upstream.
func (s *Server) workload(ctx context.Context, record *Request, hasBasic bool, response map[string]any) *denial {
	subject, refusal := s.workloadClient(ctx, *record, hasBasic)
	if refusal != nil {
		return refusal
	}
	record.Actor = subject
	application, ok := s.matchSubject(subject)
	if !ok {
		return unknownClient("no application credential matches " + subject)
	}
	record.Application = application
	value, refusal := s.grant(record.Form.Get("resource"))
	if refusal != nil {
		return refusal
	}
	response["access_token"] = application + ":" + value
	response["client_id"] = subject
	return nil
}

// grant is the credential the policy grants for the resource.
func (s *Server) grant(resource string) (string, *denial) {
	value, granted := s.opts.Credentials[resource]
	if !granted {
		return "", &denial{
			status:      http.StatusForbidden,
			Code:        codeAccessDenied,
			Description: "no policy grants " + resource,
		}
	}
	return value, nil
}

// workloadClient checks the shape of the grant and verifies its assertion.
// The grant sends no client_id and no basic credentials: the assertion's
// subject names the client.
func (s *Server) workloadClient(ctx context.Context, record Request, hasBasic bool) (string, *denial) {
	assertion := record.Form.Get("client_assertion")
	switch {
	case assertion == "":
		return "", unknownClient("the client_credentials grant sends no client assertion")
	case record.Form.Get("client_assertion_type") != assertionTypeJWTBearer:
		return "", unknownClient("the client assertion type is not " + assertionTypeJWTBearer)
	case record.ClientID != "" || hasBasic:
		return "", &denial{
			status:      http.StatusBadRequest,
			Code:        codeInvalidRequest,
			Description: "a client assertion names its client by its subject and sends no client_id",
		}
	}
	return s.verifyWorkload(ctx, assertion)
}

// verifyWorkload verifies the assertion the way the STS does: the
// assertion's own iss is discovered, the key is found by kid in that
// issuer's key set, the signature must be ES256, exp must be in the future
// and iat present, and sub must differ from iss.
func (s *Server) verifyWorkload(ctx context.Context, assertion string) (string, *denial) {
	issuer := unverified(assertion).Iss
	if issuer == "" {
		return "", unknownClient("the client assertion has no iss claim")
	}
	if s.opts.IssuerHTTPClient != nil {
		ctx = oidc.ClientContext(ctx, s.opts.IssuerHTTPClient)
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return "", unknownClient("the issuer does not discover: " + err.Error())
	}
	verifier := provider.VerifierContext(ctx, &oidc.Config{
		SkipClientIDCheck: true, SupportedSigningAlgs: []string{oidc.ES256},
	})
	token, err := verifier.Verify(ctx, assertion)
	switch {
	case err != nil:
		return "", unknownClient("the client assertion does not verify: " + err.Error())
	case token.IssuedAt.IsZero():
		return "", unknownClient("the client assertion has no iat claim")
	case token.Subject == "" || token.Subject == token.Issuer:
		return "", unknownClient("the client assertion's sub must be set and differ from iss")
	}
	return token.Subject, nil
}

// matchSubject finds the application whose pattern covers the subject. A
// pattern is exact, or a prefix when it ends in an asterisk.
func (s *Server) matchSubject(subject string) (string, bool) {
	for pattern, application := range s.opts.WorkloadSubjects {
		if prefix, ok := strings.CutSuffix(pattern, "*"); ok && strings.HasPrefix(subject, prefix) {
			return application, true
		}
		if pattern == subject {
			return application, true
		}
	}
	return "", false
}

// requestShape rejects anything other than a form POST before the server
// records it. The server does not retain those requests.
func requestShape(r *http.Request) *denial {
	if r.Method != http.MethodPost {
		return &denial{
			status:      http.StatusMethodNotAllowed,
			Code:        codeInvalidRequest,
			Description: "the token endpoint takes a POST",
		}
	}
	if err := r.ParseForm(); err != nil {
		return &denial{
			status:      http.StatusBadRequest,
			Code:        codeInvalidRequest,
			Description: "the form does not parse",
		}
	}
	return nil
}

// issue checks client authentication, the grant shape, the impersonation rule,
// and the resource grant before it returns the credential. It sets
// record.Actor to the subject of a verified assertion. The token names the
// application where a sandbox assertion authenticated the exchange, so a
// test reads which application the zone matched from what reached the
// upstream.
func (s *Server) issue(ctx context.Context, record *Request, secret string) (string, *denial) {
	actor, refusal := s.authenticate(ctx, record, secret)
	record.Actor = actor
	if refusal != nil {
		return "", refusal
	}
	if refused := grantShape(record.Form); refused != nil {
		return "", refused
	}
	if record.Subject == "" {
		return "", &denial{
			status:      http.StatusBadRequest,
			Code:        codeInvalidGrant,
			Description: "the substitute-user token has no sub claim",
		}
	}
	if refused := s.impersonation(*record); refused != nil {
		return "", refused
	}
	value, refusal := s.grant(record.Form.Get("resource"))
	if refusal != nil {
		return "", refusal
	}
	if record.Application != "" {
		return record.Application + ":" + value, nil
	}
	return value, nil
}

// impersonation applies the zone policy for user impersonation. A sandbox
// application can act for the users ImpersonableUsers lists. A
// ServiceAccount can act only for the user in its name. A request with a
// client secret names no ServiceAccount, so this rule has nothing to check.
func (s *Server) impersonation(record Request) *denial {
	switch {
	case record.Actor == "":
		return nil
	case record.Application != "":
		if slices.Contains(s.opts.ImpersonableUsers, record.Subject) {
			return nil
		}
		return &denial{
			status:      http.StatusForbidden,
			Code:        codeAccessDenied,
			Description: record.Actor + " cannot act for " + record.Subject,
		}
	}
	want := "system:serviceaccount:" + s.opts.Namespace + ":" + record.Subject
	if record.Actor != want {
		return &denial{
			status:      http.StatusForbidden,
			Code:        codeAccessDenied,
			Description: record.Actor + " cannot act for " + record.Subject,
		}
	}
	return nil
}

// authenticate accepts exactly one client authentication method and returns
// the subject of a verified assertion. RFC 6749 section 2.3 says a client
// must not use more than one in a request.
func (s *Server) authenticate(ctx context.Context, record *Request, secret string) (string, *denial) {
	assertion := record.Form.Get("client_assertion")
	switch {
	case assertion != "" && record.HasBasic:
		return "", unknownClient("the request sends both a client assertion and basic credentials")
	case assertion != "":
		return s.assertionClient(ctx, record, assertion)
	case record.HasBasic:
		if known, ok := s.opts.ClientSecrets[record.ClientID]; ok && known == secret {
			return "", nil
		}
		return "", unknownClient("the client secret is not the one this server holds")
	default:
		return "", unknownClient("the request authenticates with neither a client secret nor a client assertion")
	}
}

// assertionClient checks that the client may authenticate with an assertion,
// verifies the assertion, and returns its subject. An assertion names its
// client in client_id, because the token-federation credential identifies the
// client by that parameter and not by the assertion. A server that knows
// subject patterns names the client of an assertion without client_id by
// its subject instead, the way the client_credentials grant does.
func (s *Server) assertionClient(ctx context.Context, record *Request, assertion string) (string, *denial) {
	switch {
	case record.Form.Get("client_assertion_type") != assertionTypeJWTBearer:
		return "", unknownClient("the client assertion type is not " + assertionTypeJWTBearer)
	case record.ClientID == "" && len(s.opts.WorkloadSubjects) > 0:
		return s.sandboxClient(ctx, record, assertion)
	case record.ClientID == "":
		return "", unknownClient("the client assertion sends no client_id")
	case !slices.Contains(s.opts.AssertionClients, record.ClientID):
		return "", unknownClient(record.ClientID + " may not authenticate with a client assertion")
	case s.opts.Assertions == nil:
		return "", unknownClient("this server has no assertion verifier, so it accepts no assertion")
	}
	token, err := s.opts.Assertions.Verify(ctx, assertion)
	if err != nil {
		return "", unknownClient("the client assertion does not verify: " + err.Error())
	}
	if token.Subject == "" {
		return "", unknownClient("the client assertion has no sub claim")
	}
	return token.Subject, nil
}

// sandboxClient verifies a sandbox assertion the way verifyWorkload does,
// matches its subject against the patterns, and records the application it
// matched. The subject is returned with a refusal too, so the record names
// the sandbox the server turned away.
func (s *Server) sandboxClient(ctx context.Context, record *Request, assertion string) (string, *denial) {
	subject, refusal := s.verifyWorkload(ctx, assertion)
	if refusal != nil {
		return "", refusal
	}
	application, ok := s.matchSubject(subject)
	if !ok {
		return subject, unknownClient("no application credential matches " + subject)
	}
	record.Application = application
	return subject, nil
}

// unknownClient is the RFC 6749 section 5.2 answer to a client that did not
// authenticate.
func unknownClient(description string) *denial {
	return &denial{
		status:      http.StatusUnauthorized,
		Code:        codeInvalidClient,
		Description: description,
	}
}

// grantShape rejects a request that is not an impersonating exchange.
func grantShape(form url.Values) *denial {
	if form.Get("grant_type") != grantTokenExchange {
		return &denial{
			status:      http.StatusBadRequest,
			Code:        codeUnsupportedGrant,
			Description: "this server serves the token-exchange grant",
		}
	}
	if form.Get("subject_token_type") != subjectTypeSubstitute {
		return &denial{
			status:      http.StatusBadRequest,
			Code:        codeInvalidRequest,
			Description: "this server serves the substitute-user subject token type",
		}
	}
	if form.Get("actor_token") != "" {
		return &denial{
			status:      http.StatusBadRequest,
			Code:        codeInvalidRequest,
			Description: "a substitute-user exchange sends no actor_token",
		}
	}
	return nil
}

// denial is an RFC 6749 section 5.2 error response and its HTTP status.
type denial struct {
	status      int
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// claimSub reads the sub claim from a JWT without verifying the signature. It
// returns an empty string when it cannot read the claim.
func claimSub(token string) string {
	return unverified(token).Sub
}

// payload is what unverified reads from a JWT.
type payload struct {
	Sub string `json:"sub"`
	Iss string `json:"iss"`
}

// unverified decodes the payload of a JWT without checking the signature.
// It returns the zero value when the token does not decode.
func unverified(token string) payload {
	parts := strings.Split(token, ".")
	if len(parts) != jwtSegments {
		return payload{}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return payload{}
	}
	var claims payload
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return payload{}
	}
	return claims
}

// issuerOf reconstructs the URL that the client requested for discovery.
func issuerOf(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func writeDenial(w http.ResponseWriter, refusal denial) {
	writeJSON(w, refusal.status, refusal)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "encode the response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}
