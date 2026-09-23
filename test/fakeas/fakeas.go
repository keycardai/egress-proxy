// Package fakeas is an authorization server fixture for unit and acceptance
// tests. It answers RFC 8414 discovery and the RFC 8693 token exchange that
// the proxy posts, applies the impersonation rule from the zone policy, and
// keeps every request for tests to read.
//
// It authenticates clients with client_secret_basic or a client assertion, and
// refuses a request that sends both.
package fakeas

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
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
}

// Request contains one token request as the server read it.
type Request struct {
	// Form contains the posted parameters. The client secret uses the
	// Authorization header, so it is not in this field.
	Form url.Values
	// ClientID is the authenticated client ID from basic credentials or the
	// client_id parameter.
	ClientID string
	// Actor is the subject of the client assertion. It is empty when the
	// request uses a client secret.
	Actor string
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
	if r.PostForm.Get("client_assertion_type") == assertionTypeJWTBearer {
		record.Actor = claimSub(r.PostForm.Get("client_assertion"))
	}

	value, refusal := s.issue(record, basicSecret)
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
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      value,
		"token_type":        "Bearer",
		"expires_in":        expiresIn,
		"issued_token_type": issuedTypeAccessToken,
	})
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
// and the resource grant before it returns the credential.
func (s *Server) issue(record Request, secret string) (string, *denial) {
	if refusal := s.authenticate(record, secret); refusal != nil {
		return "", refusal
	}
	if refusal := grantShape(record.Form); refusal != nil {
		return "", refusal
	}
	if record.Subject == "" {
		return "", &denial{
			status:      http.StatusBadRequest,
			Code:        codeInvalidGrant,
			Description: "the substitute-user token has no sub claim",
		}
	}
	if refusal := s.impersonation(record); refusal != nil {
		return "", refusal
	}
	resource := record.Form.Get("resource")
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

// impersonation applies the zone policy for user impersonation. A ServiceAccount
// can act only for the user in its name. A request with a client secret names
// no ServiceAccount, so this rule has nothing to check.
func (s *Server) impersonation(record Request) *denial {
	if record.Actor == "" {
		return nil
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

// authenticate accepts exactly one client authentication method. RFC 6749
// section 2.3 says a client must not use more than one in a request. An
// assertion names its client in client_id, because the token-federation
// credential identifies the client by that parameter and not by the assertion.
func (s *Server) authenticate(record Request, secret string) *denial {
	hasAssertion := record.Form.Get("client_assertion") != ""
	switch {
	case hasAssertion && record.HasBasic:
		return unknownClient("the request sends both a client assertion and basic credentials")
	case hasAssertion:
		if record.Actor == "" {
			return unknownClient("the client assertion has no sub claim")
		}
		if !slices.Contains(s.opts.AssertionClients, record.ClientID) {
			return unknownClient(record.ClientID + " may not authenticate with a client assertion")
		}
		return nil
	case record.HasBasic:
		if known, ok := s.opts.ClientSecrets[record.ClientID]; ok && known == secret {
			return nil
		}
		return unknownClient("the client secret is not the one this server holds")
	default:
		return unknownClient("the request authenticates with neither a client secret nor a client assertion")
	}
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
	parts := strings.Split(token, ".")
	if len(parts) != jwtSegments {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Sub
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
