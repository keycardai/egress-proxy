// Package fakeas is an authorization server fixture for the tests and the
// acceptance lane. It answers RFC 8414 discovery and the RFC 8693 token
// exchange the proxy posts, and keeps every request for a test to read back.
//
// It authenticates a client with client_secret_basic, which is what this
// build of the proxy sends.
//
// It verifies no signature on anything, so it is a fixture and never a zone.
// The real zone is exercised by the cluster lane.
package fakeas

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// The paths the server serves. MetadataPath is where RFC 8414 discovery
// looks; TokenPath is what the metadata advertises.
const (
	MetadataPath = "/.well-known/oauth-authorization-server"
	TokenPath    = "/oauth2/token" //nolint:gosec // G101: a path, not a credential
)

// The wire values the exchange must send.
//
//nolint:gosec // G101: protocol URNs, not credentials
const (
	grantTokenExchange    = "urn:ietf:params:oauth:grant-type:token-exchange"
	subjectTypeSubstitute = "urn:keycard:params:oauth:token-type:substitute-user"
	issuedTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

// The RFC 6749 section 5.2 error codes this server answers with.
const (
	codeInvalidRequest   = "invalid_request"
	codeInvalidClient    = "invalid_client"
	codeInvalidGrant     = "invalid_grant"
	codeUnsupportedGrant = "unsupported_grant_type"
	codeAccessDenied     = "access_denied"
)

// expiresIn is the lifetime in seconds the server reports for every token it
// issues.
const expiresIn = 300

// jwtSegments is how many dot-separated segments a JWT has, the third empty
// for an unsigned one.
const jwtSegments = 3

// Options configures a Server.
type Options struct {
	// Credentials is the access token the server issues per resource. A
	// resource it omits is refused with access_denied, the way a zone
	// refuses a resource its policy does not grant.
	Credentials map[string]string
	// ClientSecrets is the secret per client id for client_secret_basic. A
	// server with none authenticates nobody.
	ClientSecrets map[string]string
}

// Request is one token request as the server read it.
type Request struct {
	// Form is the posted form, parameter by parameter. The client secret
	// rides in the Authorization header, so it is not in here.
	Form url.Values
	// ClientID is the client the request authenticated as, from the basic
	// credentials or the client_id parameter.
	ClientID string
	// Subject is the user the substitute-user token named.
	Subject string
	// Error is the OAuth error code the server answered with, empty on a
	// token.
	Error string
}

// Server answers discovery and the token endpoint.
type Server struct {
	opts Options

	mu       sync.Mutex
	requests []Request
}

// New builds a server. Mount it on any listener: it reads its issuer from
// the request, so it needs no address in advance.
func New(opts Options) *Server {
	return &Server{opts: opts}
}

// Requests returns every token request the server read, in order.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// ServeHTTP routes discovery and the token endpoint. Every other path is a
// 404, so a test that mistypes one sees it.
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

// metadata answers RFC 8414 discovery. The issuer must be what the client
// asked for, so it is built from the request rather than configured.
func (s *Server) metadata(w http.ResponseWriter, r *http.Request) {
	issuer := issuerOf(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"token_endpoint":                        issuer + TokenPath,
		"grant_types_supported":                 []string{grantTokenExchange},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
	})
}

// token answers the exchange. It records the request whatever the outcome,
// so a test can assert that a denied proxy request reached no exchange at
// all.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if refusal := requestShape(r); refusal != nil {
		writeDenial(w, *refusal)
		return
	}
	basicID, basicSecret, hasBasic := r.BasicAuth()
	record := Request{
		Form:     r.PostForm,
		ClientID: r.PostForm.Get("client_id"),
		Subject:  claimSub(r.PostForm.Get("subject_token")),
	}
	if hasBasic {
		record.ClientID = basicID
	}

	value, refusal := s.issue(record, basicSecret, hasBasic)
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

// requestShape refuses anything that is not a form POST, before the server
// records it. Nothing about such a request is worth reading back.
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

// issue applies client authentication, then the grant shape, then the
// resource grant, and returns the credential.
func (s *Server) issue(record Request, secret string, hasBasic bool) (string, *denial) {
	if refusal := s.authenticate(record, secret, hasBasic); refusal != nil {
		return "", refusal
	}
	if refusal := grantShape(record.Form); refusal != nil {
		return "", refusal
	}
	if record.Subject == "" {
		return "", &denial{
			status:      http.StatusBadRequest,
			Code:        codeInvalidGrant,
			Description: "the substitute-user token carries no sub",
		}
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

// authenticate accepts a client secret this server knows. Nothing in a
// secret names a ServiceAccount, so the server has nothing to bind the
// client to the user it asks to impersonate.
func (s *Server) authenticate(record Request, secret string, hasBasic bool) *denial {
	if hasBasic {
		if known, ok := s.opts.ClientSecrets[record.ClientID]; ok && known == secret {
			return nil
		}
	}
	return &denial{
		status:      http.StatusUnauthorized,
		Code:        codeInvalidClient,
		Description: "the request carries no client secret this server knows",
	}
}

// grantShape refuses a request that is not the impersonating exchange.
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
			Description: "a substitute-user exchange carries no actor_token",
		}
	}
	return nil
}

// denial is an RFC 6749 section 5.2 error response and the status it goes
// out with.
type denial struct {
	status      int
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// claimSub reads the sub claim from a JWT without verifying it. It returns
// an empty string for anything it cannot read, which the caller turns into a
// refusal.
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

// issuerOf reconstructs the URL the client asked discovery for.
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
