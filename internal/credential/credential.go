// Package credential writes a credential into an outbound request at the
// place an endpoint names, and supplies the credential to write.
//
// The placement wins. The proxy replaces whatever value the workload sent at
// that place and writes the credential where the workload sent nothing.
//
// A credential never reaches a log line or an audit record. The proxy
// records a method, a path without its query, and a host, and it passes
// every other text through Redact before it writes it.
package credential

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// Token is what a header template holds where the credential goes.
const Token = "{credential}" //nolint:gosec // G101: a template token, not a credential

// Marker replaces a credential in text that reaches a log line or an audit
// record.
const Marker = "[redacted]"

// Kind is where in a request a credential goes.
type Kind string

// Placement kinds.
const (
	KindHeader Kind = "header"
	KindQuery  Kind = "query"
	KindBasic  Kind = "basic"
)

var (
	errPlacement = errors.New("placement")
	errQuery     = errors.New("query placement")
	errInvalid   = errors.New("invalid credential")
)

// These are the failures that a Source reports. Each one maps to a denial
// reason in internal/proxy, so callers do not need to read an error message.
var (
	// ErrUnavailable means that the source has no credential for the resource.
	ErrUnavailable = errors.New("no credential for this resource")
	// ErrExchangeDenied means that the authorization server refused the
	// exchange because its policy does not permit it. The refusal is
	// permanent, so a retry returns the same answer.
	ErrExchangeDenied = errors.New("the authorization server denied the exchange")
	// ErrExchangeFailed means that the exchange did not complete. The source
	// does not know whether the credential would have been granted.
	ErrExchangeFailed = errors.New("the token exchange failed")
)

// Placement is where the proxy writes a credential into a request. It is
// the `placement` object of an endpoint's credential.
type Placement struct {
	Kind Kind `json:"kind"`
	// Name is the header name of a header placement and the parameter name
	// of a query placement.
	Name string `json:"name"`
	// Template is the header value of a header placement, with Token where
	// the credential goes.
	Template string `json:"template"`
	// User is the user name of a basic placement. The credential is the
	// password.
	User string `json:"user"`
}

// Source supplies the credential for a resource.
type Source interface {
	// Credential returns the credential for the resource identifier an
	// endpoint names. It returns an error when it has none, which denies
	// the request with credential_unavailable.
	//
	// Implementations must not leak the secret in the error contents.
	Credential(ctx context.Context, resource string) (string, error)
	// Describe names the source for the start-up announcement and the admin
	// socket. It never includes a credential.
	Describe() string
}

// Writer puts a credential into an outbound request at one placement. A
// writer that reports an error leaves the request as it found it, and the
// proxy denies the request with credential_unavailable. Never forward a
// request whose write failed.
//
// Implementations must not leak the secret in the error contents.
type Writer interface {
	Write(out *http.Request, credential string) error
}

// BannedHeaderName reports whether a header placement cannot use name. The
// comparison ignores case. It bans hop-by-hop headers, Content-Length, Host,
// Forwarded, and the x-forwarded- and sec- families. Authorization is allowed.
func BannedHeaderName(name string) bool {
	switch lower := strings.ToLower(name); lower {
	case "connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade",
		"proxy-authenticate", "proxy-authorization", "content-length", "host", "forwarded":
		return true
	default:
		return strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "sec-")
	}
}

// NewWriter returns the writer for a placement. It refuses a placement this
// build cannot write, which denies the request with credential_unavailable.
//
//nolint:ireturn // polymorphism intended
func NewWriter(placement Placement) (Writer, error) {
	switch placement.Kind {
	case KindHeader:
		if !httpguts.ValidHeaderFieldName(placement.Name) {
			return nil, fmt.Errorf("%w: %q is not a header name", errPlacement, placement.Name)
		}
		if BannedHeaderName(placement.Name) {
			return nil, fmt.Errorf("%w: a header placement cannot name %q", errPlacement, placement.Name)
		}
		if !strings.Contains(placement.Template, Token) {
			return nil, fmt.Errorf("%w: the header template holds no %s", errPlacement, Token)
		}
		return headerWriter{name: placement.Name, template: placement.Template}, nil
	case KindQuery:
		if placement.Name == "" {
			return nil, fmt.Errorf("%w: the query placement names no parameter", errPlacement)
		}
		return queryWriter{name: placement.Name}, nil
	case KindBasic:
		return nil, fmt.Errorf("%w: this build does not write a %s placement", errPlacement, placement.Kind)
	default:
		return nil, fmt.Errorf("%w: %q is not a placement kind", errPlacement, placement.Kind)
	}
}

// headerWriter sets one header to the template with the credential in it.
type headerWriter struct {
	name     string
	template string
}

// Write replaces every value the workload sent under the header name.
func (w headerWriter) Write(out *http.Request, credential string) error {
	out.Header.Set(w.name, strings.ReplaceAll(w.template, Token, credential))
	return nil
}

// queryWriter sets one query parameter to the credential.
type queryWriter struct {
	name string
}

// Write replaces every value the workload sent under the parameter name.
// The query is re-encoded, so the request leaves with its parameters sorted
// by name.
//
// A query that does not parse is left as the workload sent it. Re-encoding
// one would drop the pairs that did not parse, and the request would reach
// the upstream shorter than it was written.
func (w queryWriter) Write(out *http.Request, credential string) error {
	values, err := url.ParseQuery(out.URL.RawQuery)
	if err != nil {
		return fmt.Errorf("%w: the request query does not parse: %w", errQuery, err)
	}
	values.Set(w.name, credential)
	out.URL.RawQuery = values.Encode()
	return nil
}

// Validate refuses a credential the proxy cannot put into a request. A
// control character in a header value splits the head, and an empty
// credential authenticates nothing.
func Validate(credential string) error {
	if credential == "" {
		return fmt.Errorf("%w: empty value", errInvalid)
	}
	if i := strings.IndexFunc(credential, isControl); i >= 0 {
		return fmt.Errorf("%w: contains an invalid character", errInvalid)
	}
	return nil
}

func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f
}

// Redact replaces every occurrence of the credential in text with Marker.
// A query placement percent-encodes the credential into the URL, so the
// escaped form is replaced as well as the raw one. An empty credential
// leaves the text alone.
func Redact(text, credential string) string {
	if credential == "" {
		return text
	}
	text = strings.ReplaceAll(text, credential, Marker)
	return strings.ReplaceAll(text, url.QueryEscape(credential), Marker)
}
