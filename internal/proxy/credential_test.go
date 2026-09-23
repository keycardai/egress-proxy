package proxy_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mccutchen/go-httpbin/v2/httpbin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/policy"
)

// The credentials the static source holds, by resource.
//
//nolint:gosec // G101: test fixtures, not credentials
const (
	headerResource = "https://api.example/"
	headerSecret   = "header-sekrit"
	queryResource  = "https://maps.example/"
	querySecret    = "query-sekrit"
)

// queryPlacement puts the credential in the "key" parameter.
var queryPlacement = credential.Placement{ //nolint:gochecknoglobals // a fixture the tests share
	Kind: credential.KindQuery, Name: "key",
}

// credentialEndpoints is one endpoint per case the tests cover: each
// placement, an endpoint with no credential, a placement this build cannot
// write, and a resource the source does not hold.
func credentialEndpoints(port int) []policy.Endpoint {
	return []policy.Endpoint{
		{
			Host: upstreamHost, Port: port, PathPrefix: "/anything/header/",
			Resource: headerResource, Credential: &headerPlacement,
		},
		{
			Host: upstreamHost, Port: port, PathPrefix: "/anything/query/",
			Resource: queryResource, Credential: &queryPlacement,
		},
		{Host: upstreamHost, Port: port, PathPrefix: "/anything/plain/", Resource: headerResource},
		{
			Host: upstreamHost, Port: port, PathPrefix: "/anything/basic/", Resource: headerResource,
			Credential: &credential.Placement{Kind: credential.KindBasic, User: "x-access-token"},
		},
		{
			Host: upstreamHost, Port: port, PathPrefix: "/anything/unknown/",
			Resource: "https://nobody.example/", Credential: &headerPlacement,
		},
		{Host: upstreamHost, Port: port, PathPrefix: "/stall/", Resource: queryResource, Credential: &queryPlacement},
	}
}

// staticSource writes the credential file the proxy reads and loads it.
//
//nolint:ireturn // the harness takes the interface the proxy reads
func staticSource(t *testing.T) credential.Source {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	body := "version: 1\ncredentials:\n" +
		"  - resource: " + headerResource + "\n    value: " + headerSecret + "\n" +
		"  - resource: " + queryResource + "\n    value: " + querySecret + "\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600), "write the credential file")
	source, err := credential.LoadStaticFile(path)
	require.NoError(t, err, "LoadStaticFile")
	return source
}

// httpbinUpstream serves go-httpbin under /anything/, which reports the
// query parameters and headers that arrived, and a path that never answers.
func httpbinUpstream() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/anything/", httpbin.New())
	mux.HandleFunc("/stall/", func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	return mux
}

// byPath matches the request-scoped record for a path. Every case uses a
// path of its own, because an allowed response has no request id.
func byPath(path string) func(audit.Record) bool {
	return func(record audit.Record) bool {
		return record.Scope == audit.ScopeRequest && record.Request != nil && record.Request.Path == path
	}
}

// arrived is what go-httpbin reports about the request it received.
type arrived struct {
	Args    url.Values  `json:"args"`
	Headers http.Header `json:"headers"`
	URL     string      `json:"url"`
}

// fetch sends one request through the proxy with the headers the workload
// would send.
func fetch(t *testing.T, h *harness, target string, header http.Header) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	require.NoError(t, err)
	for name, values := range header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	//nolint:bodyclose // readReply closes it
	resp, err := h.client().Do(req)
	answer, err := readReply(t, resp, err)
	require.NoError(t, err, "GET %s", target)
	return answer
}

// TestCredentialInjection pins the bytes that leave for the upstream. The
// placement wins: the workload value is replaced, and the credential is
// written when the workload sent nothing.
func TestCredentialInjection(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{
		upstream: httpbinUpstream(), endpoints: credentialEndpoints, credentials: staticSource(t),
	})
	placeholder := http.Header{"Authorization": []string{"Bearer ${GITHUB_TOKEN}"}}
	tests := []struct {
		name   string
		path   string
		header http.Header
		// wantArgs is every query parameter the upstream received.
		wantArgs url.Values
		// wantAuthorization is every value the upstream received under that
		// header name.
		wantAuthorization []string
		// wantPrefix is the path prefix of the endpoint the record names.
		wantPrefix string
	}{
		{
			name: "a header the workload did not send", path: "/anything/header/absent",
			wantArgs: url.Values{}, wantAuthorization: []string{"Bearer " + headerSecret},
			wantPrefix: "/anything/header/",
		},
		{
			name: "a header the workload sent with its placeholder", path: "/anything/header/placeholder",
			header:   placeholder,
			wantArgs: url.Values{}, wantAuthorization: []string{"Bearer " + headerSecret},
			wantPrefix: "/anything/header/",
		},
		{
			name: "a header the workload sent twice", path: "/anything/header/twice",
			header:   http.Header{"Authorization": []string{"Bearer one", "Bearer two"}},
			wantArgs: url.Values{}, wantAuthorization: []string{"Bearer " + headerSecret},
			wantPrefix: "/anything/header/",
		},
		{
			name: "a workload naming the placement header in Connection", path: "/anything/header/hopbyhop",
			header: http.Header{
				"Authorization": []string{"Bearer ${GITHUB_TOKEN}"},
				"Connection":    []string{"Authorization"},
			},
			wantArgs: url.Values{}, wantAuthorization: []string{"Bearer " + headerSecret},
			wantPrefix: "/anything/header/",
		},
		{
			name: "a header placement leaves the query alone", path: "/anything/header/query?q=here",
			wantArgs: url.Values{"q": {"here"}}, wantAuthorization: []string{"Bearer " + headerSecret},
			wantPrefix: "/anything/header/",
		},
		{
			name: "a parameter the workload did not send", path: "/anything/query/absent",
			wantArgs: url.Values{"key": {querySecret}}, wantAuthorization: nil,
			wantPrefix: "/anything/query/",
		},
		{
			name: "a parameter beside the ones the workload sent", path: "/anything/query/beside?q=here&z=2",
			wantArgs:   url.Values{"key": {querySecret}, "q": {"here"}, "z": {"2"}},
			wantPrefix: "/anything/query/",
		},
		{
			name: "a parameter the workload sent", path: "/anything/query/present?key=placeholder",
			wantArgs: url.Values{"key": {querySecret}}, wantPrefix: "/anything/query/",
		},
		{
			name: "a parameter the workload sent twice", path: "/anything/query/twice?key=one&key=two",
			wantArgs: url.Values{"key": {querySecret}}, wantPrefix: "/anything/query/",
		},
		{
			name: "a query placement writes no header", path: "/anything/query/noheader",
			header:   placeholder,
			wantArgs: url.Values{"key": {querySecret}}, wantAuthorization: []string{"Bearer ${GITHUB_TOKEN}"},
			wantPrefix: "/anything/query/",
		},
		{
			name: "an endpoint naming no credential forwards what the workload sent",
			path: "/anything/plain/pypi?q=here", header: placeholder,
			wantArgs: url.Values{"q": {"here"}}, wantAuthorization: []string{"Bearer ${GITHUB_TOKEN}"},
			wantPrefix: "/anything/plain/",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			answer := fetch(t, h, h.upstreamURL(tc.path), tc.header)
			require.Equal(t, http.StatusOK, answer.status, "response status, body %s", answer.body)
			var got arrived
			require.NoError(t, json.Unmarshal([]byte(answer.body), &got), "decode %s", answer.body)
			assert.Equal(t, tc.wantArgs, got.Args, "the query the upstream received")
			assert.Equal(t, tc.wantAuthorization, got.Headers.Values("Authorization"),
				"the Authorization header the upstream received")
			wantPath, _, _ := strings.Cut(tc.path, "?")
			record := h.sink.find(t, tc.name, byPath(wantPath))
			assert.Equal(t, policy.VerdictAllow, record.Decision.Verdict, "record verdict")
			assert.Equal(t, h.upstreamAuthority()+tc.wantPrefix, record.Decision.Endpoint, "record endpoint")
			require.NotNil(t, record.Outcome, "the record names the outcome")
			assert.Equal(t, http.StatusOK, record.Outcome.Status, "record status")
		})
	}
}

// TestCredentialRefusals covers every way a credential can be missing. Each
// one denies, so a request never leaves with whatever the workload had
// at the placement.
func TestCredentialRefusals(t *testing.T) {
	t.Parallel()
	withSource := start(t, harnessOptions{
		upstream: httpbinUpstream(), endpoints: credentialEndpoints, credentials: staticSource(t),
	})
	withoutSource := start(t, harnessOptions{
		upstream: httpbinUpstream(), endpoints: credentialEndpoints,
	})
	tests := []struct {
		name    string
		harness *harness
		path    string
		wantErr string
		// prefix is the path prefix of the endpoint the record names.
		prefix string
	}{
		{
			name: "a process with no credential source", harness: withoutSource, path: "/anything/header/repos",
			wantErr: "no credential source", prefix: "/anything/header/",
		},
		{
			name: "a placement this build does not write", harness: withSource, path: "/anything/basic/repo.git",
			wantErr: "does not write a basic placement", prefix: "/anything/basic/",
		},
		{
			name: "a resource the source does not hold", harness: withSource, path: "/anything/unknown/thing",
			wantErr: "no credential for this resource", prefix: "/anything/unknown/",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			answer := fetch(t, tc.harness, tc.harness.upstreamURL(tc.path), nil)
			assert.Equal(t, http.StatusForbidden, answer.status, "response status")
			assert.Equal(t, policy.ReasonCredentialUnavailable, answer.reason(), "response reason")
			record := tc.harness.sink.find(t, tc.name, byRequest(answer.id()))
			assert.Equal(t, policy.VerdictDeny, record.Decision.Verdict, "record verdict")
			assert.Equal(t, policy.ReasonCredentialUnavailable, record.Decision.Reason, "record reason")
			assert.Equal(t, tc.harness.upstreamAuthority()+tc.prefix, record.Decision.Endpoint, "record endpoint")
			assert.Contains(t, record.Decision.Error, tc.wantErr, "record error")
			assert.Nil(t, record.Outcome, "a denied request has no outcome")
		})
	}
	t.Cleanup(func() {
		assert.Zero(t, withSource.upstream.connections.Load(), "a request without its credential reached the upstream")
	})
}

// TestNoCredentialReachesARecordOrALogLine reads the whole record and the
// whole log for three requests with a query placement: one the upstream
// answers, one whose upstream never answers, and one the proxy refuses. It
// proves that the record names the path without its query, that a failed
// forward says why it failed, and that neither the records nor the log hold
// the credential. The timeout text the stalled request produces names no
// URL, so this case does not reach the redaction path.
func TestNoCredentialReachesARecordOrALogLine(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{
		upstream: httpbinUpstream(), endpoints: credentialEndpoints, credentials: staticSource(t),
		responseHeaderTimeout: 100 * time.Millisecond,
	})
	answer := fetch(t, h, h.upstreamURL("/anything/query/geocode?q=here"), nil)
	require.Equal(t, http.StatusOK, answer.status, "the allowed request")
	allowed := h.sink.find(t, "the allowed request", byPath("/anything/query/geocode"))
	assert.Equal(t, "/anything/query/geocode", allowed.Request.Path, "the record names the path without its query")

	stalled := fetch(t, h, h.upstreamURL("/stall/forever?q=here"), nil)
	require.Equal(t, http.StatusBadGateway, stalled.status, "the stalled request")
	failed := h.sink.find(t, "the stalled request", byPath("/stall/forever"))
	require.NotNil(t, failed.Outcome, "the record names the outcome")
	assert.NotEmpty(t, failed.Outcome.Error, "the record says why the request failed")

	// A refused request is what puts a line in the log at all, so the
	// assertion below reads a log the proxy actually wrote.
	refused := fetch(t, h, h.upstreamURL("/anything/unknown/thing"), nil)
	require.Equal(t, http.StatusForbidden, refused.status, "the refused request")

	for _, record := range []audit.Record{allowed, failed} {
		line, err := json.Marshal(record)
		require.NoError(t, err, "marshal the record")
		assert.NotContains(t, string(line), querySecret, "an audit record holds the credential")
	}
	logged := h.logs.String()
	assert.NotContains(t, logged, querySecret, "a log line holds the credential")
	assert.Contains(t, logged, "refused a request", "the proxy logged nothing, so the assertion above proves nothing")
}

// errSomethingElse represents a source failure with no class.
var errSomethingElse = errors.New("something else")

// refusingSource reports one failure for every resource. It represents the
// exchange, whose failures use the same two classes for every zone response.
type refusingSource struct{ err error }

func (s refusingSource) Credential(context.Context, string) (string, error) { return "", s.err }

func (refusingSource) Describe() string { return "a source that refuses every resource" }

// TestASourceFailureClassIsItsDenialReason checks the mapping used by audit
// queries and error handling. A source reports the failure class, and the
// proxy does not read its message to choose a reason.
func TestASourceFailureClassIsItsDenialReason(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		err        error
		wantReason policy.Reason
		wantStatus int
	}{
		{
			name: "the zone's policy refused the exchange", err: credential.ErrExchangeDenied,
			wantReason: policy.ReasonExchangeDenied, wantStatus: http.StatusForbidden,
		},
		{
			name: "the exchange did not complete", err: credential.ErrExchangeFailed,
			// A dependency caused the failure, so a retry can succeed.
			wantReason: policy.ReasonExchangeFailed, wantStatus: http.StatusBadGateway,
		},
		{
			name: "the source holds nothing for the resource", err: credential.ErrUnavailable,
			wantReason: policy.ReasonCredentialUnavailable, wantStatus: http.StatusForbidden,
		},
		{
			name: "a failure in no class at all", err: errSomethingElse,
			wantReason: policy.ReasonCredentialUnavailable, wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := start(t, harnessOptions{
				upstream: httpbinUpstream(), endpoints: credentialEndpoints,
				credentials: refusingSource{err: fmt.Errorf("resource %s: %w", headerResource, tc.err)},
			})
			answer := fetch(t, h, h.upstreamURL("/anything/header/repos"), nil)
			assert.Equal(t, tc.wantStatus, answer.status, "response status")
			assert.Equal(t, tc.wantReason, answer.reason(), "response reason")

			record := h.sink.find(t, tc.name, byRequest(answer.id()))
			assert.Equal(t, policy.VerdictDeny, record.Decision.Verdict, "record verdict")
			assert.Equal(t, tc.wantReason, record.Decision.Reason, "record reason")
			assert.Zero(t, h.upstream.connections.Load(), "a request without its credential reached the upstream")
		})
	}
}
