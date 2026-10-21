package proxy_test

import (
	"bufio"
	"context"
	"encoding/base64"
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
	"github.com/keycardai/egress-proxy/internal/proxy"
)

// The credentials the static source holds, by resource.
//
//nolint:gosec // G101: test fixtures, not credentials
const (
	headerResource = "https://api.example/"
	headerSecret   = "header-sekrit"
	queryResource  = "https://maps.example/"
	querySecret    = "query-sekrit"
	basicUser      = "x-access-token"
)

// queryPlacement puts the credential in the "key" parameter.
var queryPlacement = credential.Placement{ //nolint:gochecknoglobals // a fixture the tests share
	Kind: credential.KindQuery, Name: "key",
}

// basicPlacement puts the credential in Authorization as the password of
// basicUser, which is the user name a minted GitHub token arrives under.
var basicPlacement = credential.Placement{ //nolint:gochecknoglobals // a fixture the tests share
	Kind: credential.KindBasic, User: basicUser,
}

// basicAuthorization is the Authorization value basicPlacement writes for
// the credential the source holds for headerResource.
func basicAuthorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUser+":"+headerSecret))
}

// credentialEndpoints is one endpoint per case the tests cover: each
// placement, an endpoint with no credential, a placement the writer
// refuses, and a resource the source does not hold.
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
			Credential: &basicPlacement,
		},
		{
			Host: upstreamHost, Port: port, PathPrefix: "/anything/nouser/", Resource: headerResource,
			Credential: &credential.Placement{Kind: credential.KindBasic},
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
			name: "a basic placement the workload sent nothing for", path: "/anything/basic/clone",
			wantArgs: url.Values{}, wantAuthorization: []string{basicAuthorization()},
			wantPrefix: "/anything/basic/",
		},
		{
			name: "a basic placement over the credentials the workload sent", path: "/anything/basic/push",
			header: http.Header{"Authorization": []string{
				"Basic " + base64.StdEncoding.EncodeToString([]byte("alice:hunter2")),
			}},
			wantArgs: url.Values{}, wantAuthorization: []string{basicAuthorization()},
			wantPrefix: "/anything/basic/",
		},
		{
			name: "a basic placement over a bearer token the workload sent", path: "/anything/basic/bearer",
			header:   placeholder,
			wantArgs: url.Values{}, wantAuthorization: []string{basicAuthorization()},
			wantPrefix: "/anything/basic/",
		},
		{
			name: "a basic placement leaves the query alone", path: "/anything/basic/refs?service=git-upload-pack",
			wantArgs:          url.Values{"service": {"git-upload-pack"}},
			wantAuthorization: []string{basicAuthorization()},
			wantPrefix:        "/anything/basic/",
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
			name: "a basic placement naming no user", harness: withSource, path: "/anything/nouser/repo.git",
			wantErr: "the basic placement names no user", prefix: "/anything/nouser/",
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
// whole log for four requests: one with a query placement that the upstream
// answers, one with a basic placement that the upstream answers, one whose
// upstream never answers, and one the proxy refuses. It proves that the
// record names the path without its query, that a failed forward says why it
// failed, and that neither the records nor the log hold the credential in
// any form the placement puts on the wire. A basic placement sends base64 of
// the user, a colon and the credential, so the scan covers that form too.
// The timeout text of the stalled request does not include a URL, so that
// case does not reach the redaction path.
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

	basicAnswer := fetch(t, h, h.upstreamURL("/anything/basic/repo.git/info/refs?service=git-upload-pack"), nil)
	require.Equal(t, http.StatusOK, basicAnswer.status, "the basic placement request")
	basic := h.sink.find(t, "the basic placement request", byPath("/anything/basic/repo.git/info/refs"))
	assert.Equal(t, "/anything/basic/repo.git/info/refs", basic.Request.Path,
		"the record names the path without its query")

	stalled := fetch(t, h, h.upstreamURL("/stall/forever?q=here"), nil)
	require.Equal(t, http.StatusBadGateway, stalled.status, "the stalled request")
	failed := h.sink.find(t, "the stalled request", byPath("/stall/forever"))
	require.NotNil(t, failed.Outcome, "the record names the outcome")
	assert.NotEmpty(t, failed.Outcome.Error, "the record says why the request failed")

	// A refused request is what puts a line in the log at all, so the
	// assertion below reads a log the proxy actually wrote.
	refused := fetch(t, h, h.upstreamURL("/anything/unknown/thing"), nil)
	require.Equal(t, http.StatusForbidden, refused.status, "the refused request")

	// basicWire is the base64 the basic placement puts on the wire. The raw
	// credential does not appear in it, so a scan for headerSecret alone
	// would miss it.
	basicWire := base64.StdEncoding.EncodeToString([]byte(basicUser + ":" + headerSecret))
	for _, record := range []audit.Record{allowed, basic, failed} {
		line, err := json.Marshal(record)
		require.NoError(t, err, "marshal the record")
		assert.NotContains(t, string(line), querySecret, "an audit record holds the query credential")
		assert.NotContains(t, string(line), headerSecret, "an audit record holds the basic credential")
		assert.NotContains(t, string(line), basicWire, "an audit record holds the base64 the basic placement writes")
	}
	logged := h.logs.String()
	assert.NotContains(t, logged, querySecret, "a log line holds the query credential")
	assert.NotContains(t, logged, headerSecret, "a log line holds the basic credential")
	assert.NotContains(t, logged, basicWire, "a log line holds the base64 the basic placement writes")
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
// proxy does not read its message to choose a reason. A source that says
// why also carries that reason, which the refusal puts in the detail header
// and the log line, made safe for a header value.
func TestASourceFailureClassIsItsDenialReason(t *testing.T) {
	t.Parallel()
	const zoneProse = `Application "review-agent" is not allowed to access "GitHub API"`
	tests := []struct {
		name       string
		err        error
		wantReason policy.Reason
		wantStatus int
		// wantDetail is the detail header and the log field. Empty means
		// the refusal carries neither.
		wantDetail string
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
			name:       "the zone's policy refused the exchange and said why",
			err:        &credential.ExchangeError{Class: credential.ErrExchangeDenied, Detail: zoneProse},
			wantReason: policy.ReasonExchangeDenied, wantStatus: http.StatusForbidden,
			wantDetail: zoneProse,
		},
		{
			name:       "the exchange did not complete and the class is known",
			err:        &credential.ExchangeError{Class: credential.ErrExchangeFailed, Detail: "the zone answered 502"},
			wantReason: policy.ReasonExchangeFailed, wantStatus: http.StatusBadGateway,
			wantDetail: "the zone answered 502",
		},
		{
			name: "the zone's reason holds control characters",
			err: &credential.ExchangeError{
				Class: credential.ErrExchangeDenied, Detail: "no grant\r\nX-Injected: 1\x00\x7f",
			},
			wantReason: policy.ReasonExchangeDenied, wantStatus: http.StatusForbidden,
			wantDetail: "no grantX-Injected: 1",
		},
		{
			name:       "the zone's reason is longer than the cap",
			err:        &credential.ExchangeError{Class: credential.ErrExchangeDenied, Detail: strings.Repeat("a", 600)},
			wantReason: policy.ReasonExchangeDenied, wantStatus: http.StatusForbidden,
			wantDetail: strings.Repeat("a", 512),
		},
		{
			name: "the source holds nothing for the resource", err: credential.ErrUnavailable,
			wantReason: policy.ReasonCredentialUnavailable, wantStatus: http.StatusForbidden,
		},
		{
			name:       "the source made no exchange and said why",
			err:        &credential.ExchangeError{Class: credential.ErrUnavailable, Detail: "the assertion names no owner"},
			wantReason: policy.ReasonCredentialUnavailable, wantStatus: http.StatusForbidden,
			wantDetail: "the assertion names no owner",
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

			logged := h.logs.String()
			require.Contains(t, logged, "refused a request", "the refusal is logged")
			// The body carries the same detail as the header, or none, so
			// the body can hold nothing the header redaction removed.
			assert.Equal(t, "application/problem+json", answer.header.Get("Content-Type"), "the refusal content type")
			var problem map[string]any
			require.NoError(t, json.Unmarshal([]byte(answer.body), &problem), "the refusal body parses as JSON")
			assert.Equal(t, string(tc.wantReason), problem["reason"], "the reason in the body")
			assert.Equal(t, "urn:keycard:request:"+answer.id(), problem["instance"], "the instance in the body")
			if tc.wantDetail == "" {
				assert.Empty(t, answer.header.Values(proxy.HeaderDetail), "a refusal with no detail sets no header")
				assert.NotContains(t, problem, "detail", "a refusal with no detail has no detail member")
				assert.NotContains(t, logged, `"detail":`, "a refusal with no detail logs none")
				return
			}
			assert.Equal(t, []string{tc.wantDetail}, answer.header.Values(proxy.HeaderDetail), "the detail header")
			assert.Equal(t, tc.wantDetail, problem["detail"], "the detail in the body")
			encoded, err := json.Marshal(tc.wantDetail)
			require.NoError(t, err, "encode the detail")
			assert.Contains(t, logged, `"detail":`+string(encoded), "the log line carries the detail")
			assert.Contains(t, record.Decision.Error, tc.err.Error(), "the record keeps the full error")
		})
	}
}

// TestUserinfoInTheRequestLineNeverReachesTheUpstream drives an
// absolute-form request line with userinfo in it, which is the only shape
// that can put userinfo in front of the proxy. The outbound request line is
// origin form, so no placement forwards the userinfo. The test checks the
// URL and the Authorization header the upstream received, and the path in
// the record.
func TestUserinfoInTheRequestLineNeverReachesTheUpstream(t *testing.T) {
	t.Parallel()
	h := start(t, harnessOptions{
		upstream: httpbinUpstream(), endpoints: credentialEndpoints, credentials: staticSource(t),
	})
	tests := []struct {
		name              string
		path              string
		userinfo          string
		wantAuthorization []string
	}{
		{
			name: "a basic placement and a user", path: "/anything/basic/user",
			userinfo: "alice@", wantAuthorization: []string{basicAuthorization()},
		},
		{
			name: "a basic placement, a user and a password", path: "/anything/basic/userpass",
			userinfo: "alice:hunter2@", wantAuthorization: []string{basicAuthorization()},
		},
		{
			name: "a header placement, a user and a password", path: "/anything/header/userpass",
			userinfo: "alice:hunter2@", wantAuthorization: []string{"Bearer " + headerSecret},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn, err := h.tlsTunnel(t, upstreamHost)
			require.NoError(t, err, "open a tunnel")
			authority := h.upstreamAuthority()
			answer := h.roundTrip(t, conn, bufio.NewReader(conn),
				"GET https://"+tc.userinfo+authority+tc.path+" HTTP/1.1\r\nHost: "+authority+
					"\r\nConnection: close\r\n\r\n")
			require.Equal(t, http.StatusOK, answer.status, "response status, body %s", answer.body)
			var got arrived
			require.NoError(t, json.Unmarshal([]byte(answer.body), &got), "decode %s", answer.body)
			assert.Equal(t, tc.wantAuthorization, got.Headers.Values("Authorization"),
				"the Authorization header the upstream received")
			assert.Contains(t, got.URL, tc.path, "the URL the upstream reports")
			assert.NotContains(t, got.URL, "alice", "the user the workload put in the request line")
			assert.NotContains(t, got.URL, "hunter2", "the password the workload put in the request line")
			record := h.sink.find(t, tc.name, byPath(tc.path))
			assert.Equal(t, policy.VerdictAllow, record.Decision.Verdict, "record verdict")
			assert.NotContains(t, record.Request.Path, "alice", "the record holds the userinfo")
		})
	}
}
