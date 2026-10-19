package credential_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/credential"
)

//nolint:gosec // G101: test fixtures, not credentials
const (
	secret = "sekrit-token"
	// escapedSecret holds the three characters Validate permits and
	// url.Values.Encode rewrites: a space becomes "+", "=" becomes "%3D",
	// and "+" becomes "%2B".
	escapedSecret = "a b=c+d"
	escapedForm   = "a+b%3Dc%2Bd"
	// basicUser is the user name GitHub expects a minted token to arrive
	// under, and the user every basic case here names.
	basicUser = "x-access-token"
	// workloadPassword is what a workload puts in a clone URL. It must not
	// reach the outbound request line or the Authorization header.
	workloadPassword = "hunter2"
)

// basicHeader is the Authorization value a basic placement for basicUser
// writes for a credential.
func basicHeader(user, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+secret))
}

// request builds an outbound request the way the reverse proxy hands one to
// the rewrite: a target with its query, and the headers the workload sent.
func request(t *testing.T, target string, header http.Header) *http.Request {
	t.Helper()
	parsed, err := url.Parse(target)
	require.NoError(t, err, "parse %s", target)
	if header == nil {
		header = http.Header{}
	}
	return &http.Request{Method: http.MethodGet, URL: parsed, Header: header}
}

// TestWriterReplacesWhatTheWorkloadSent pins the outbound request for each
// placement. The placement wins: a value the workload sent there is replaced,
// and one it did not send is written.
func TestWriterReplacesWhatTheWorkloadSent(t *testing.T) {
	t.Parallel()
	header := credential.Placement{
		Kind: credential.KindHeader, Name: "Authorization", Template: "Bearer " + credential.Token,
	}
	query := credential.Placement{Kind: credential.KindQuery, Name: "key"}
	basic := credential.Placement{Kind: credential.KindBasic, User: basicUser}
	tests := []struct {
		name      string
		placement credential.Placement
		target    string
		header    http.Header
		wantQuery string
		// wantUserinfo is the userinfo left on the outbound request line.
		// It is empty in every case. Only the basic cases send userinfo, and
		// the basic writer removes it.
		wantUserinfo string
		// wantHeader is the whole outbound value list under the placement
		// name, or under checkHeader when the placement writes no header.
		checkHeader string
		wantHeader  []string
		// wantErr is what Write reports when it cannot write the
		// credential. The request then goes on unchanged.
		wantErr string
	}{
		{
			name: "a header the workload did not send", placement: header, target: "/repos",
			wantHeader: []string{"Bearer " + secret},
		},
		{
			name: "a header the workload sent with its placeholder", placement: header, target: "/repos",
			header:     http.Header{"Authorization": []string{"Bearer ${GITHUB_TOKEN}"}},
			wantHeader: []string{"Bearer " + secret},
		},
		{
			name: "a header the workload sent twice", placement: header, target: "/repos",
			header:     http.Header{"Authorization": []string{"Bearer one", "Bearer two"}},
			wantHeader: []string{"Bearer " + secret},
		},
		{
			name: "a header name in another case", placement: header, target: "/repos",
			header:     http.Header{"authorization": []string{"Bearer one"}},
			wantHeader: []string{"Bearer " + secret},
		},
		{
			name: "a header placement leaves every other header alone", placement: header, target: "/repos",
			header:      http.Header{"Accept": []string{"application/json"}},
			checkHeader: "Accept", wantHeader: []string{"application/json"},
		},
		{
			name: "a parameter the workload did not send", placement: query, target: "/geocode",
			wantQuery: "key=" + secret,
		},
		{
			name: "a parameter beside the ones the workload sent", placement: query, target: "/geocode?q=here&z=2",
			wantQuery: "key=" + secret + "&q=here&z=2",
		},
		{
			name: "a parameter the workload sent", placement: query, target: "/geocode?key=placeholder&q=here",
			wantQuery: "key=" + secret + "&q=here",
		},
		{
			name: "a parameter the workload sent twice", placement: query, target: "/geocode?key=one&key=two",
			wantQuery: "key=" + secret,
		},
		{
			name: "a query placement writes no header", placement: query, target: "/geocode",
			header:      http.Header{"Authorization": []string{"Bearer placeholder"}},
			wantQuery:   "key=" + secret,
			checkHeader: "Authorization", wantHeader: []string{"Bearer placeholder"},
		},
		{
			name: "a basic placement the workload sent nothing for", placement: basic,
			target:      "/repo.git/info/refs?service=git-upload-pack",
			wantQuery:   "service=git-upload-pack",
			checkHeader: "Authorization", wantHeader: []string{basicHeader(basicUser, secret)},
		},
		{
			name: "a basic placement over the Authorization the workload sent", placement: basic,
			target:      "/repo.git/git-receive-pack",
			header:      http.Header{"Authorization": []string{basicHeader("someone", "their-password")}},
			checkHeader: "Authorization", wantHeader: []string{basicHeader(basicUser, secret)},
		},
		{
			name: "a request line naming a user", placement: basic,
			target:      "https://alice@git.example/repo.git",
			checkHeader: "Authorization", wantHeader: []string{basicHeader(basicUser, secret)},
		},
		{
			name: "a request line naming a user and a password", placement: basic,
			target:      "https://alice:" + workloadPassword + "@git.example/repo.git",
			checkHeader: "Authorization", wantHeader: []string{basicHeader(basicUser, secret)},
		},
		{
			name: "a basic placement leaves every other header alone", placement: basic,
			target:      "/repo.git/info/refs",
			header:      http.Header{"Accept": []string{"application/x-git-upload-pack-advertisement"}},
			checkHeader: "Accept", wantHeader: []string{"application/x-git-upload-pack-advertisement"},
		},
		{
			name:      "a query that does not parse keeps the bytes the workload sent",
			placement: query, target: "/geocode?q=here&bad=%zz",
			wantQuery: "q=here&bad=%zz", wantErr: "the request query does not parse",
		},
		{
			name:      "a query with a semicolon separator, which is not a separator",
			placement: query, target: "/geocode?a=1;b=2",
			wantQuery: "a=1;b=2", wantErr: "the request query does not parse",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer, err := credential.NewWriter(tc.placement)
			require.NoError(t, err, "NewWriter")
			out := request(t, tc.target, tc.header)
			err = writer.Write(out, secret)
			if tc.wantErr == "" {
				require.NoError(t, err, "Write")
			} else {
				require.ErrorContains(t, err, tc.wantErr, "Write")
				assert.NotContains(t, err.Error(), secret, "the message quotes the credential")
			}
			assert.Equal(t, tc.wantQuery, out.URL.RawQuery, "the outbound query")
			var userinfo string
			if out.URL.User != nil {
				userinfo = out.URL.User.String()
			}
			assert.Equal(t, tc.wantUserinfo, userinfo, "the userinfo on the outbound request line")
			name := tc.checkHeader
			if name == "" {
				name = tc.placement.Name
			}
			if tc.wantHeader != nil {
				assert.Equal(t, tc.wantHeader, out.Header.Values(name), "the outbound %s header", name)
			}
		})
	}
}

func TestNewWriterRefusals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		placement credential.Placement
		wantErr   string
	}{
		{
			name:      "a basic placement naming no user",
			placement: credential.Placement{Kind: credential.KindBasic},
			wantErr:   "the basic placement names no user",
		},
		{
			name:      "a basic placement whose user holds a colon",
			placement: credential.Placement{Kind: credential.KindBasic, User: "alice:hunter2"},
			wantErr:   "a basic placement user must not contain a colon or a control character",
		},
		{
			name:      "a basic placement whose user would split the request head",
			placement: credential.Placement{Kind: credential.KindBasic, User: "alice\r\nX-Injected: 1"},
			wantErr:   "a basic placement user must not contain a colon or a control character",
		},
		{
			name:      "a kind no build writes",
			placement: credential.Placement{Kind: "cookie", Name: "session"},
			wantErr:   `"cookie" is not a placement kind`,
		},
		{
			name: "a header name that would split the request head",
			placement: credential.Placement{
				Kind: credential.KindHeader, Name: "X-Token\r\nX-Injected: 1", Template: credential.Token,
			},
			wantErr: "is not a header name",
		},
		{
			name: "a header template without the token",
			placement: credential.Placement{
				Kind: credential.KindHeader, Name: "Authorization", Template: "Bearer",
			},
			wantErr: "the header template holds no {credential}",
		},
		{
			name:      "a query placement naming no parameter",
			placement: credential.Placement{Kind: credential.KindQuery},
			wantErr:   "names no parameter",
		},
		{
			name:      "no kind at all",
			placement: credential.Placement{Name: "Authorization"},
			wantErr:   `"" is not a placement kind`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer, err := credential.NewWriter(tc.placement)
			require.ErrorContains(t, err, tc.wantErr, "NewWriter")
			assert.Nil(t, writer, "a refused placement has no writer")
		})
	}
}

// TestNewWriterRefusesABannedHeaderName pins the names a header placement
// cannot use. NewWriter applies the rule to endpoints built in code as well
// as to endpoints read from a document.
func TestNewWriterRefusesABannedHeaderName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// group says why the name is banned, so a failure names the rule.
		group string
	}{
		{name: "Connection", group: "hop-by-hop"},
		{name: "Proxy-Connection", group: "hop-by-hop"},
		{name: "Keep-Alive", group: "hop-by-hop"},
		{name: "TE", group: "hop-by-hop"},
		{name: "Trailer", group: "hop-by-hop"},
		{name: "Transfer-Encoding", group: "hop-by-hop"},
		{name: "Upgrade", group: "hop-by-hop"},
		{name: "Proxy-Authenticate", group: "hop-by-hop"},
		{name: "Proxy-Authorization", group: "hop-by-hop"},
		{name: "Content-Length", group: "body framing"},
		{name: "Host", group: "written from the request target, never from the header map"},
		{name: "Forwarded", group: "upstream trust"},
		{name: "X-Forwarded-For", group: "upstream trust, by prefix"},
		{name: "X-Forwarded-Proto", group: "upstream trust, by prefix"},
		{name: "Sec-Fetch-Site", group: "reserved for the user agent, by prefix"},
		{name: "host", group: "the comparison ignores case"},
		{name: "CONNECTION", group: "the comparison ignores case"},
		{name: "TrAnSfEr-EnCoDiNg", group: "the comparison ignores case"},
		{name: "x-FORWARDED-proto", group: "the prefix comparison ignores case"},
		{name: "SEC-websocket-key", group: "the prefix comparison ignores case"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.True(t, credential.BannedHeaderName(tc.name), "BannedHeaderName: %s", tc.group)
			writer, err := credential.NewWriter(credential.Placement{
				Kind: credential.KindHeader, Name: tc.name, Template: "Bearer " + credential.Token,
			})
			require.ErrorContains(t, err, "a header placement cannot name "+strconv.Quote(tc.name), "NewWriter")
			assert.Nil(t, writer, "a refused placement has no writer")
		})
	}
}

// TestNewWriterAcceptsAHeaderName pins allowed names. Authorization is the
// placement most endpoints name. A ban applies only to an exact name or a
// complete family prefix.
func TestNewWriterAcceptsAHeaderName(t *testing.T) {
	t.Parallel()
	names := []string{
		"Authorization",
		"authorization",
		"X-Api-Key",
		"Private-Token",
		// A banned prefix inside a name is allowed.
		"My-X-Forwarded-Marker",
		// A banned name as a prefix of a longer name is allowed.
		"Second-Factor",
		"Host-Key",
		"Connection-Id",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.False(t, credential.BannedHeaderName(name), "BannedHeaderName")
			writer, err := credential.NewWriter(credential.Placement{
				Kind: credential.KindHeader, Name: name, Template: "Bearer " + credential.Token,
			})
			require.NoError(t, err, "NewWriter")
			assert.NotNil(t, writer, "an accepted placement has a writer")
		})
	}
}

// TestValidate refuses a credential the proxy cannot put into a request. A
// carriage return or a newline in a header value splits the request head.
func TestValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		wantErr string
	}{
		{name: "an ordinary token", value: "ghp_1234"},
		{name: "a token with spaces and punctuation", value: "Basic dXNlcjpwYXNz=="},
		{name: "empty", value: "", wantErr: "empty value"},
		{name: "a newline", value: "one\ntwo", wantErr: "invalid character"},
		{name: "a carriage return", value: "one\r\nX-Injected: 1", wantErr: "invalid character"},
		{name: "a null byte", value: "one\x00", wantErr: "invalid character"},
		{name: "a delete byte", value: "\x7f", wantErr: "invalid character"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := credential.Validate(tc.value)
			if tc.wantErr == "" {
				require.NoError(t, err, "Validate")
				return
			}
			require.ErrorContains(t, err, tc.wantErr, "Validate")
		})
	}
}

func TestRedact(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		text string
		// placement is the placement whose wire forms Redact covers. The
		// zero value names no kind, and its wire form is the credential
		// itself.
		placement  credential.Placement
		credential string
		// noSecrets drives the call a forward with no credential makes. The
		// slice is nil and Redact has nothing to cover.
		noSecrets bool
		want      string
	}{
		{
			name: "a credential whose escaped form is itself",
			text: `Get "https://maps.example/geocode?key=` + secret + `": refused`,
			// This case covers a credential that needs no escaping.
			credential: secret, want: `Get "https://maps.example/geocode?key=[redacted]": refused`,
		},
		{
			name: "every occurrence", text: secret + " and " + secret,
			credential: secret, want: "[redacted] and [redacted]",
		},
		{
			name: "text without one", text: "dial tcp 127.0.0.1:1: refused", credential: secret,
			want: "dial tcp 127.0.0.1:1: refused",
		},
		{name: "no credential leaves the text alone", text: "anything", credential: "", want: "anything"},
		{
			name: "no secrets at all leaves the text alone", text: "dial tcp 127.0.0.1:1: refused",
			noSecrets: true, want: "dial tcp 127.0.0.1:1: refused",
		},
		{
			name:       "a credential in the raw form a header placement writes",
			text:       `Post "https://api.example/": header "Bearer ` + escapedSecret + `" rejected`,
			credential: escapedSecret,
			want:       `Post "https://api.example/": header "Bearer [redacted]" rejected`,
		},
		{
			name:       "a credential in the escaped form a query placement writes",
			text:       `Get "https://maps.example/geocode?key=` + escapedForm + `&q=here": refused`,
			credential: escapedSecret,
			want:       `Get "https://maps.example/geocode?key=[redacted]&q=here": refused`,
		},
		{
			name:       "both forms in one text",
			text:       escapedSecret + " encodes to " + escapedForm,
			credential: escapedSecret, want: "[redacted] encodes to [redacted]",
		},
		{
			name:       "the escaped form alone, with no raw occurrence",
			text:       "key=" + escapedForm,
			credential: escapedSecret, want: "key=[redacted]",
		},
		{
			name:       "the base64 a basic placement writes, which holds none of the credential bytes",
			text:       `Get "https://git.example/repo.git": ` + basicHeader(basicUser, secret) + " rejected",
			placement:  credential.Placement{Kind: credential.KindBasic, User: basicUser},
			credential: secret,
			want:       `Get "https://git.example/repo.git": Basic [redacted] rejected`,
		},
		{
			name:       "the credential itself under a basic placement",
			text:       "resource https://git.example/: " + secret + " rejected",
			placement:  credential.Placement{Kind: credential.KindBasic, User: basicUser},
			credential: secret,
			want:       "resource https://git.example/: [redacted] rejected",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var forms []string
			if !tc.noSecrets {
				forms = credential.WireForms(tc.placement, tc.credential)
			}
			assert.Equal(t, tc.want, credential.Redact(tc.text, forms), "Redact")
		})
	}
}

// errZoneAnswer stands in for the OAuth error the SDK reports.
var errZoneAnswer = errors.New("oauth error access_denied: no policy grants the resource")

// TestExchangeErrorKeepsTheClassAndCarriesTheDetail pins that an
// ExchangeError matches its class with errors.Is, exposes its cause, and
// hands the proxy a detail that any other error lacks.
func TestExchangeErrorKeepsTheClassAndCarriesTheDetail(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		err        error
		wantIs     []error
		wantText   string
		wantDetail string
	}{
		"a refusal with its cause": {
			err: &credential.ExchangeError{
				Class: credential.ErrExchangeDenied, Detail: "no policy grants the resource", Cause: errZoneAnswer,
			},
			wantIs:     []error{credential.ErrExchangeDenied, errZoneAnswer},
			wantText:   "the authorization server denied the exchange: oauth error access_denied: no policy grants the resource",
			wantDetail: "no policy grants the resource",
		},
		"a failure with no cause": {
			err:        &credential.ExchangeError{Class: credential.ErrExchangeFailed, Detail: "the zone answered 502"},
			wantIs:     []error{credential.ErrExchangeFailed},
			wantText:   "the token exchange failed: the zone answered 502",
			wantDetail: "the zone answered 502",
		},
		"a wrapped exchange error": {
			err: fmt.Errorf("resource x: %w",
				&credential.ExchangeError{Class: credential.ErrExchangeFailed, Detail: "the zone answered 502"}),
			wantIs:     []error{credential.ErrExchangeFailed},
			wantText:   "resource x: the token exchange failed: the zone answered 502",
			wantDetail: "the zone answered 502",
		},
		"a plain class error": {
			err:      credential.ErrExchangeDenied,
			wantIs:   []error{credential.ErrExchangeDenied},
			wantText: "the authorization server denied the exchange",
		},
		"no error": {},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)
			for _, want := range tc.wantIs {
				r.ErrorIs(tc.err, want, "the chain keeps %v", want)
			}
			if tc.err != nil {
				r.Equal(tc.wantText, tc.err.Error(), "the error text")
			}
			r.Equal(tc.wantDetail, credential.Detail(tc.err), "the detail")
		})
	}
}
