package credential_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/credential"
)

const secret = "sekrit-token" //nolint:gosec // G101: a test fixture, not a credential

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
// placement. The placement is authoritative: a value the workload sent
// there is replaced, and one it did not send is written.
func TestWriterReplacesWhatTheWorkloadSent(t *testing.T) {
	t.Parallel()
	header := credential.Placement{
		Kind: credential.KindHeader, Name: "Authorization", Template: "Bearer " + credential.Token,
	}
	query := credential.Placement{Kind: credential.KindQuery, Name: "key"}
	tests := []struct {
		name      string
		placement credential.Placement
		target    string
		header    http.Header
		wantQuery string
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
			name:      "a basic placement, which this build does not write",
			placement: credential.Placement{Kind: credential.KindBasic, User: "x-access-token"},
			wantErr:   "does not write a basic placement",
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
		{name: "empty", value: "", wantErr: "it is empty"},
		{name: "a newline", value: "one\ntwo", wantErr: "control character at byte 3"},
		{name: "a carriage return", value: "one\r\nX-Injected: 1", wantErr: "control character at byte 3"},
		{name: "a null byte", value: "one\x00", wantErr: "control character at byte 3"},
		{name: "a delete byte", value: "\x7f", wantErr: "control character at byte 0"},
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
		name       string
		text       string
		credential string
		want       string
	}{
		{
			name: "a credential in a URL", text: `Get "https://maps.example/geocode?key=` + secret + `": refused`,
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
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, credential.Redact(tc.text, tc.credential), "Redact")
		})
	}
}
