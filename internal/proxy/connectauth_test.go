package proxy_test

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/proxy"
)

// writeConnectAuth writes a connect credential file with the given mode.
func writeConnectAuth(t *testing.T, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "connect-auth")
	require.NoError(t, os.WriteFile(path, []byte(contents), mode))
	return path
}

func basic(userPass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(userPass))
}

func TestLoadConnectAuthRefusals(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		contents string
		mode     os.FileMode
		wantErr  string
	}{
		"no colon":          {contents: "troybarnes", mode: 0o600, wantErr: "user:password"},
		"empty user":        {contents: ":secret", mode: 0o600, wantErr: "user is empty"},
		"empty password":    {contents: "troy:", mode: 0o600, wantErr: "password is empty"},
		"control character": {contents: "troy:sec\x00ret", mode: 0o600, wantErr: "control character"},
		"group readable":    {contents: "troy:secret", mode: 0o640, wantErr: "readable by its owner alone"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := proxy.LoadConnectAuth(writeConnectAuth(t, tc.contents, tc.mode))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.NotContains(t, err.Error(), "secret", "the error never quotes the credential")
		})
	}
}

func TestConnectAuthAllows(t *testing.T) {
	t.Parallel()
	auth, err := proxy.LoadConnectAuth(writeConnectAuth(t, "troy:greendale\n", 0o600))
	require.NoError(t, err, "a trailing newline is not part of the password")
	tests := map[string]struct {
		header string
		want   bool
	}{
		"no header":           {header: "", want: false},
		"another scheme":      {header: "Bearer dGhpcyBpcyBub3QgYmFzaWM=", want: false},
		"not base64":          {header: "Basic %%%", want: false},
		"wrong user":          {header: basic("abed:greendale"), want: false},
		"wrong password":      {header: basic("troy:city-college"), want: false},
		"password prefix":     {header: basic("troy:greendal"), want: false},
		"the configured pair": {header: basic("troy:greendale"), want: true},
		"lowercase scheme":    {header: "basic " + base64.StdEncoding.EncodeToString([]byte("troy:greendale")), want: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := &http.Request{Header: http.Header{}}
			if tc.header != "" {
				r.Header.Set("Proxy-Authorization", tc.header)
			}
			assert.Equal(t, tc.want, auth.Allows(r))
		})
	}
}
