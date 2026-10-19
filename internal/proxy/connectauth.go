package proxy

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/keycardai/egress-proxy/internal/credential"
)

var errConnectAuth = errors.New("invalid connect auth file")

// ConnectAuth is the credential every CONNECT must present in
// Proxy-Authorization. One credential serves the whole proxy, so it proves
// that a client is a runtime this proxy was deployed for and nothing finer.
type ConnectAuth struct {
	// userPass is "user:password", the decoded form of the Basic value.
	userPass []byte
}

// LoadConnectAuth reads listen.connect_auth_file: one line, "user:password",
// readable by its owner alone. A trailing newline is not part of the
// password. The error never quotes the file's contents.
func LoadConnectAuth(path string) (*ConnectAuth, error) {
	if err := credential.CheckSecretFile(errConnectAuth, path); err != nil {
		return nil, fmt.Errorf("listen.connect_auth_file: %w", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path is listen.connect_auth_file
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errConnectAuth, err)
	}
	userPass := bytes.TrimRight(data, "\r\n")
	user, pass, ok := bytes.Cut(userPass, []byte(":"))
	switch {
	case !ok:
		return nil, fmt.Errorf("%w %s: it must hold user:password", errConnectAuth, path)
	case len(user) == 0:
		return nil, fmt.Errorf("%w %s: the user is empty", errConnectAuth, path)
	case len(pass) == 0:
		return nil, fmt.Errorf("%w %s: the password is empty", errConnectAuth, path)
	}
	for _, b := range userPass {
		if b < 0x20 || b == 0x7f {
			return nil, fmt.Errorf("%w %s: it holds a control character", errConnectAuth, path)
		}
	}
	return &ConnectAuth{userPass: userPass}, nil
}

// Allows reports whether the request carries the configured credential as
// a Basic Proxy-Authorization. The comparison takes constant time over the
// whole user:password, so neither half leaks through timing.
func (a *ConnectAuth) Allows(r *http.Request) bool {
	scheme, encoded, ok := strings.Cut(r.Header.Get("Proxy-Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	presented, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(presented, a.userPass) == 1
}
