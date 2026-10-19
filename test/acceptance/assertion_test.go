//go:build acceptance

package acceptance_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/rogpeppe/go-internal/testscript"

	"github.com/keycardai/egress-proxy/internal/assertion"
)

var errAssertKey = errors.New("assertion key")

// defaultIssuer is the iss an assertion carries when the script names
// none. It is the fixed issuer the extension uses when it publishes no
// keys, so a scenario that involves no zone needs no issuer server.
const defaultIssuer = "keycard-openshell-extension"

// cmdAssertKey writes a P-256 key pair for sandbox assertions:
//
//	assertkey DIR
//
// DIR/key.pem holds the private key (PKCS #8, mode 0600) and DIR/key.pub the
// public key in the form sandbox_assertion.issuer_key_file reads.
func cmdAssertKey(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 1 {
		ts.Fatalf("usage: assertkey DIR")
	}
	dir := ts.MkAbs(args[0])
	ts.Check(os.MkdirAll(dir, 0o700))
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ts.Check(err)
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	ts.Check(err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	ts.Check(os.WriteFile(filepath.Join(dir, "key.pem"), privPEM, 0o600))
	pubPEM, err := assertion.MarshalPublicKey(&priv.PublicKey)
	ts.Check(err)
	ts.Check(os.WriteFile(filepath.Join(dir, "key.pub"), pubPEM, 0o644))
}

// cmdIssuer publishes the key assertkey wrote the way the extension does,
// so a zone can discover it from an assertion's iss:
//
//	issuer KEYDIR VAR
//
// It starts a cleartext server in the test process that answers
// /.well-known/openid-configuration, whose issuer is the server's own URL,
// and /jwks.json with the public key under its RFC 7638 kid. VAR receives
// the URL. The server stops when the script ends.
func cmdIssuer(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 2 {
		ts.Fatalf("usage: issuer KEYDIR VAR")
	}
	key := readAssertKey(ts, filepath.Join(ts.MkAbs(args[0]), "key.pem"))
	kid, err := assertion.KeyID(&key.PublicKey)
	ts.Check(err)
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &key.PublicKey, KeyID: kid, Use: "sig", Algorithm: string(jose.ES256)},
	}})
	ts.Check(err)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discovery, err := json.Marshal(map[string]any{
				"issuer":                                server.URL,
				"jwks_uri":                              server.URL + "/jwks.json",
				"id_token_signing_alg_values_supported": []string{string(jose.ES256)},
				"subject_types_supported":               []string{"public"},
				"response_types_supported":              []string{},
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(discovery)
		case "/jwks.json":
			_, _ = w.Write(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	ts.Defer(server.Close)
	ts.Setenv(args[1], server.URL)
}

// cmdAssertion signs a sandbox assertion with a key assertkey wrote and
// puts it in a script variable:
//
//	assertion [-ttl DURATION] [-iss URL] [-aud A,B] [-id ID] [-sub SUBJECT] [-owner SUBJECT] -app NAME \
//	    KEYDIR VAR SANDBOX [WORKSPACE]
//
// The workspace defaults to "default". A negative ttl writes an assertion
// that has already expired. -app names the application and is required.
// -iss names the issuer, -aud the audiences, and -id the sandbox id, which
// defaults to uuid-SANDBOX. -owner names the principal who created the
// sandbox; without it the token carries no owner claim. The subject is
// openshell:NAME:ID. -sub writes another subject in its place, which the
// proxy must refuse, so the token is signed without the checks Sign makes.
func cmdAssertion(ts *testscript.TestScript, neg bool, args []string) {
	ttl := 30 * time.Second
	issuer, audiences := defaultIssuer, []string{"keycard-egress-proxy"}
	var application, id, subject, owner string
	for len(args) >= 2 && strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "-ttl":
			parsed, err := time.ParseDuration(args[1])
			ts.Check(err)
			ttl = parsed
		case "-app":
			application = args[1]
		case "-iss":
			issuer = args[1]
		case "-aud":
			audiences = strings.Split(args[1], ",")
		case "-id":
			id = args[1]
		case "-sub":
			subject = args[1]
		case "-owner":
			owner = args[1]
		default:
			ts.Fatalf("assertion: unknown flag %s", args[0])
		}
		args = args[2:]
	}
	if neg || len(args) < 3 || len(args) > 4 || application == "" {
		ts.Fatalf("usage: assertion [-ttl DURATION] [-iss URL] [-aud A,B] [-id ID] [-sub SUBJECT] [-owner SUBJECT] " +
			"-app NAME KEYDIR VAR SANDBOX [WORKSPACE]")
	}
	workspace := "default"
	if len(args) == 4 {
		workspace = args[3]
	}
	if id == "" {
		id = "uuid-" + args[2]
	}
	key := readAssertKey(ts, filepath.Join(ts.MkAbs(args[0]), "key.pem"))
	claims := assertion.Claims{
		Issuer: issuer, Application: application,
		Sandbox: args[2], Workspace: workspace, SandboxUUID: id, ExecPath: "/usr/bin/curl", Owner: owner,
	}
	if subject != "" {
		ts.Setenv(args[1], signWithSubject(ts, key, claims, subject, audiences, ttl))
		return
	}
	token, err := assertion.Sign(key, claims, audiences, time.Now(), ttl)
	ts.Check(err)
	ts.Setenv(args[1], token)
}

// signWithSubject signs the claims under a subject that contradicts them.
func signWithSubject(
	ts *testscript.TestScript, key *ecdsa.PrivateKey, claims assertion.Claims, subject string,
	audiences []string, ttl time.Duration,
) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	ts.Check(err)
	now := time.Now()
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: claims.Issuer, Subject: subject, Audience: jwt.Audience(audiences), ID: "jti-chang",
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(ttl)),
	}).Claims(map[string]any{
		"app": claims.Application, "sandbox": claims.Sandbox, "workspace": claims.Workspace,
		"sandbox_id": claims.SandboxUUID, "exec_path": claims.ExecPath,
	}).Serialize()
	ts.Check(err)
	return token
}

func readAssertKey(ts *testscript.TestScript, path string) *ecdsa.PrivateKey {
	pemBytes, err := os.ReadFile(path)
	ts.Check(err)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		ts.Check(errAssertKey)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	ts.Check(err)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		ts.Check(errAssertKey)
	}
	return key
}
