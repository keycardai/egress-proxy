// Package assertion verifies the sandbox assertion a request carries: a
// short-lived JWT, signed with ES256 by a component the sandbox runtime
// trusts, that names the sandbox the request came from and the application
// it is an instance of. The proxy selects a credential identity by it, names
// the sandbox on the audit record, and can present the same token to the
// Keycard zone as the sandbox's client assertion.
package assertion

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var (
	// ErrInvalid is the class of every verification failure. The wrapped
	// text says which check failed and never quotes the token.
	ErrInvalid = errors.New("invalid sandbox assertion")

	errKey  = errors.New("sandbox assertion key")
	errSign = errors.New("sign sandbox assertion")
)

// SubjectPrefix starts every subject. The zone matches application
// credentials against the subject, so the prefix keeps a sandbox subject
// apart from every other subject the zone knows.
const SubjectPrefix = "openshell:"

// ThumbprintHash is the hash the kid header is computed with, per RFC 7638.
const ThumbprintHash = crypto.SHA256

// jtiBytes is the entropy of a token id.
const jtiBytes = 16

// Claims is what an assertion says about a request.
type Claims struct {
	// Issuer is the iss claim: the URL the signing component publishes its
	// keys under.
	Issuer string
	// Subject is the sub claim. It is Subject(Application, SandboxUUID),
	// and the zone calls the client by it.
	Subject string
	// Sandbox is the sandbox name.
	Sandbox string
	// Workspace is the runtime workspace that scopes the name.
	Workspace string
	// SandboxUUID is the runtime's own identifier for the sandbox.
	SandboxUUID string
	// ExecPath is the binary that made the request, where the runtime
	// knows it.
	ExecPath string
	// Application is the kind of sandbox, which Keycard names an
	// application. A sandbox id is new on every create, so the identity
	// the proxy acts as follows the application.
	Application string
	// Owner is the principal who created the sandbox, as the runtime
	// authenticated them at create. The runtime asserts it and nothing
	// here verifies it. Empty where the runtime recorded none.
	Owner string
	// OwnerID is the Keycard user public id of the owner, resolved by the
	// runtime. An identity that impersonates the sandbox owner exchanges
	// for it. Empty where the runtime resolved none.
	OwnerID string
}

// Subject builds the sub claim for an application and a sandbox id.
func Subject(application, sandboxUUID string) string {
	return SubjectPrefix + application + ":" + sandboxUUID
}

// privateClaims is the wire form of the private claims. The JSON names are
// the contract a signer outside this module follows.
type privateClaims struct {
	Application string `json:"app,omitempty"`
	Sandbox     string `json:"sandbox,omitempty"`
	Workspace   string `json:"workspace,omitempty"`
	SandboxUUID string `json:"sandbox_id,omitempty"`
	ExecPath    string `json:"exec_path,omitempty"`
	Owner       string `json:"owner,omitempty"`
	OwnerID     string `json:"owner_id,omitempty"`
}

// Verifier checks assertions against one issuer key.
type Verifier struct {
	key      *ecdsa.PublicKey
	audience string
	issuer   string
	maxAge   time.Duration
}

// Option adjusts a Verifier.
type Option func(*Verifier)

// WithIssuer requires the iss claim to equal issuer. Without it, any
// issuer is accepted and the key alone says who signed.
func WithIssuer(issuer string) Option {
	return func(v *Verifier) { v.issuer = issuer }
}

// NewVerifier reads a P-256 public key in PEM (PKIX) form. Any other key
// type or curve is refused, because the zone verifies the same token and
// accepts no other.
func NewVerifier(publicKeyPEM []byte, audience string, maxAge time.Duration, opts ...Option) (*Verifier, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", errKey)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errKey, err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %T is not a P-256 key", errKey, parsed)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: curve %s is not P-256", errKey, key.Curve.Params().Name)
	}
	if audience == "" {
		return nil, fmt.Errorf("%w: audience is empty", errKey)
	}
	if maxAge <= 0 {
		return nil, fmt.Errorf("%w: max age must be positive", errKey)
	}
	verifier := &Verifier{key: key, audience: audience, maxAge: maxAge}
	for _, apply := range opts {
		apply(verifier)
	}
	return verifier, nil
}

// Verify checks the token's signature, algorithm, audience, lifetime and
// required claims at the given time. The subject must be the one the app
// and sandbox_id claims build, so a token cannot name one application to
// the proxy and another to the zone.
func (v *Verifier) Verify(token string, now time.Time) (Claims, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return Claims{}, fmt.Errorf("%w: parse: %w", ErrInvalid, err)
	}
	var standard jwt.Claims
	var private privateClaims
	if err := parsed.Claims(v.key, &standard, &private); err != nil {
		return Claims{}, fmt.Errorf("%w: signature: %w", ErrInvalid, err)
	}
	if err := v.checkLifetime(standard); err != nil {
		return Claims{}, err
	}
	// Leeway absorbs clock skew between the signer and this process. It
	// widens the expiry and the issue time by the same amount, so a token
	// is accepted up to Leeway after exp and may be issued up to Leeway in
	// the future. The lifetime bound above does not stretch with it.
	if err := standard.ValidateWithLeeway(jwt.Expected{
		Issuer:      v.issuer,
		AnyAudience: jwt.Audience{v.audience},
		Time:        now,
	}, Leeway); err != nil {
		return Claims{}, describe(err)
	}
	if err := checkRequired(standard, private); err != nil {
		return Claims{}, err
	}
	return Claims{
		Issuer:      standard.Issuer,
		Subject:     standard.Subject,
		Sandbox:     private.Sandbox,
		Workspace:   private.Workspace,
		SandboxUUID: private.SandboxUUID,
		ExecPath:    private.ExecPath,
		Application: private.Application,
		Owner:       private.Owner,
		OwnerID:     private.OwnerID,
	}, nil
}

// Leeway is the clock skew the verifier tolerates on exp, nbf and iat.
const Leeway = time.Minute

// checkLifetime requires iat and exp and refuses a lifetime over the
// maximum. Expiry and issue time against the clock are the standard
// validation's job.
func (v *Verifier) checkLifetime(standard jwt.Claims) error {
	if standard.IssuedAt == nil || standard.Expiry == nil {
		return fmt.Errorf("%w: iat and exp are required", ErrInvalid)
	}
	lifetime := standard.Expiry.Time().Sub(standard.IssuedAt.Time())
	if lifetime > v.maxAge {
		return fmt.Errorf("%w: lifetime %s is over the maximum %s", ErrInvalid, lifetime, v.maxAge)
	}
	return nil
}

// checkRequired refuses a token that leaves out a claim the contract
// requires, and one whose subject contradicts its app and sandbox_id.
func checkRequired(standard jwt.Claims, private privateClaims) error {
	switch {
	case standard.Issuer == "":
		return fmt.Errorf("%w: no iss claim", ErrInvalid)
	case standard.Subject == "":
		return fmt.Errorf("%w: no sub claim", ErrInvalid)
	case standard.ID == "":
		return fmt.Errorf("%w: no jti claim", ErrInvalid)
	case private.Application == "":
		return fmt.Errorf("%w: no app claim", ErrInvalid)
	case private.Sandbox == "":
		return fmt.Errorf("%w: no sandbox claim", ErrInvalid)
	case private.SandboxUUID == "":
		return fmt.Errorf("%w: no sandbox_id claim", ErrInvalid)
	case standard.Subject != Subject(private.Application, private.SandboxUUID):
		return fmt.Errorf("%w: sub does not name the app and sandbox_id claims", ErrInvalid)
	}
	return nil
}

// describe maps go-jose's validation sentinels to the words the operator
// reads. Any other error passes through under ErrInvalid.
func describe(err error) error {
	switch {
	case errors.Is(err, jwt.ErrExpired):
		return fmt.Errorf("%w: expired", ErrInvalid)
	case errors.Is(err, jwt.ErrInvalidAudience):
		return fmt.Errorf("%w: audience does not match", ErrInvalid)
	case errors.Is(err, jwt.ErrInvalidIssuer):
		return fmt.Errorf("%w: issuer does not match", ErrInvalid)
	case errors.Is(err, jwt.ErrNotValidYet):
		return fmt.Errorf("%w: not valid yet", ErrInvalid)
	case errors.Is(err, jwt.ErrIssuedInTheFuture):
		return fmt.Errorf("%w: issued in the future", ErrInvalid)
	default:
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
}

// Sign builds an assertion for the claims, valid from now for ttl, for every
// audience given. The subject is derived from the application and the
// sandbox id, and claims.Subject is ignored. The header carries the key's
// RFC 7638 thumbprint as kid, so a verifier that fetches the signer's JWKS
// finds the key. The middleware outside this module signs with the same
// claim names.
func Sign(key *ecdsa.PrivateKey, claims Claims, audiences []string, now time.Time, ttl time.Duration) (string, error) {
	if err := claims.checkSignable(audiences); err != nil {
		return "", err
	}
	kid, err := KeyID(&key.PublicKey)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), kid))
	if err != nil {
		return "", fmt.Errorf("%w: %w", errSign, err)
	}
	jti, err := tokenID()
	if err != nil {
		return "", err
	}
	token, err := jwt.Signed(signer).
		Claims(jwt.Claims{
			Issuer:   claims.Issuer,
			Subject:  Subject(claims.Application, claims.SandboxUUID),
			Audience: jwt.Audience(audiences),
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(ttl)),
			ID:       jti,
		}).
		Claims(privateClaims{
			Application: claims.Application,
			Sandbox:     claims.Sandbox,
			Workspace:   claims.Workspace,
			SandboxUUID: claims.SandboxUUID,
			ExecPath:    claims.ExecPath,
			Owner:       claims.Owner,
			OwnerID:     claims.OwnerID,
		}).
		Serialize()
	if err != nil {
		return "", fmt.Errorf("%w: %w", errSign, err)
	}
	return token, nil
}

// checkSignable refuses claims the verifier would refuse for a missing
// value.
func (c Claims) checkSignable(audiences []string) error {
	switch {
	case c.Issuer == "":
		return fmt.Errorf("%w: the issuer is empty", errSign)
	case c.Application == "":
		return fmt.Errorf("%w: the application is empty", errSign)
	case c.Sandbox == "":
		return fmt.Errorf("%w: the sandbox name is empty", errSign)
	case c.SandboxUUID == "":
		return fmt.Errorf("%w: the sandbox id is empty", errSign)
	case len(audiences) == 0:
		return fmt.Errorf("%w: no audience", errSign)
	}
	return nil
}

// tokenID is a fresh jti.
func tokenID() (string, error) {
	raw := make([]byte, jtiBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("%w: token id: %w", errSign, err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// KeyID is the RFC 7638 thumbprint of the key, base64url without padding.
// It is the kid the signed header carries and the kid a published JWK must
// carry for a verifier to find the key.
func KeyID(key *ecdsa.PublicKey) (string, error) {
	thumbprint, err := (&jose.JSONWebKey{Key: key}).Thumbprint(ThumbprintHash)
	if err != nil {
		return "", fmt.Errorf("%w: thumbprint: %w", errKey, err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// MarshalPublicKey writes a P-256 public key in the PEM form NewVerifier
// reads.
func MarshalPublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal: %w", errKey, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// tokenKey is the context key for the raw token.
type tokenKey struct{}

// WithToken puts the raw assertion on the context for the credential source
// that presents it to the zone. The value is a credential: NEVER log it or
// write it to a record.
func WithToken(ctx context.Context, raw string) context.Context {
	return context.WithValue(ctx, tokenKey{}, raw)
}

// TokenFromContext reads the raw assertion WithToken put on the context.
func TokenFromContext(ctx context.Context) (string, bool) {
	raw, ok := ctx.Value(tokenKey{}).(string)
	return raw, ok
}
