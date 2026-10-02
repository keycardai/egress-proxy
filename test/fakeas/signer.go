package fakeas

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// assertionLifetime is how long an assertion from Signer.Token stays valid.
const assertionLifetime = time.Hour

// signerKeyBits is the RSA key size. The API server signs projected tokens
// with RS256, and go-oidc accepts RS256 alone unless configured otherwise.
const signerKeyBits = 2048

// Signer mints client assertions for a test and builds the verifier that
// accepts them. It holds its private key in memory for the life of the
// process. NEVER use it outside a test.
type Signer struct {
	key      *rsa.PrivateKey
	issuer   string
	audience string
}

// NewSigner builds a signer on a fresh RSA key for one issuer and audience.
func NewSigner(issuer, audience string) (*Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, signerKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate the assertion key: %w", err)
	}
	return &Signer{key: key, issuer: issuer, audience: audience}, nil
}

// Verifier accepts what Token mints. Pass it to New as Options.Assertions.
func (s *Signer) Verifier() *oidc.IDTokenVerifier {
	keys := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&s.key.PublicKey}}
	return oidc.NewVerifier(s.issuer, keys, &oidc.Config{ClientID: s.audience})
}

// Public is the key Verifier checks signatures against.
func (s *Signer) Public() *rsa.PublicKey {
	return &s.key.PublicKey
}

// Token mints an assertion for subject that Verifier accepts.
func (s *Signer) Token(subject string) (string, error) {
	return s.Sign(jwt.Claims{
		Issuer:   s.issuer,
		Audience: jwt.Audience{s.audience},
		Subject:  subject,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(assertionLifetime)),
	})
}

// Sign mints claims exactly as given with RS256, including a claim set that
// Verifier refuses.
func (s *Signer) Sign(claims jwt.Claims) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.key}, nil)
	if err != nil {
		return "", fmt.Errorf("build the assertion signer: %w", err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign the assertion: %w", err)
	}
	return token, nil
}
