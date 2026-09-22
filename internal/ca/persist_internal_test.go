package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testNow is the instant the material in TestLoadChecksMaterial is dated
// against.
func testNow() time.Time {
	return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
}

// caTemplate is material load accepts. Each case in TestLoadChecksMaterial
// spoils one field of it.
func caTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "egress-proxy test"},
		NotBefore:             testNow().Add(-time.Hour),
		NotAfter:              testNow().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

// writeMaterial self-signs template and writes it to dir with storeKey as
// ca.key. Passing a storeKey other than the signer produces material whose
// key does not match its certificate.
func writeMaterial(t *testing.T, dir string, template *x509.Certificate, storeKey *ecdsa.PrivateKey) {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate the signing key")
	if storeKey == nil {
		storeKey = signer
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &signer.PublicKey, signer)
	require.NoError(t, err, "self-sign the template")
	keyDER, err := x509.MarshalPKCS8PrivateKey(storeKey)
	require.NoError(t, err, "marshal the key")

	require.NoError(t, os.MkdirAll(dir, stateDirMode))
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(filepath.Join(dir, keyFileName), keyPEM, keyFileMode))
	require.NoError(t, os.WriteFile(filepath.Join(dir, certFileName), certPEM, keyFileMode))
}

// TestLoadChecksMaterial covers the checks load applies to material read
// back from the state directory, which need not be what New wrote. It calls
// load directly, so the cases run on every platform rather than only where
// a tmpfs exists.
func TestLoadChecksMaterial(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// spoil mutates the template before it is self-signed.
		spoil func(*x509.Certificate)
		// otherKey stores a key that did not sign the certificate.
		otherKey bool
		wantErr  string
	}{
		{name: "material New would write"},
		{
			name:     "a key that did not sign the certificate",
			otherKey: true,
			wantErr:  "the key does not match the certificate",
		},
		{
			name:    "a certificate that cannot sign certificates",
			spoil:   func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
			wantErr: "the certificate cannot sign certificates",
		},
		{
			name:    "a certificate with no key usage at all",
			spoil:   func(c *x509.Certificate) { c.KeyUsage = 0 },
			wantErr: "the certificate cannot sign certificates",
		},
		{
			name:    "a certificate that is not a CA",
			spoil:   func(c *x509.Certificate) { c.IsCA = false },
			wantErr: "not a CA certificate",
		},
		{
			name:    "a certificate that has expired",
			spoil:   func(c *x509.Certificate) { c.NotAfter = testNow().Add(-time.Minute) },
			wantErr: "the certificate expires at",
		},
		{
			name:    "a certificate that expires inside the renewal window",
			spoil:   func(c *x509.Certificate) { c.NotAfter = testNow().Add(renewBefore / 2) },
			wantErr: "the certificate expires at",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			template := caTemplate()
			if tc.spoil != nil {
				tc.spoil(template)
			}
			var storeKey *ecdsa.PrivateKey
			if tc.otherKey {
				var err error
				storeKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err, "generate the mismatched key")
			}
			dir := filepath.Join(t.TempDir(), "state")
			writeMaterial(t, dir, template, storeKey)

			authority, err := load(dir, Options{Now: testNow})
			if tc.wantErr == "" {
				require.NoError(t, err, "load")
				assert.NotNil(t, authority, "the loaded authority")
				return
			}
			require.ErrorIs(t, err, errMaterial, "the refusal names the stored material")
			require.ErrorContains(t, err, tc.wantErr, "the refusal says which check failed")
			assert.Nil(t, authority, "a refused load returns no authority")
		})
	}
}
