// Package ca mints the TLS certificate authority that the proxy terminates
// connections with: one CA per sandbox, and one leaf per server name.
//
// The authority's key lives in process memory, optionally stored in the
// configured state directory. The state directory must be a memory-backed
// volume.
//
// The configured output directory will contain the public CA certificate for
// workloads that need to trust it.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/keycardai/egress-proxy/internal/policy"
)

// CertificateFileName is the file WriteCertificate creates under the output
// directory. The workload adds this file to its trust store.
const CertificateFileName = "ca.crt"

const (
	// backdate covers clock skew between the proxy and the workload. A
	// workload rejects a leaf whose NotBefore is in its own future.
	backdate = time.Hour
	// defaultTTL is the authority's lifetime. It outlives a sandbox.
	defaultTTL = 30 * 24 * time.Hour
	// defaultLeafTTL is a leaf's lifetime.
	defaultLeafTTL = 24 * time.Hour
	// serialBits is the size of a certificate serial. CA/Browser Forum
	// Baseline Requirements section 7.1 require at least 64 bits from a
	// CSPRNG.
	serialBits = 128

	// outDirMode lets the workload, which runs as another uid, read the
	// certificate out of the shared mount.
	outDirMode  = 0o755
	outFileMode = 0o644
)

var errNoHost = errors.New("ca: no host to mint a leaf for")

// Options configures a new authority. The zero value is usable.
type Options struct {
	// CommonName and Organization go in the CA subject.
	CommonName   string
	Organization string
	// TTL is the authority's lifetime, measured from Now.
	TTL time.Duration
	// LeafTTL is a minted leaf's lifetime. A leaf never outlives the
	// authority.
	LeafTTL time.Duration
	// Now is the clock. Tests set it.
	Now func() time.Time
}

func (o Options) withDefaults() Options {
	if o.CommonName == "" {
		o.CommonName = "Keycard egress proxy CA"
	}
	if o.Organization == "" {
		o.Organization = "Keycard"
	}
	if o.TTL <= 0 {
		o.TTL = defaultTTL
	}
	if o.LeafTTL <= 0 {
		o.LeafTTL = defaultLeafTTL
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// Authority is a certificate authority that signs one leaf per server name.
type Authority struct {
	opts    Options
	cert    *x509.Certificate
	certDER []byte
	certPEM []byte
	key     *ecdsa.PrivateKey
	pool    *x509.CertPool
}

// New generates an authority. The key is ECDSA P-256, which keeps leaf
// minting cheap enough to sit on the handshake path.
func New(opts Options) (*Authority, error) {
	opts = opts.withDefaults()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := opts.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{opts.Organization},
		},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(opts.TTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// The authority signs leaves and nothing else. A chain through an
		// intermediate that it signed does not verify.
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("ca: self-sign: %w", err)
	}
	return fromMaterial(opts, der, key)
}

// fromMaterial builds an Authority around a parsed certificate and its key.
func fromMaterial(opts Options, der []byte, key *ecdsa.PrivateKey) (*Authority, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parse certificate: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &Authority{
		opts:    opts,
		cert:    cert,
		certDER: der,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
		pool:    pool,
	}, nil
}

// Certificate returns the CA certificate. It holds the public key only.
func (a *Authority) Certificate() *x509.Certificate {
	return a.cert
}

// CertificatePEM returns the PEM encoding of the CA certificate.
func (a *Authority) CertificatePEM() []byte {
	return append([]byte(nil), a.certPEM...)
}

// Pool returns a pool holding the CA certificate and nothing else.
func (a *Authority) Pool() *x509.CertPool {
	return a.pool.Clone()
}

// NotAfter is when the authority expires.
func (a *Authority) NotAfter() time.Time {
	return a.cert.NotAfter
}

// prepareOutDir creates the output directory and leaves it readable by the
// workload, which runs as another uid. The mode is set on every start:
// MkdirAll subtracts the process umask, which a hardened base image sets to
// 0077, and applies outDirMode only to a directory it creates.
func prepareOutDir(dir string) error {
	if err := os.MkdirAll(dir, outDirMode); err != nil {
		return fmt.Errorf("ca: create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, outDirMode); err != nil {
		return fmt.Errorf("ca: set mode on %s: %w", dir, err)
	}
	return nil
}

// WriteCertificate writes the CA certificate to dir and returns the path. It
// writes the certificate and nothing else. The write is a create-and-rename,
// so a workload reading the path never sees a partial file.
func (a *Authority) WriteCertificate(dir string) (string, error) {
	if err := prepareOutDir(dir); err != nil {
		return "", err
	}
	final := filepath.Join(dir, CertificateFileName)
	tmp, err := os.CreateTemp(dir, CertificateFileName+".tmp*")
	if err != nil {
		return "", fmt.Errorf("ca: create temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(a.certPEM); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("ca: write %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(outFileMode); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("ca: chmod %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("ca: close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return "", fmt.Errorf("ca: rename %s to %s: %w", tmpName, final, err)
	}
	return final, nil
}

// Leaf mints a server certificate for one host, a DNS name or an IP literal
// without a port. Every leaf has exactly one SAN, so a leaf minted for
// one destination cannot authenticate another.
func (a *Authority) Leaf(host string) (*tls.Certificate, error) {
	host = policy.NormalizeHost(host)
	if host == "" {
		return nil, errNoHost
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate leaf key for %s: %w", host, err)
	}

	now := a.opts.Now()
	notAfter := now.Add(a.opts.LeafTTL)
	if notAfter.After(a.cert.NotAfter) {
		notAfter = a.cert.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{a.opts.Organization}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, key.Public(), a.key)
	if err != nil {
		return nil, fmt.Errorf("ca: sign leaf for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parse leaf for %s: %w", host, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, a.certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// randomSerial draws a positive serial of serialBits from the CSPRNG.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), serialBits)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("ca: draw serial: %w", err)
	}
	return serial.Add(serial, big.NewInt(1)), nil
}
