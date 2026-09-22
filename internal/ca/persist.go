package ca

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The files a state directory holds.
const (
	keyFileName  = "ca.key"
	certFileName = "ca.crt"

	// stateDirMode and keyFileMode keep the key readable by the proxy's uid
	// alone.
	stateDirMode = 0o700
	keyFileMode  = 0o600
)

// errNotMemoryBacked occurs when the configured state directory is on a
// filesystem that is not memory-backed. NEVER weaken this into a warning.
var errNotMemoryBacked = errors.New("ca: the state directory is not on a memory-backed filesystem")

var errMaterial = errors.New("ca: stored material refused")

// errSharedDirectory is returned when the state directory and the output
// directory are the same directory, or one sits under the other. The
// workload reads the output directory, so a key under it is a key the
// workload can read.
var errSharedDirectory = errors.New("ca: the state directory and the output directory overlap")

// Overlaps reports whether one directory is the other or sits under it. It
// cleans both paths, so a trailing slash, a repeated separator or a dot
// segment cannot hide a nesting the filesystem honours.
//
// It compares text and cannot see a symlink. PrepareDirectories resolves the
// paths first and then calls this, which is the check that holds.
func Overlaps(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	separator := string(filepath.Separator)
	return a == b || strings.HasPrefix(a, b+separator) || strings.HasPrefix(b, a+separator)
}

// PrepareDirectories creates the output directory, and the state directory
// when one is configured, then refuses a pair where one resolves inside the
// other.
//
// Call it before LoadOrNew. Resolving the paths needs them to exist, and a
// refused pair must never have a key written into it.
func PrepareDirectories(stateDir, outDir string) error {
	if err := os.MkdirAll(outDir, outDirMode); err != nil {
		return fmt.Errorf("ca: create %s: %w", outDir, err)
	}
	if stateDir == "" {
		return nil
	}
	if err := os.MkdirAll(stateDir, stateDirMode); err != nil {
		return fmt.Errorf("ca: create %s: %w", stateDir, err)
	}
	resolvedState, err := filepath.EvalSymlinks(stateDir)
	if err != nil {
		return fmt.Errorf("ca: resolve %s: %w", stateDir, err)
	}
	resolvedOut, err := filepath.EvalSymlinks(outDir)
	if err != nil {
		return fmt.Errorf("ca: resolve %s: %w", outDir, err)
	}
	if Overlaps(resolvedState, resolvedOut) {
		return fmt.Errorf("%w: %s resolves to %s, and %s to %s",
			errSharedDirectory, stateDir, resolvedState, outDir, resolvedOut)
	}
	return nil
}

// LoadOrNew returns the authority held in stateDir, or mints one and stores
// it there. An empty stateDir mints an authority that lives in process
// memory alone. Otherwise stateDir must be on a memory-backed filesystem (tmpfs).
//
// The second return value is true when LoadOrNew loaded a previously written
// authority.
func LoadOrNew(stateDir string, opts Options) (*Authority, bool, error) {
	if stateDir == "" {
		authority, err := New(opts)
		return authority, false, err
	}
	if err := os.MkdirAll(stateDir, stateDirMode); err != nil {
		return nil, false, fmt.Errorf("ca: create %s: %w", stateDir, err)
	}
	if err := requireMemoryBacked(stateDir); err != nil {
		return nil, false, err
	}
	authority, err := load(stateDir, opts)
	switch {
	case err == nil:
		return authority, true, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, false, err
	}
	authority, err = New(opts)
	if err != nil {
		return nil, false, err
	}
	if err := authority.store(stateDir); err != nil {
		return nil, false, err
	}
	return authority, false, nil
}

// load reads the authority from dir. A missing file reads as fs.ErrNotExist.
// Any other problem with the material reads as errMaterial.
func load(dir string, opts Options) (*Authority, error) { //nolint:cyclop // breaking this up doesn't aid readability
	opts = opts.withDefaults()
	keyPEM, err := os.ReadFile(filepath.Join(dir, keyFileName)) //nolint:gosec // G304: dir is ca.state_dir
	if err != nil {
		return nil, fmt.Errorf("ca: read key: %w", err)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, certFileName)) //nolint:gosec // G304: dir is ca.state_dir
	if err != nil {
		return nil, fmt.Errorf("ca: read certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	certBlock, _ := pem.Decode(certPEM)
	if keyBlock == nil || certBlock == nil {
		return nil, fmt.Errorf("%w: %s holds no PEM block", errMaterial, dir)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errMaterial, err)
	}
	key, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: the key is not ECDSA", errMaterial)
	}
	authority, err := fromMaterial(opts, certBlock.Bytes, key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errMaterial, err)
	}
	if !key.PublicKey.Equal(authority.cert.PublicKey) {
		return nil, fmt.Errorf("%w: the key does not match the certificate", errMaterial)
	}
	if now := opts.Now(); !now.Before(authority.cert.NotAfter.Add(-renewBefore)) {
		return nil, fmt.Errorf("%w: the certificate expires at %s", errMaterial,
			authority.cert.NotAfter.Format(time.RFC3339))
	}
	if !authority.cert.IsCA {
		return nil, fmt.Errorf("%w: not a CA certificate", errMaterial)
	}
	// x509.CreateCertificate does not check the parent's key usage. A
	// certificate without KeyUsageCertSign mints leaves that every client
	// rejects at chain verification, so refuse it at load.
	if authority.cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("%w: the certificate cannot sign certificates", errMaterial)
	}
	return authority, nil
}

// store writes the key and certificate to dir. It creates each file with its
// final mode, then renames it into place.
func (a *Authority) store(dir string) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(a.key)
	if err != nil {
		return fmt.Errorf("ca: encode key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeFile(filepath.Join(dir, keyFileName), keyPEM, keyFileMode); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, certFileName), a.certPEM, keyFileMode)
}

func writeFile(final string, data []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(final), filepath.Base(final)+".tmp*")
	if err != nil {
		return fmt.Errorf("ca: create temporary file for %s: %w", final, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("ca: chmod %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("ca: write %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("ca: close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("ca: rename %s to %s: %w", tmpName, final, err)
	}
	return nil
}
