package ca_test

import (
	"crypto/x509"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/ca"
)

func newAuthority(t *testing.T, opts ca.Options) *ca.Authority {
	t.Helper()
	authority, err := ca.New(opts)
	require.NoError(t, err, "ca.New")
	return authority
}

func TestAuthorityCertificate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	authority := newAuthority(t, ca.Options{Now: func() time.Time { return now }, TTL: 48 * time.Hour})
	cert := authority.Certificate()
	assert.True(t, cert.IsCA, "IsCA")
	assert.True(t, cert.BasicConstraintsValid, "BasicConstraintsValid")
	assert.True(t, cert.MaxPathLenZero, "MaxPathLenZero: the CA signs leaves and no intermediate")
	assert.Equal(t, now.Add(-time.Hour), cert.NotBefore, "NotBefore is backdated one hour")
	assert.Equal(t, now.Add(48*time.Hour), cert.NotAfter, "NotAfter is now plus the TTL")
	assert.Equal(t, "Keycard egress proxy CA", cert.Subject.CommonName, "CommonName")
	assert.True(t, strings.HasPrefix(string(authority.CertificatePEM()), "-----BEGIN CERTIFICATE-----"),
		"CertificatePEM is PEM")
}

func TestLeafVerifiesAgainstThePoolAndNothingElse(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	authority := newAuthority(t, ca.Options{
		Now: func() time.Time { return now }, TTL: 10 * time.Hour, LeafTTL: 24 * time.Hour,
	})
	tests := []struct {
		name     string
		host     string
		verifyAs string
		wantErr  bool
	}{
		{name: "the minted name verifies", host: "API.GitHub.com.", verifyAs: "api.github.com"},
		{name: "another name does not", host: "api.github.com", verifyAs: "github.com", wantErr: true},
		{name: "an IP literal is a SAN", host: "127.0.0.1", verifyAs: "127.0.0.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			leaf, err := authority.Leaf(tc.host)
			require.NoError(t, err, "Leaf")
			require.Len(t, leaf.Certificate, 2, "the chain is the leaf and the CA")
			// A leaf never outlives the authority.
			assert.Equal(t, authority.NotAfter(), leaf.Leaf.NotAfter, "leaf NotAfter is the CA's")
			_, err = leaf.Leaf.Verify(x509.VerifyOptions{
				DNSName: tc.verifyAs, Roots: authority.Pool(), CurrentTime: now,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if tc.wantErr {
				assert.Error(t, err, "Verify as %q", tc.verifyAs)
				return
			}
			assert.NoError(t, err, "Verify as %q", tc.verifyAs)
		})
	}
	_, err := authority.Leaf("")
	assert.Error(t, err, "Leaf with no name is refused")
}

func TestWriteCertificateWritesOnlyTheCertificate(t *testing.T) {
	t.Parallel()
	authority := newAuthority(t, ca.Options{})
	dir := filepath.Join(t.TempDir(), "shared-ca")
	path, err := authority.WriteCertificate(dir)
	require.NoError(t, err, "WriteCertificate")
	assert.Equal(t, filepath.Join(dir, ca.CertificateFileName), path, "the path it reports")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "the directory holds one file")
	assert.Equal(t, ca.CertificateFileName, entries[0].Name(), "and it is the certificate")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm(), "mode, so the workload's uid can read it")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(authority.CertificatePEM()), string(data), "the file is the CA certificate")
	require.NotContains(t, string(data), "PRIVATE KEY", "the output directory holds no key material")
}

func TestStoreCachesAndRenews(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	authority := newAuthority(t, ca.Options{Now: clock, LeafTTL: time.Hour})
	store, err := ca.NewStore(authority, 2)
	require.NoError(t, err, "NewStore")

	first, err := store.Certificate("a.example")
	require.NoError(t, err)
	again, err := store.Certificate("A.Example.")
	require.NoError(t, err)
	assert.Same(t, first, again, "one leaf for two spellings of one name")
	assert.Equal(t, int64(1), store.Mints(), "Mints after a hit")

	// The cache holds two, so a third name evicts the least recently used.
	for _, name := range []string{"b.example", "c.example"} {
		_, mintErr := store.Certificate(name)
		require.NoError(t, mintErr, "Certificate(%q)", name)
	}
	assert.Equal(t, 2, store.Len(), "the cache holds its size and no more")

	// Within five minutes of expiry the store mints a new leaf.
	now = now.Add(56 * time.Minute)
	renewed, err := store.Certificate("c.example")
	require.NoError(t, err)
	require.NotNil(t, renewed)
	assert.NotEqual(t, first.Leaf.NotBefore, renewed.Leaf.NotBefore, "an expiring leaf is re-minted")
	assert.Equal(t, int64(4), store.Mints(), "Mints after the renewal")
}

// TestPrepareDirectoriesRefusesASymlinkedStateDirectory covers what the
// document check in internal/config cannot: the two paths do not overlap as
// text, and the state directory resolves inside the output directory the
// workload reads.
func TestPrepareDirectoriesRefusesASymlinkedStateDirectory(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	outDir := filepath.Join(base, "shared-ca")
	inner := filepath.Join(outDir, "inner")
	require.NoError(t, os.MkdirAll(inner, 0o750))
	stateDir := filepath.Join(base, "state-link")
	require.NoError(t, os.Symlink(inner, stateDir))

	err := ca.PrepareDirectories(stateDir, outDir)
	require.ErrorContains(t, err, "overlap", "a link into the output directory is refused")

	// A pair that does not overlap is prepared, and both directories exist.
	apart := filepath.Join(base, "state")
	require.NoError(t, ca.PrepareDirectories(apart, outDir))
	for _, dir := range []string{apart, outDir} {
		info, statErr := os.Stat(dir)
		require.NoError(t, statErr, "%s", dir)
		assert.True(t, info.IsDir(), "%s is a directory", dir)
	}
}

func TestLoadOrNewWithoutAStateDirectoryMints(t *testing.T) {
	t.Parallel()
	authority, loaded, err := ca.LoadOrNew("", ca.Options{})
	require.NoError(t, err, "LoadOrNew with no state directory")
	assert.NotNil(t, authority, "it mints an authority")
	assert.False(t, loaded, "and reports that it minted rather than loaded")
}

func TestLoadOrNewRefusesADiskDirectory(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "state")
	_, _, err := ca.LoadOrNew(dir, ca.Options{})
	require.ErrorContains(t, err, "not on a memory-backed filesystem", "LoadOrNew on a disk directory")
	// LoadOrNew creates the directory before it proves the filesystem, so
	// the directory exists and reading it must succeed. Discarding that
	// error would let an absent directory satisfy the emptiness check.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "read the refused state directory")
	assert.Empty(t, entries, "a refused state directory holds nothing")
}

// memoryDir returns a directory on tmpfs. It skips the test when the host
// has none.
func memoryDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("a memory-backed directory can be shown only on Linux")
	}
	dir, err := os.MkdirTemp("/dev/shm", "egress-proxy-ca-*") //nolint:usetesting // t.TempDir is not on tmpfs
	if err != nil {
		t.Skipf("no tmpfs at /dev/shm: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestLoadOrNewPersistsInAMemoryDirectory(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(memoryDir(t), "state")
	first, loaded, err := ca.LoadOrNew(dir, ca.Options{})
	require.NoError(t, err, "first LoadOrNew")
	assert.False(t, loaded, "the first run mints")
	for _, name := range []string{"ca.key", "ca.crt"} {
		info, statErr := os.Stat(filepath.Join(dir, name))
		require.NoError(t, statErr, "%s", name)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "%s mode", name)
	}
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "state directory mode")

	second, loaded, err := ca.LoadOrNew(dir, ca.Options{})
	require.NoError(t, err, "second LoadOrNew")
	assert.True(t, loaded, "the second run loads rather than mints")
	assert.True(t, second.Certificate().Equal(first.Certificate()), "both runs hold one authority")
	leaf, err := second.Leaf("a.example")
	require.NoError(t, err)
	_, err = leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "a.example", Roots: first.Pool()})
	assert.NoError(t, err, "a leaf from the loaded authority verifies against the first")
}

func TestLoadOrNewRefusesCorruptMaterial(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(memoryDir(t), "state")
	_, _, err := ca.LoadOrNew(dir, ca.Options{})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.key"), []byte("not a key"), 0o600))
	_, _, err = ca.LoadOrNew(dir, ca.Options{})
	require.ErrorContains(t, err, "stored material refused", "LoadOrNew over a corrupt key")
	assert.NotErrorIs(t, err, fs.ErrNotExist, "a corrupt key does not read as a missing one")
}
