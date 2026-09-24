package netsetup_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// now is the clock the fixture receipt is dated against, so a case that
// turns on the receipt's age says so in its own edit.
//
//nolint:gochecknoglobals // a fixture the cases share
var now = time.Date(2026, time.September, 23, 12, 0, 0, 0, time.UTC)

// writeFile writes a fixture into the test's own directory and returns its
// path.
func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

// contained is the receipt a sidecar starts on: the rules were applied,
// verified and then made unchangeable.
func contained() netsetup.Receipt {
	cfg := netsetup.DefaultConfig()
	cfg.DNSServers = valid().DNSServers
	programs := make([]netsetup.Program, 0, len(cfg.Families()))
	for _, family := range cfg.Families() {
		program, err := cfg.Program(family)
		if err != nil {
			panic(err)
		}
		programs = append(programs, program)
	}
	receipt := netsetup.NewReceipt(cfg, programs, true, now.Add(-time.Minute))
	receipt.CapabilitiesDropped = true
	return receipt
}

// place writes a receipt at 0644 in a directory at 0755, which is what the
// init container leaves, and returns its path.
func place(t *testing.T, receipt netsetup.Receipt) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "egress")
	require.NoError(t, os.MkdirAll(dir, 0o755)) //nolint:gosec // G301: the sidecar traverses it as another uid
	path := filepath.Join(dir, "netsetup.json")
	require.NoError(t, netsetup.WriteReceipt(path, receipt))
	return path
}

// TestRemoveReceiptLeavesNothingBehind proves the unlink a failed run
// depends on. A receipt an earlier run left says the rules are in force when
// they are not.
func TestRemoveReceiptLeavesNothingBehind(t *testing.T) {
	t.Parallel()
	path := place(t, contained())
	require.NoError(t, netsetup.RemoveReceipt(path), "remove the receipt")
	_, err := os.Stat(path)
	require.ErrorIs(t, err, fs.ErrNotExist, "the receipt is gone")
	require.NoError(t, netsetup.RemoveReceipt(path), "removing a receipt that is already gone is not a failure")
}
