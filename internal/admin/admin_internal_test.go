package admin

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunReturnsTheServeFailure covers the arm of Run that wraps a Serve
// error. Closing the listener is the only way to make Serve fail, and the
// Server does not export it, so this case lives inside the package.
func TestRunReturnsTheServeFailure(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "admin.sock")
	server, err := New(t.Context(), path, func() any { return nil }, nil)
	require.NoError(t, err, "New")

	require.NoError(t, server.listener.Close(), "close the listener out from under Serve")
	err = server.Run(t.Context())
	require.Error(t, err, "Run over a closed listener")
	require.ErrorIs(t, err, net.ErrClosed, "the failure names the closed listener")
	assert.ErrorContains(t, err, "admin: serve", "the failure says where it came from")
}
