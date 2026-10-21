package audit_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/audit"
)

// TestStampedKeepsASandboxTheRequestNamed pins how a request-scoped record
// that already names a sandbox survives the stamp: the process-level
// sandbox.id fills only an empty field, so an assertion-identified sandbox
// reaches the stream.
func TestStampedKeepsASandboxTheRequestNamed(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	stamped := audit.NewStamped(audit.NewJSONSink(&buf), audit.Stamp{SandboxID: "openshell-local"},
		func() time.Time { return time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC) })

	stamped.Emit(audit.Record{Scope: audit.ScopeConnection})
	stamped.Emit(audit.Record{
		Scope:       audit.ScopeRequest,
		SandboxID:   "keycard-demo",
		SandboxUUID: "26697100-f1ee-45cf-8ab9-8ee6fb645700",
		Application: "review-agent",
		Identity:    &audit.Identity{ClientID: "demo-application"},
	})

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	require.Len(t, lines, 2)
	var connection, request map[string]any
	require.NoError(t, json.Unmarshal(lines[0], &connection))
	require.NoError(t, json.Unmarshal(lines[1], &request))
	assert.Equal(t, "openshell-local", connection["sandbox_id"], "an empty field takes the process sandbox")
	assert.NotContains(t, connection, "sandbox_uuid")
	assert.NotContains(t, connection, "application")
	assert.NotContains(t, connection, "identity")
	assert.Equal(t, "keycard-demo", request["sandbox_id"], "a named sandbox is kept")
	assert.Equal(t, "26697100-f1ee-45cf-8ab9-8ee6fb645700", request["sandbox_uuid"])
	assert.Equal(t, "review-agent", request["application"])
	assert.Equal(t, map[string]any{"client_id": "demo-application"}, request["identity"])
}
