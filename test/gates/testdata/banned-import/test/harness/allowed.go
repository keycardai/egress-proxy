//go:build gate_negative

// Package harness stands in for a test that runs a fixture.
// The import gate exempts it, so this import raises nothing.
package harness

import "github.com/keycardai/egress-proxy/test/fakeas"

// Allowed reaches the test fixture from a file under test/ so the import is used.
const Allowed = fakeas.Name
