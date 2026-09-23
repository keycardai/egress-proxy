//go:build gate_negative

package fixture

import "github.com/keycardai/egress-proxy/test/fakeas"

// Shipped reaches the test fixture from a non-test file so the import is used.
const Shipped = fakeas.Name
