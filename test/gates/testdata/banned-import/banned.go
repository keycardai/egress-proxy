//go:build gate_negative

package fixture

import "github.com/keycardlabs/gatefixture"

// Banned reaches the internal module so the import is used.
const Banned = gatefixture.Name
