//go:build !linux && !darwin

package ca

import "fmt"

// requireMemoryBacked refuses every directory. This platform cannot prove
// that a directory is memory-backed, and the key goes only where that proof
// holds. Development here runs without a state directory.
func requireMemoryBacked(dir string) error {
	return fmt.Errorf("%w: %s cannot be checked on this platform", errNotMemoryBacked, dir)
}
