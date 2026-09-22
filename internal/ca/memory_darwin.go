//go:build darwin

package ca

import (
	"bytes"
	"fmt"

	"golang.org/x/sys/unix"
)

// requireMemoryBacked reports errNotMemoryBacked unless dir is on a
// filesystem named tmpfs. macOS mounts no tmpfs by default, so this refuses
// every state directory on a stock machine. Development on macOS runs
// without one.
func requireMemoryBacked(dir string) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(dir, &stat); err != nil {
		return fmt.Errorf("ca: statfs %s: %w", dir, err)
	}
	name := string(bytes.TrimRight(stat.Fstypename[:], "\x00"))
	if name != "tmpfs" {
		return fmt.Errorf("%w: %s has filesystem type %q", errNotMemoryBacked, dir, name)
	}
	return nil
}
