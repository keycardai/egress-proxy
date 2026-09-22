//go:build linux

package ca

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// requireMemoryBacked reports errNotMemoryBacked unless dir is on tmpfs. A
// Kubernetes emptyDir with medium Memory mounts tmpfs.
func requireMemoryBacked(dir string) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(dir, &stat); err != nil {
		return fmt.Errorf("ca: statfs %s: %w", dir, err)
	}
	if stat.Type != unix.TMPFS_MAGIC {
		return fmt.Errorf("%w: %s has filesystem type %#x", errNotMemoryBacked, dir, stat.Type)
	}
	return nil
}
