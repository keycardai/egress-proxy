//go:build linux

package netsetup

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// netNamespacePath is this process's network namespace link. stat follows
// it to the namespace itself (namespaces(7), The /proc/[pid]/ns/ directory).
const netNamespacePath = "/proc/self/ns/net"

// CurrentNetNamespace reads the identity of this process's network
// namespace.
func CurrentNetNamespace() (NetNamespace, error) {
	return netNamespaceAt(netNamespacePath)
}

// netNamespaceAt reads the device and inode of the namespace at path.
func netNamespaceAt(path string) (NetNamespace, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return NetNamespace{}, fmt.Errorf("stat %s: %w", path, err)
	}
	return NetNamespace{Device: stat.Dev, Inode: stat.Ino}, nil
}
