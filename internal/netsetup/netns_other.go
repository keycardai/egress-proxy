//go:build !linux

package netsetup

// CurrentNetNamespace has no implementation on this platform.
func CurrentNetNamespace() (NetNamespace, error) { return NetNamespace{}, ErrNetNamespaceNotSupported }
