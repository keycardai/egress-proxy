//go:build linux

package netsetup

// NetNamespaceAt exposes netNamespaceAt to tests.
func NetNamespaceAt(path string) (NetNamespace, error) { return netNamespaceAt(path) }
