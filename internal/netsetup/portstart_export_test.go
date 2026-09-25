//go:build linux

package netsetup

// UnprivilegedPortStartAt exports unprivilegedPortStartAt for tests.
func UnprivilegedPortStartAt(path string) (int, error) { return unprivilegedPortStartAt(path) }

// ErrPortStart exports errPortStart for tests.
var ErrPortStart = errPortStart
