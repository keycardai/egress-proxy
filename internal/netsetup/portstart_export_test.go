//go:build linux

package netsetup

// UnprivilegedPortStartAt exposes unprivilegedPortStartAt to tests.
func UnprivilegedPortStartAt(path string) (int, error) { return unprivilegedPortStartAt(path) }

// ErrPortStart exposes errPortStart to tests.
var ErrPortStart = errPortStart
