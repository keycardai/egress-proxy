//go:build !linux

package netsetup

// UnprivilegedPortStart has no implementation on this platform.
func UnprivilegedPortStart() (int, error) { return 0, ErrPortStartNotSupported }
