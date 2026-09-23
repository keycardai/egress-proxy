//go:build !linux

package netsetup

// UnprivilegedPortStart is not supported on this platform.
func UnprivilegedPortStart() (int, error) { return 0, ErrPortStartNotSupported }
