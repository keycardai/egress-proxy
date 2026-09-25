//go:build !linux

package netsetup

// DropNetAdmin is not supported on this platform.
func DropNetAdmin() error { return ErrCapabilitiesNotSupported }

// HasNetAdmin cannot read capabilities on this platform.
func HasNetAdmin() (bool, error) { return false, ErrCapabilitiesNotSupported }
