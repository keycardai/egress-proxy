//go:build !linux

package netsetup

// DropNetAdmin is not supported on this platform.
func DropNetAdmin() error { return ErrCapabilitiesNotSupported }
