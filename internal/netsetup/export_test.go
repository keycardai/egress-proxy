package netsetup

// KernelHasIPv6At exports kernelHasIPv6At for tests.
func KernelHasIPv6At(path string) (bool, error) { return kernelHasIPv6At(path) }
