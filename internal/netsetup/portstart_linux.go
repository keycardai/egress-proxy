//go:build linux

package netsetup

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// unprivilegedPortStartPath names the sysctl for the lowest port a process
// without CAP_NET_BIND_SERVICE can bind. See Linux
// Documentation/networking/ip-sysctl.rst, ip_unprivileged_port_start. Its
// default is 1024.
const unprivilegedPortStartPath = "/proc/sys/net/ipv4/ip_unprivileged_port_start"

// errPortStart reports a sysctl value that is not a port number.
var errPortStart = errors.New("the unprivileged port start is not a port number")

// UnprivilegedPortStart reads the lowest port a process without
// CAP_NET_BIND_SERVICE can bind. The setting covers both address families,
// so this function reads the IPv4 path. An IPv6 bind checks it too (Linux
// net/ipv6/af_inet6.c, __inet6_bind, and inet_port_requires_bind_service).
func UnprivilegedPortStart() (int, error) {
	return unprivilegedPortStartAt(unprivilegedPortStartPath)
}

// unprivilegedPortStartAt reads the sysctl at path.
func unprivilegedPortStartAt(path string) (int, error) {
	body, err := os.ReadFile(path) //nolint:gosec // G304: the sysctl path, or a test fixture
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	held := strings.TrimSpace(string(body))
	start, err := strconv.Atoi(held)
	if err != nil {
		return 0, fmt.Errorf("%w: %s holds %q", errPortStart, path, held)
	}
	return start, nil
}
