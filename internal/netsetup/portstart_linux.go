//go:build linux

package netsetup

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// unprivilegedPortStartPath is the lowest port a process with no
// CAP_NET_BIND_SERVICE may bind. Source: linux
// Documentation/networking/ip-sysctl.rst, ip_unprivileged_port_start. Its
// default is 1024.
const unprivilegedPortStartPath = "/proc/sys/net/ipv4/ip_unprivileged_port_start"

// UnprivilegedPortStart reads the lowest port a process with no
// CAP_NET_BIND_SERVICE may bind. The setting covers both address families,
// which is why it is read from the IPv4 path alone.
func UnprivilegedPortStart() (int, error) {
	body, err := os.ReadFile(unprivilegedPortStartPath)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", unprivilegedPortStartPath, err)
	}
	start, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil {
		return 0, fmt.Errorf("%s holds %q, which is not a port number", unprivilegedPortStartPath,
			strings.TrimSpace(string(body)))
	}
	return start, nil
}
