package netsetup

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// ErrNoResolver is returned when a resolv.conf names no usable resolver. A
// filter chain with no DNS accept drops every resolution, so the workload
// then reaches nothing by name.
var ErrNoResolver = errors.New("no usable resolver")

// Nameservers reads the resolvers out of a resolv.conf, in the order the
// file lists them. It returns an error when the file names none, because a
// filter chain with no DNS accept drops every resolution and the workload
// then reaches nothing by name.
//
// The format is resolv.conf(5): one directive per line, "nameserver
// <address>", with "#" and ";" starting a comment.
func Nameservers(path string) ([]netip.Addr, error) {
	//nolint:gosec // G304: the path comes from this command's own flags
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read the resolvers: %w", err)
	}
	defer func() { _ = file.Close() }()
	var servers []netip.Addr
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line, _, _ = strings.Cut(line, ";")
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "nameserver" {
			continue
		}
		addr, parseErr := netip.ParseAddr(fields[1])
		if parseErr != nil {
			return nil, fmt.Errorf("%w: %s names the resolver %q, which is not an address",
				ErrNoResolver, path, fields[1])
		}
		servers = append(servers, addr.Unmap())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("%w: %s names no resolver", ErrNoResolver, path)
	}
	return servers, nil
}
