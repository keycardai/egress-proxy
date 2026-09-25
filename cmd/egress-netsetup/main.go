// Command egress-netsetup programs the iptables rules that send a sandbox
// pod's outbound TCP traffic into the egress proxy and drop everything else.
// It runs as an init container with NET_ADMIN and SETPCAP, gives up
// NET_ADMIN once the rules are in place, and exits. SETPCAP is what lets it
// take NET_ADMIN out of the bounding set.
//
// A run that puts the whole ruleset in force writes a receipt, a JSON file on
// the emptyDir that the init container and the sidecar are intended to share.
// It names the proxy uid, the redirect port, the capture ports and the families
// programmed, a digest of the ruleset, whether CAP_NET_ADMIN went, and the
// network namespace the rules govern. The
// sidecar runs without that capability and cannot read the tables, so the
// receipt is how it checks its own containment against rules it has no way to
// see. netsetup.Receipt holds the format and what makes the file trustworthy.
//
// Each family's ruleset goes in with one iptables-restore run, and the
// kernel replaces each table in one operation. Re-running installs the same
// rules and no second copy. A run that fails unlinks the receipt and exits
// non-zero. netsetup.Apply says what a failure leaves in the tables.
//
// --dry-run prints the ruleset and --verify reads the tables back. Neither
// writes the receipt.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/keycardai/egress-proxy/internal/netsetup"
)

func main() {
	if err := command(os.Stdout, nil).Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "egress-netsetup: %v\n", err)
		os.Exit(1)
	}
}

// settings are what the command line supplies.
type settings struct {
	proxyUID       int
	redirectPort   int
	capturePorts   []string
	podCIDRs       []string
	serviceCIDRs   []string
	dnsServers     []string
	resolvConf     string
	ipv6           string
	iptables       string
	ip6tables      string
	receipt        string
	dryRun         bool
	verifyOnly     bool
	keepNetAdmin   bool
	portProtection string
	portStartFile  string
}

// opener resolves the handle and the binary for one address family. A nil
// opener uses the real iptables binary, which is what every caller outside
// a test passes.
type opener func(ctx context.Context, family netsetup.Family, override string) (netsetup.Tables, netsetup.Tool, error)

// openTables resolves the legacy iptables binary for a family.
//
//nolint:ireturn // the interface is the seam a test substitutes a recorded ruleset at
func openTables(ctx context.Context, family netsetup.Family, override string) (netsetup.Tables, netsetup.Tool, error) {
	return netsetup.Open(ctx, family, override) //nolint:wrapcheck // eachFamily names the family that failed
}

// command builds the command line.
//
// NEVER give a flag here an environment variable source. An init container's
// settings are its arguments, so a manifest review reads the whole ruleset
// off the pod spec. A variable can take its value from a ConfigMap or Secret
// the spec only references, and envFrom imports every key from one without
// the spec naming any of them. Source:
// https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/
func command(out io.Writer, open opener) *cli.Command {
	var opts settings
	if open == nil {
		open = openTables
	}
	return &cli.Command{
		Name:  "egress-netsetup",
		Usage: "programs the sandbox egress rules with iptables-legacy",
		Description: "Re-running it installs the same rules and no second copy. Each table is replaced\n" +
			"in one kernel operation, so a failed run leaves the table as it was.",
		Writer:          out,
		ErrWriter:       out,
		HideVersion:     true,
		HideHelpCommand: true,
		Flags:           flagSet(&opts),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return run(ctx, cmd, opts, open, out)
		},
	}
}

// errUsage is every refusal that comes from the command line rather than
// from the tables.
var errUsage = errors.New("egress-netsetup")

func run(ctx context.Context, cmd *cli.Command, opts settings, open opener, out io.Writer) error {
	if cmd.Args().Len() > 0 {
		return fmt.Errorf("%w: unexpected argument %q", errUsage, cmd.Args().First())
	}
	if err := opts.validate(); err != nil {
		return err
	}
	// NEVER let a run that programs the rules fail with an earlier run's
	// receipt in place. The receipt is the sidecar's only evidence of its own
	// containment, and one an earlier run wrote says rules are in force that
	// this run may never have put there.
	if !opts.dryRun && !opts.verifyOnly {
		if err := netsetup.RemoveReceipt(opts.receipt); err != nil {
			return fmt.Errorf("netsetup: %w", err)
		}
	}
	cfg, err := opts.config(out, netsetup.KernelHasIPv6)
	if err != nil {
		return err
	}
	switch {
	case opts.dryRun:
		return dryRun(cfg, out)
	case opts.verifyOnly:
		return verify(ctx, cfg, opts, open, out)
	}
	// A receipt WriteReceipt left part written is removed too.
	if err := program(ctx, cfg, opts, open, out); err != nil {
		return errors.Join(err, netsetup.RemoveReceipt(opts.receipt))
	}
	return nil
}

const maxPort = 65535

// checkRedirectPort refuses a redirect port that a process without
// NET_BIND_SERVICE can bind. path holds net.ipv4.ip_unprivileged_port_start.
func checkRedirectPort(port int, path string) error {
	//nolint:gosec // G304: the path comes from this command's own flags
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read net.ipv4.ip_unprivileged_port_start: %w", err)
	}
	start, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil {
		return fmt.Errorf("parse net.ipv4.ip_unprivileged_port_start: %w", err)
	}
	if start < 0 || start > maxPort {
		return fmt.Errorf("%w: net.ipv4.ip_unprivileged_port_start=%d is outside 0-65535", errUsage, start)
	}
	if port >= start {
		return fmt.Errorf("%w: redirect port %d must be below net.ipv4.ip_unprivileged_port_start=%d",
			errUsage, port, start)
	}
	return nil
}

// validate rejects an unknown --redirect-port-protection mode and a command
// line that asks for two different runs.
func (s settings) validate() error {
	switch netsetup.PortProtection(s.portProtection) {
	case netsetup.PortProtectionRequired, netsetup.PortProtectionAllowUnprotected:
	default:
		return fmt.Errorf("%w: --redirect-port-protection must be %s or %s", errUsage,
			netsetup.PortProtectionRequired, netsetup.PortProtectionAllowUnprotected)
	}
	if s.dryRun && s.verifyOnly {
		return fmt.Errorf("%w: --dry-run prints the ruleset and --verify reads the tables back. Give one",
			errUsage)
	}
	if s.verifyOnly && s.keepNetAdmin {
		return fmt.Errorf("%w: --verify drops no capability, so --keep-net-admin has nothing to keep", errUsage)
	}
	return nil
}

// ipv6Probe reports whether the kernel has IPv6. netsetup.KernelHasIPv6 is
// the probe every caller outside a test passes.
type ipv6Probe func() (bool, error)

// config turns the flags into a validated ruleset input.
func (s settings) config(out io.Writer, hasIPv6 ipv6Probe) (netsetup.Config, error) {
	cfg := netsetup.Config{ProxyUID: s.proxyUID, RedirectPort: s.redirectPort}
	var err error
	if cfg.CapturePorts, err = parsePorts(s.capturePorts); err != nil {
		return cfg, fmt.Errorf("--capture-ports: %w", err)
	}
	if cfg.PodCIDRs, err = parsePrefixes(s.podCIDRs); err != nil {
		return cfg, fmt.Errorf("--pod-cidrs: %w", err)
	}
	if cfg.ServiceCIDRs, err = parsePrefixes(s.serviceCIDRs); err != nil {
		return cfg, fmt.Errorf("--service-cidrs: %w", err)
	}
	if cfg.DNSServers, err = parseAddrs(s.dnsServers); err != nil {
		return cfg, fmt.Errorf("--dns-servers: %w", err)
	}
	if len(cfg.DNSServers) == 0 {
		if cfg.DNSServers, err = netsetup.Nameservers(s.resolvConf); err != nil {
			return cfg, fmt.Errorf("--resolv-conf: %w. Name the resolvers with --dns-servers", err)
		}
		fmt.Fprintf(out, "# resolvers from %s: %s\n", s.resolvConf, joinAddrs(cfg.DNSServers))
	}
	if cfg.IPv6, err = resolveIPv6(s.ipv6, hasIPv6, out); err != nil {
		return cfg, fmt.Errorf("--ipv6: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("netsetup: %w", err)
	}
	return cfg, nil
}

// dryRun prints the ruleset each family would get and applies nothing.
func dryRun(cfg netsetup.Config, out io.Writer) error {
	for _, family := range cfg.Families() {
		program, err := cfg.Program(family)
		if err != nil {
			return fmt.Errorf("netsetup: %w", err)
		}
		fmt.Fprint(out, program.String())
	}
	return nil
}

// eachFamily opens the tool for every family the configuration programs and
// runs action against it. It returns the rulesets it built, in family order.
func eachFamily(
	ctx context.Context,
	cfg netsetup.Config,
	opts settings,
	open opener,
	out io.Writer,
	action func(handle netsetup.Tables, built netsetup.Program) error,
) ([]netsetup.Program, error) {
	if netsetup.PortProtection(opts.portProtection) == netsetup.PortProtectionAllowUnprotected {
		fmt.Fprintln(out, "# WARNING: redirect-port protection is waived. A workload can bind the redirect port "+
			"and receive redirected traffic that bypasses the proxy")
	} else if err := checkRedirectPort(cfg.RedirectPort, opts.portStartFile); err != nil {
		return nil, err
	}
	programs := make([]netsetup.Program, 0, len(cfg.Families()))
	for _, family := range cfg.Families() {
		built, err := cfg.Program(family)
		if err != nil {
			return nil, fmt.Errorf("netsetup: %w", err)
		}
		programs = append(programs, built)
		override := opts.iptables
		if family == netsetup.FamilyIPv6 {
			override = opts.ip6tables
		}
		handle, tool, err := open(ctx, family, override)
		if err != nil {
			return nil, fmt.Errorf("netsetup: %w", err)
		}
		fmt.Fprintf(out, "# %s: %s (%s), %s\n", family, tool.Path, tool.Version, tool.Restore)
		if err := action(handle, built); err != nil {
			return nil, fmt.Errorf("netsetup: %w", err)
		}
	}
	return programs, nil
}

// verify reads the tables back on every family and reports whether the
// ruleset this command line describes is in force.
//
// NEVER let it write the receipt or drop a capability. A --verify run
// programs nothing, so a receipt it wrote would give the sidecar evidence of
// a containment this process never established, and one written here would
// replace a receipt that correctly says CAP_NET_ADMIN is still held.
func verify(ctx context.Context, cfg netsetup.Config, opts settings, open opener, out io.Writer) error {
	programs, err := eachFamily(ctx, cfg, opts, open, out,
		func(handle netsetup.Tables, built netsetup.Program) error {
			return netsetup.Verify(handle, built, out)
		})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "# --verify: the ruleset is in force: %s. Nothing was written\n",
		netsetup.RulesetDigest(programs))
	return nil
}

// program applies and verifies the ruleset on every family, gives up
// CAP_NET_ADMIN and writes the receipt. Every failure it returns leaves the
// receipt to be unlinked by the caller.
func program(ctx context.Context, cfg netsetup.Config, opts settings, open opener, out io.Writer) error {
	programs, err := eachFamily(ctx, cfg, opts, open, out,
		func(handle netsetup.Tables, built netsetup.Program) error {
			if err := netsetup.Apply(ctx, handle, built, out); err != nil {
				return err //nolint:wrapcheck // eachFamily names the family that failed
			}
			return netsetup.Verify(handle, built, out)
		})
	if err != nil {
		return err
	}
	receipt := netsetup.NewReceipt(cfg, programs, true, time.Now())
	receipt.RedirectPortProtection = netsetup.PortProtection(opts.portProtection)
	if err := recordNetNamespace(&receipt); err != nil {
		return err
	}
	if err := dropNetAdmin(opts.keepNetAdmin, &receipt, out); err != nil {
		return err
	}
	if err := netsetup.WriteReceipt(opts.receipt, receipt); err != nil {
		return fmt.Errorf("netsetup: %w", err)
	}
	fmt.Fprintf(out, "# receipt %s: %s\n", opts.receipt, receipt.RulesetDigest)
	return nil
}

// recordNetNamespace puts the network namespace the rules were programmed in
// on the receipt. The sidecar refuses a receipt from any other namespace. A
// platform that does not report one leaves the field empty.
func recordNetNamespace(receipt *netsetup.Receipt) error {
	namespace, err := netsetup.CurrentNetNamespace()
	switch {
	case errors.Is(err, netsetup.ErrNetNamespaceNotSupported):
		return nil
	case err != nil:
		return fmt.Errorf("netsetup: %w", err)
	}
	receipt.NetNamespace = &namespace
	return nil
}

// dropNetAdmin gives up the capability that programs the tables, after they
// are verified. The receipt records whether it went. The drop covers the
// calling thread, and the process exits as soon as the receipt is written.
func dropNetAdmin(keep bool, receipt *netsetup.Receipt, out io.Writer) error {
	if keep {
		fmt.Fprintln(out, "# --keep-net-admin: CAP_NET_ADMIN is still held, and the receipt says so")
		return nil
	}
	if err := netsetup.DropNetAdmin(); err != nil {
		return fmt.Errorf("netsetup: %w", err)
	}
	receipt.CapabilitiesDropped = true
	fmt.Fprintln(out, "# CAP_NET_ADMIN dropped from every capability set on this thread, no_new_privs set")
	return nil
}

// resolveIPv6 turns the --ipv6 flag and the kernel into a mode. auto and on
// send captured IPv6 TCP into the proxy, and off drops every IPv6 packet
// the pod sends.
//
// A probe that cannot answer fails the run rather than guessing. See
// netsetup.IPv6Mode for what an ungoverned family costs.
func resolveIPv6(mode string, hasIPv6 ipv6Probe, out io.Writer) (netsetup.IPv6Mode, error) {
	if mode != "auto" && mode != "on" && mode != "off" {
		return netsetup.IPv6None, fmt.Errorf("%w: %q is not auto, on or off", errUsage, mode)
	}
	has, err := hasIPv6()
	if err != nil {
		return netsetup.IPv6None, fmt.Errorf("%w. Name --ipv6 on or --ipv6 off rather than auto", err)
	}
	if !has {
		if mode == "on" {
			return netsetup.IPv6None, fmt.Errorf("%w: on was asked for and this kernel has no IPv6", errUsage)
		}
		fmt.Fprintln(out, "# this kernel has no IPv6, so no ip6tables ruleset is programmed")
		return netsetup.IPv6None, nil
	}
	if mode == "off" {
		fmt.Fprintln(out, "# --ipv6 off: every IPv6 packet this pod sends is dropped. "+
			"Replies to inbound connections and neighbour discovery still go out")
		return netsetup.IPv6Deny, nil
	}
	return netsetup.IPv6Proxy, nil
}

func parsePorts(values []string) ([]int, error) {
	ports := make([]int, 0, len(values))
	for _, value := range values {
		for field := range strings.SplitSeq(value, ",") {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}
			port, err := strconv.Atoi(field)
			if err != nil {
				return nil, fmt.Errorf("%w: %q is not a port", errUsage, field)
			}
			ports = append(ports, port)
		}
	}
	return ports, nil
}

func parsePrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		for field := range strings.SplitSeq(value, ",") {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(field)
			if err != nil {
				return nil, fmt.Errorf("%w: %q is not a CIDR prefix", errUsage, field)
			}
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return prefixes, nil
}

func parseAddrs(values []string) ([]netip.Addr, error) {
	addrs := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		for field := range strings.SplitSeq(value, ",") {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}
			addr, err := netip.ParseAddr(field)
			if err != nil {
				return nil, fmt.Errorf("%w: %q is not an address", errUsage, field)
			}
			addrs = append(addrs, addr.Unmap())
		}
	}
	return addrs, nil
}

func portStrings(ports []int) []string {
	out := make([]string, len(ports))
	for i, port := range ports {
		out[i] = strconv.Itoa(port)
	}
	return out
}

func joinAddrs(addrs []netip.Addr) string {
	parts := make([]string, len(addrs))
	for i, addr := range addrs {
		parts[i] = addr.String()
	}
	return strings.Join(parts, ",")
}

// flagSet is the command line an init container is given.
//
//nolint:funlen // keep the declarative flag list together
func flagSet(opts *settings) []cli.Flag {
	defaults := netsetup.DefaultConfig()
	return []cli.Flag{
		&cli.IntFlag{
			Name: "proxy-uid", Value: defaults.ProxyUID, Destination: &opts.proxyUID,
			Usage: "uid the sidecar runs as; its traffic is neither redirected nor dropped",
		},
		&cli.IntFlag{
			Name: "redirect-port", Value: defaults.RedirectPort, Destination: &opts.redirectPort,
			Usage: "the sidecar's transparent listener port",
		},
		&cli.StringFlag{
			Name: "redirect-port-protection", Value: string(netsetup.PortProtectionRequired),
			Destination: &opts.portProtection,
			Usage:       "required enforces port protection; allow-unprotected skips the check",
		},
		&cli.StringFlag{
			Name: "port-start-file", Value: "/proc/sys/net/ipv4/ip_unprivileged_port_start",
			Destination: &opts.portStartFile,
			Usage:       "file net.ipv4.ip_unprivileged_port_start is read from",
		},
		&cli.StringSliceFlag{
			Name: "capture-ports", Value: portStrings(defaults.CapturePorts), Destination: &opts.capturePorts,
			Usage: "outbound TCP destination ports to redirect",
		},
		&cli.StringSliceFlag{
			Name: "pod-cidrs", Destination: &opts.podCIDRs,
			Usage: "pod CIDRs; traffic to them is not redirected and the filter DROP still covers it",
		},
		&cli.StringSliceFlag{
			Name: "service-cidrs", Destination: &opts.serviceCIDRs,
			Usage: "service CIDRs; treated the same as the pod CIDRs",
		},
		&cli.StringSliceFlag{
			Name: "dns-servers", Destination: &opts.dnsServers,
			Usage: "resolvers outbound DNS may reach; empty reads them from --resolv-conf",
		},
		&cli.StringFlag{
			Name: "resolv-conf", Value: "/etc/resolv.conf", Destination: &opts.resolvConf,
			Usage: "file the resolvers are read from when --dns-servers names none",
		},
		&cli.StringFlag{
			Name: "ipv6", Value: "auto", Destination: &opts.ipv6,
			Usage: "ip6tables ruleset: auto follows the kernel, on requires IPv6, off denies all IPv6 egress",
		},
		&cli.StringFlag{
			Name: "iptables", Destination: &opts.iptables,
			Usage: "iptables binary to use; empty resolves the legacy binary",
		},
		&cli.StringFlag{
			Name: "ip6tables", Destination: &opts.ip6tables,
			Usage: "ip6tables binary to use; empty resolves the legacy binary",
		},
		&cli.StringFlag{
			Name: "receipt", Value: netsetup.DefaultReceiptPath, Destination: &opts.receipt,
			Usage: "file recording what was programmed, for the sidecar to check its own containment against",
		},
		&cli.BoolFlag{
			Name: "dry-run", Destination: &opts.dryRun,
			Usage: "print the rules and exit without applying them",
		},
		&cli.BoolFlag{
			Name: "verify", Destination: &opts.verifyOnly,
			Usage: "read the tables back and confirm the ruleset is in force; " +
				"writes no receipt, drops no capability and applies nothing",
		},
		&cli.BoolFlag{
			Name: "keep-net-admin", Destination: &opts.keepNetAdmin,
			Usage: "keep CAP_NET_ADMIN after the rules are in place, instead of dropping it",
		},
	}
}
