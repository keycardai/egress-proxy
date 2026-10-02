package netsetup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// maxReceiptSize limits the read. The receipt has scalar fields only.
const maxReceiptSize = 64 << 10

// groupAndOtherWrite contains permission bits the receipt must not have.
const groupAndOtherWrite = 0o022

// Containment check errors.
var (
	// ErrNoReceipt means the receipt is missing from its configured path.
	ErrNoReceipt = errors.New("no netsetup receipt")
	// ErrNotContained means the active rules do not match what the sidecar
	// will do.
	ErrNotContained = errors.New("the sidecar cannot assert its own containment")
	// ErrNetNamespaceNotSupported means the platform does not report the
	// identity of a network namespace.
	ErrNetNamespaceNotSupported = errors.New("the network namespace is reported only on Linux")
	// ErrPortStartNotSupported means the platform does not report the lowest
	// port an unprivileged process can bind.
	ErrPortStartNotSupported = errors.New("the unprivileged port start is reported only on Linux")
	// ErrUnreadableReceipt means the receipt cannot be used. It is not a
	// regular file, is not JSON, or uses a schema version this build cannot
	// read.
	ErrUnreadableReceipt = errors.New("the netsetup receipt cannot be read")
)

// ReadReceipt reads and validates the receipt's shape. Containment checks
// whether it agrees with the caller.
func ReadReceipt(path string) (Receipt, error) {
	receipt, _, err := readReceipt(path)
	return receipt, err
}

// readReceipt returns the receipt and metadata for its file.
//
// The contents and metadata come from one open file descriptor, so the mode
// and owner checks apply to the bytes read. The open does not follow a
// symlink or block. A symlink or FIFO at the path is refused.
func readReceipt(path string) (Receipt, fs.FileInfo, error) {
	//nolint:gosec // G304: the path comes from this process's own configuration
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Receipt{}, nil, fmt.Errorf("%w at %s: the init container writes it after it programs and "+
				"verifies the rules, so either it did not run or it wrote somewhere this container cannot see",
				ErrNoReceipt, path)
		}
		return Receipt{}, nil, fmt.Errorf("read the netsetup receipt %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return Receipt{}, nil, fmt.Errorf("read the netsetup receipt %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return Receipt{}, nil, fmt.Errorf("%w: %s is %s, not a regular file",
			ErrUnreadableReceipt, path, info.Mode().Type())
	}
	body, err := io.ReadAll(io.LimitReader(file, maxReceiptSize))
	if err != nil {
		return Receipt{}, nil, fmt.Errorf("read the netsetup receipt %s: %w", path, err)
	}
	var receipt Receipt
	if err := json.Unmarshal(body, &receipt); err != nil {
		return Receipt{}, nil, fmt.Errorf("%w: %s does not parse: %w", ErrUnreadableReceipt, path, err)
	}
	if receipt.Version != receiptVersion {
		return Receipt{}, nil, fmt.Errorf("%w: %s is version %d and this build reads version %d",
			ErrUnreadableReceipt, path, receipt.Version, receiptVersion)
	}
	return receipt, info, nil
}

// ContainmentRequest describes what the sidecar will do. Containment checks
// it against what the init container programmed.
type ContainmentRequest struct {
	// Path is the receipt path.
	Path string
	// TransparentPort is the port the transparent frontend will bind.
	TransparentPort int
	// DNSPort is the port listen.dns binds, zero when the process runs no
	// resolver.
	DNSPort int
	// UID is the uid of this process.
	UID int
	// Now is the time used to check the receipt's age. The zero time uses the
	// system clock.
	Now time.Time
	// NetAdmin reports whether this process holds CAP_NET_ADMIN. Nil uses
	// HasNetAdmin. A platform with no capability sets is not checked.
	NetAdmin func() (bool, error)
	// PortStart reports the lowest port a process without
	// CAP_NET_BIND_SERVICE can bind. Nil uses UnprivilegedPortStart. A
	// platform that does not report it is not checked.
	PortStart func() (int, error)
	// NetNamespace reports the network namespace of this process. Nil uses
	// CurrentNetNamespace. A platform that does not report it is not
	// checked.
	NetNamespace func() (NetNamespace, error)
	// Owner reports the uid that owns a file. Nil reads it from the
	// filesystem.
	Owner func(fs.FileInfo) (int, bool)
}

// Containment reports each mismatch between the active rules and what this
// sidecar will do.
//
// It answers whether this process will force the workload's egress through
// itself. Each refusal names both values and the setting to change.
//
// A passing receipt shows that the whole ruleset was in the tables when the
// init container wrote it and that the init container then gave up the
// capability to change it. The pod's securityContext controls whether the
// workload can get around the ruleset.
//
// It returns the checked receipt. Log that value and NEVER read the file
// again. A second read can find a different receipt.
func Containment(request ContainmentRequest) (Receipt, error) {
	receipt, info, err := readReceipt(request.Path)
	if err != nil {
		return Receipt{}, err
	}
	var found problems
	if !receipt.Verified {
		found.addf("the receipt says the rules were not verified. The init container writes verified true only "+
			"after it reads the tables back and finds every rule, so the ruleset in %s is not known to be in "+
			"force", request.Path)
	}
	if !receipt.CapabilitiesDropped {
		found.addf("the receipt says the init container kept CAP_NET_ADMIN, so the process that programmed the " +
			"rules could still change them after it verified them. Drop --keep-net-admin from the init container")
	}
	found.add(receiptAgeProblems(receipt, request)...)
	if receipt.ProxyUID <= 0 {
		found.addf("the ruleset excludes uid %d. Uid 0 would exempt every root process in the pod from both "+
			"chains. Program the rules with --proxy-uid set to the sidecar's own non-root uid", receipt.ProxyUID)
	}
	if receipt.ProxyUID != request.UID {
		found.addf("the ruleset excludes uid %d and this process runs as uid %d. Every connection this process "+
			"opens would be redirected into its own transparent listener. Run the sidecar as uid %d, or program "+
			"the rules with --proxy-uid %d",
			receipt.ProxyUID, request.UID, receipt.ProxyUID, request.UID)
	}
	if receipt.RedirectPort != request.TransparentPort {
		found.addf("the redirect sends captured traffic to port %d and listen.transparent_port is %d, so "+
			"nothing would arrive on this listener. Set listen.transparent_port to %d, or program the rules with "+
			"--redirect-port %d",
			receipt.RedirectPort, request.TransparentPort, receipt.RedirectPort, request.TransparentPort)
	}
	found.add(dnsPortProblems(receipt, request)...)
	if len(receipt.Families) == 0 {
		found.addf("the receipt names no address family, so nothing was programmed")
	}
	found.add(netAdminProblems(request)...)
	found.add(portStartProblems(receipt, request)...)
	found.add(netNamespaceProblems(receipt, request)...)
	found.add(receiptFileProblems(request, info)...)
	if len(found) > 0 {
		return Receipt{}, fmt.Errorf("%w:\n  %s", ErrNotContained, strings.Join(found, "\n  "))
	}
	return receipt, nil
}

// dnsPortProblems refuses a sidecar whose resolver port and DNS redirect
// port differ. If they differ, every lookup fails.
func dnsPortProblems(receipt Receipt, request ContainmentRequest) []string {
	if receipt.DNSPort == request.DNSPort {
		return nil
	}
	if request.DNSPort == 0 {
		return []string{fmt.Sprintf("the rules redirect DNS to port %d and this process runs no resolver, so "+
			"every lookup the workload makes is refused. Set listen.dns to :%d, or program the rules with "+
			"--dns-port 0", receipt.DNSPort, receipt.DNSPort)}
	}
	if receipt.DNSPort == 0 {
		return []string{fmt.Sprintf("listen.dns binds port %d and the rules redirect no DNS to it, so a client "+
			"that names any other resolver reaches the terminal DROP. Program the rules with --dns-port %d, "+
			"or leave listen.dns empty", request.DNSPort, request.DNSPort)}
	}
	return []string{fmt.Sprintf("the rules redirect DNS to port %d and listen.dns binds port %d, so no lookup "+
		"arrives on this resolver. Set listen.dns to :%d, or program the rules with --dns-port %d",
		receipt.DNSPort, request.DNSPort, receipt.DNSPort, request.DNSPort)}
}

// receiptAgeProblems checks when the receipt was written. A missing timestamp
// or a future timestamp does not identify a ruleset in the tables. The two
// containers share a clock, so neither check needs a tolerance.
func receiptAgeProblems(receipt Receipt, request ContainmentRequest) []string {
	now := request.Now
	if now.IsZero() {
		now = time.Now()
	}
	var found problems
	switch {
	case receipt.VerifiedAt.IsZero():
		found.addf("the receipt has no verified_at, so there is no saying when the tables were read back. " +
			"Re-run the init container")
	case receipt.VerifiedAt.After(now):
		found.addf("the receipt says the rules were verified at %s and it is now %s. A receipt dated in the "+
			"future was not written by the init container of this pod",
			receipt.VerifiedAt.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return found
}

// netAdminProblems refuses a sidecar that holds the capability that programs
// the tables. The receipt is useful only when this process cannot change it.
func netAdminProblems(request ContainmentRequest) []string {
	netAdmin := request.NetAdmin
	if netAdmin == nil {
		netAdmin = HasNetAdmin
	}
	held, err := netAdmin()
	switch {
	case errors.Is(err, ErrCapabilitiesNotSupported):
		return nil
	case err != nil:
		return []string{fmt.Sprintf("this process's capabilities could not be read, so it cannot show that it "+
			"is unable to change the tables the receipt describes: %v", err)}
	case !held:
		return nil
	}
	return []string{"this process holds CAP_NET_ADMIN, so it can change the very rules the receipt says are in " +
		"force. Give the sidecar container capabilities.drop ALL and capabilities.add NET_BIND_SERVICE; only " +
		"the init container needs NET_ADMIN"}
}

// portStartProblems refuses a port the sidecar binds that an unprivileged
// process can bind too. A workload that can bind one can stand in for the
// proxy during a sidecar restart, or answer its own lookups. Read the kernel
// value instead of trusting the manifest. A receipt that records
// allow-unprotected is not checked, because the init container was told to
// accept that exposure.
//
// The sysctl has to be above the redirect port and above the DNS port, so
// the check compares it with the higher of the two.
func portStartProblems(receipt Receipt, request ContainmentRequest) []string {
	if receipt.RedirectPortProtection == PortProtectionAllowUnprotected {
		return nil
	}
	read := request.PortStart
	if read == nil {
		read = UnprivilegedPortStart
	}
	highest, which := receipt.RedirectPort, "redirect port"
	if receipt.DNSPort > highest {
		highest, which = receipt.DNSPort, "DNS port"
	}
	start, err := read()
	switch {
	case errors.Is(err, ErrPortStartNotSupported):
		return nil
	case err != nil:
		return []string{fmt.Sprintf("the lowest port an unprivileged process may bind could not be read, so "+
			"there is no saying whether the workload can bind the %s %d: %v", which, highest, err)}
	case start > highest:
		return nil
	}
	return []string{fmt.Sprintf("net.ipv4.ip_unprivileged_port_start is %d, so a process holding no "+
		"CAP_NET_BIND_SERVICE can bind the %s %d and stand in for the proxy during a restart. "+
		"Set the pod sysctl net.ipv4.ip_unprivileged_port_start to 1024 in securityContext.sysctls and keep the "+
		"%s below it. containerd 2.0 and later sets it to 0 in a pod that does not set it",
		start, which, highest, which)}
}

// netNamespaceProblems refuses a receipt written in another network
// namespace. The rules it describes govern that namespace, not the one this
// process and the workload share.
func netNamespaceProblems(receipt Receipt, request ContainmentRequest) []string {
	read := request.NetNamespace
	if read == nil {
		read = CurrentNetNamespace
	}
	own, err := read()
	switch {
	case errors.Is(err, ErrNetNamespaceNotSupported):
		return nil
	case err != nil:
		return []string{fmt.Sprintf("this process's network namespace could not be read, so there is no saying "+
			"whether the receipt describes rules in it: %v", err)}
	case receipt.NetNamespace == nil:
		return []string{"the receipt records no network namespace, so there is no saying whether its rules " +
			"govern this pod's network. Re-run the init container"}
	case *receipt.NetNamespace == own:
		return nil
	}
	return []string{fmt.Sprintf("the receipt was written in network namespace %s and this process is in "+
		"network namespace %s, so the init container and the sidecar are not in the same pod network",
		receipt.NetNamespace, own)}
}

// receiptFileProblems refuses a receipt that another uid can write or owns,
// and a directory that another uid owns. A writer can replace the receipt.
//
// The directory can be writable by every uid. An emptyDir mount point is
// 0777 (kubernetes pkg/volume/emptydir/empty_dir.go, perm). A replacement is
// owned by the uid that wrote it, so the owner check refuses it.
func receiptFileProblems(request ContainmentRequest, info fs.FileInfo) []string {
	owner := request.Owner
	if owner == nil {
		owner = fileOwner
	}
	var found problems
	if info.Mode().Perm()&groupAndOtherWrite != 0 {
		found.addf("%s is mode %#o, so a uid other than its owner can write it. Whoever can write the receipt "+
			"decides what this process believes about its own containment. Set the mode to 0644",
			request.Path, info.Mode().Perm())
	}
	found.add(ownerProblems(owner, info, request.Path, request.UID,
		"A receipt some other uid owns is a receipt some other uid rewrites")...)
	found.add(receiptDirProblems(owner, request)...)
	return found
}

// receiptDirProblems refuses a directory owned by a uid other than root or
// this process. Its owner can change its mode and entries.
func receiptDirProblems(owner func(fs.FileInfo) (int, bool), request ContainmentRequest) []string {
	dir := filepath.Dir(request.Path)
	info, err := os.Stat(dir)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", dir, err)}
	}
	return ownerProblems(owner, info, dir, request.UID, "So that uid can replace the receipt")
}

// ownerProblems refuses a path owned by a uid other than root or this
// process. Those are the only uids that can write the receipt. It also
// refuses a filesystem that does not report an owner.
func ownerProblems(owner func(fs.FileInfo) (int, bool), info fs.FileInfo, path string, uid int, why string) []string {
	found, ok := owner(info)
	switch {
	case !ok:
		return []string{fmt.Sprintf("the filesystem does not report who owns %s, so there is no saying whether "+
			"another uid can write it. %s", path, why)}
	case found == 0 || found == uid:
		return nil
	}
	return []string{fmt.Sprintf("%s is owned by uid %d, which is neither root nor this process's own uid %d. %s",
		path, found, uid, why)}
}

// fileOwner reads the uid that owns a file. It returns false when the
// filesystem does not report one.
func fileOwner(info fs.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}
