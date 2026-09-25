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

// maxReceiptSize bounds the read. The receipt is a dozen scalar fields.
const maxReceiptSize = 64 << 10

// groupAndOtherWrite is the permission bits the receipt may not have.
const groupAndOtherWrite = 0o022

// The errors the containment check returns.
var (
	// ErrNoReceipt is returned when the receipt is not where it was
	// expected.
	ErrNoReceipt = errors.New("no netsetup receipt")
	// ErrNotContained is returned when the ruleset in force disagrees with
	// what the sidecar is about to do.
	ErrNotContained = errors.New("the sidecar cannot assert its own containment")
	// ErrPortStartNotSupported is returned on a platform that does not
	// report the lowest port an unprivileged process may bind.
	ErrPortStartNotSupported = errors.New("the unprivileged port start is reported only on Linux")
	// ErrUnreadableReceipt is returned for a receipt that is there and
	// cannot be used: not a regular file, not JSON, or from a schema version
	// this build does not read.
	ErrUnreadableReceipt = errors.New("the netsetup receipt cannot be read")
)

// ReadReceipt reads and validates a receipt's own shape. Whether what it
// says agrees with the caller is Containment's question.
func ReadReceipt(path string) (Receipt, error) {
	receipt, _, err := readReceipt(path)
	return receipt, err
}

// readReceipt returns the receipt and the metadata of the file it came out
// of.
//
// The contents and the metadata come from one open file descriptor, so the
// mode and the owner Containment checks belong to the bytes it parsed. The
// open does not follow a symlink: a link at the receipt's path points the
// check at one file and the read at another. The open does not block: a
// FIFO at the path is refused as not a regular file.
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

// ContainmentRequest is what the sidecar is about to do, checked against
// what the init container programmed.
type ContainmentRequest struct {
	// Path is where the receipt is.
	Path string
	// TransparentPort is the port the transparent frontend binds.
	TransparentPort int
	// UID is the uid this process runs as.
	UID int
	// Now is the clock the receipt's age is measured against. The zero time
	// uses the system clock.
	Now time.Time
	// NetAdmin reports whether this process holds CAP_NET_ADMIN. Nil uses
	// HasNetAdmin, and a platform with no capability sets is not checked.
	NetAdmin func() (bool, error)
	// PortStart reports the lowest port a process with no
	// CAP_NET_BIND_SERVICE may bind. Nil uses UnprivilegedPortStart, and a
	// platform that does not report it is not checked.
	PortStart func() (int, error)
	// Owner reports the uid owning a file. Nil reads it from the
	// filesystem.
	Owner func(fs.FileInfo) (int, bool)
}

// Containment reports every way the ruleset in force disagrees with what
// this sidecar is about to do.
//
// It answers one question: if this process starts, is the workload's egress
// forced through it. Every refusal names the two values that disagree and
// the setting that changes each, because a refusal that says only
// "verification failed" leaves an operator reading two containers'
// arguments side by side.
//
// A receipt that passes says the whole ruleset was in the tables when it was
// written and that the process that wrote it then gave up the capability to
// change them. It does not say the workload cannot get around the ruleset:
// the securityContext says that.
//
// It returns the receipt it checked. Log from that value and NEVER read the
// file again: a second read can find a receipt this check never saw.
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
		found.addf("the redirect sends captured traffic to port %d and listen.transparent binds port %d, so "+
			"nothing would arrive on this listener. Set listen.transparent to :%d, or program the rules with "+
			"--redirect-port %d",
			receipt.RedirectPort, request.TransparentPort, receipt.RedirectPort, request.TransparentPort)
	}
	if len(receipt.Families) == 0 {
		found.addf("the receipt names no address family, so nothing was programmed")
	}
	found.add(netAdminProblems(request)...)
	found.add(portStartProblems(receipt, request)...)
	found.add(receiptFileProblems(request, info)...)
	if len(found) > 0 {
		return Receipt{}, fmt.Errorf("%w:\n  %s", ErrNotContained, strings.Join(found, "\n  "))
	}
	return receipt, nil
}

// receiptAgeProblems bounds when the receipt was written. A receipt with no
// timestamp, or one dated after now, describes a ruleset this process has no
// reason to believe is in the tables. The two containers share one clock, so
// neither bound needs a tolerance.
func receiptAgeProblems(receipt Receipt, request ContainmentRequest) []string {
	now := request.Now
	if now.IsZero() {
		now = time.Now()
	}
	var found problems
	switch {
	case receipt.VerifiedAt.IsZero():
		found.addf("the receipt carries no verified_at, so there is no saying when the tables were read back. " +
			"Re-run the init container")
	case receipt.VerifiedAt.After(now):
		found.addf("the receipt says the rules were verified at %s and it is now %s. A receipt dated in the "+
			"future was not written by the init container of this pod",
			receipt.VerifiedAt.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return found
}

// netAdminProblems refuses a sidecar holding the capability that programs
// the tables. The receipt is worth something only because this process
// cannot change what it describes.
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

// portStartProblems refuses a redirect port an unprivileged process can
// bind. A workload that can bind it stands in for the proxy during a sidecar
// restart and decides its own traffic, so the manifest is not taken at its
// word: the kernel is asked.
func portStartProblems(receipt Receipt, request ContainmentRequest) []string {
	read := request.PortStart
	if read == nil {
		read = UnprivilegedPortStart
	}
	start, err := read()
	switch {
	case errors.Is(err, ErrPortStartNotSupported):
		return nil
	case err != nil:
		return []string{fmt.Sprintf("the lowest port an unprivileged process may bind could not be read, so "+
			"there is no saying whether the workload can bind the redirect port %d: %v",
			receipt.RedirectPort, err)}
	case start > receipt.RedirectPort:
		return nil
	}
	return []string{fmt.Sprintf("net.ipv4.ip_unprivileged_port_start is %d, so a process holding no "+
		"CAP_NET_BIND_SERVICE can bind the redirect port %d and stand in for the proxy during a restart. "+
		"Set the pod sysctl net.ipv4.ip_unprivileged_port_start to 1024 in securityContext.sysctls and keep the "+
		"redirect port below it. containerd 2.0 and later sets it to 0 in a pod that does not set it",
		start, receipt.RedirectPort)}
}

// receiptFileProblems refuses a receipt another uid can write or owns, and a
// directory another uid owns. Whoever can write the receipt decides what
// this process believes about its own containment.
//
// The directory may be writable by every uid. An emptyDir mount point is
// 0777 (kubernetes pkg/volume/emptydir/empty_dir.go, perm). A uid that
// replaces the receipt there owns the replacement, and the owner check
// refuses it.
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

// receiptDirProblems refuses a directory owned by a uid that is neither root
// nor this process's own. Its owner can change its mode and its entries.
func receiptDirProblems(owner func(fs.FileInfo) (int, bool), request ContainmentRequest) []string {
	dir := filepath.Dir(request.Path)
	info, err := os.Stat(dir)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", dir, err)}
	}
	return ownerProblems(owner, info, dir, request.UID, "So that uid can replace the receipt")
}

// ownerProblems refuses a path owned by a uid that is neither root nor this
// process's own. Those are the only two with any business writing the
// receipt: the init container's and the sidecar's. A filesystem that does
// not report an owner is refused too, because the check cannot be made.
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

// fileOwner reads the uid owning a file. It reports false where the
// filesystem does not say.
func fileOwner(info fs.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}
