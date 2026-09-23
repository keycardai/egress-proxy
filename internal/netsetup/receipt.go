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

// receiptVersion is the schema version. It grows fields and never renames
// one, so a sidecar reading a receipt from a newer init container finds what
// it knows.
const receiptVersion = 1

// maxReceiptSize bounds the read. The receipt is a dozen scalar fields.
const maxReceiptSize = 64 << 10

// The errors the receipt path returns.
var (
	// ErrNoReceipt is returned when the receipt is not where it was
	// expected.
	ErrNoReceipt = errors.New("no netsetup receipt")
	// ErrNotContained is returned when the ruleset in force disagrees with
	// what the sidecar is about to do.
	ErrNotContained = errors.New("the sidecar cannot assert its own containment")
	// ErrCapabilitiesNotSupported is returned on a platform with no Linux
	// capability sets. Nothing outside Linux programs these tables.
	ErrCapabilitiesNotSupported = errors.New("capabilities exist only on Linux")
	// ErrPortStartNotSupported is returned on a platform that does not
	// report the lowest port an unprivileged process may bind.
	ErrPortStartNotSupported = errors.New("the unprivileged port start is reported only on Linux")
	// ErrUnreadableReceipt is returned for a receipt that is there and
	// cannot be used: not a regular file, or from a schema version this
	// build does not read.
	ErrUnreadableReceipt = errors.New("the netsetup receipt cannot be read")
)

// The modes the init container leaves behind. Anything looser lets another
// uid decide what the sidecar believes about its own containment.
const (
	receiptMode    = 0o644
	receiptDirMode = 0o755
	// groupAndOtherWrite is the permission bits neither the receipt nor its
	// directory may carry.
	groupAndOtherWrite = 0o022
)

// Receipt is what the init container programmed and verified.
//
// The sidecar cannot read the tables itself: that needs CAP_NET_ADMIN and
// the sidecar runs without it. The receipt is how the container that holds
// the capability tells the container that does not what is in force, so the
// sidecar refuses to start when the rules do not match what it is about to
// do.
//
// It is not a secret and it carries none. It is trusted because of where it
// is: an emptyDir with medium Memory that the sidecar and the init container
// share and the workload does not mount. The sidecar refuses a receipt any
// other uid can write.
type Receipt struct {
	Version int `json:"version"`
	// VerifiedAt is when the tables were last read back and found to hold
	// the whole ruleset, in UTC.
	VerifiedAt time.Time `json:"verified_at"`
	// Verified says the tables were read back and hold every rule. A
	// receipt that says false is a receipt the sidecar refuses.
	Verified bool `json:"verified"`
	// ProxyUID is the uid whose traffic is neither redirected nor dropped.
	// The sidecar must run as it: any other uid has its own egress
	// redirected into its own listener.
	ProxyUID int `json:"proxy_uid"`
	// RedirectPort is where the nat REDIRECT sends captured traffic. It must
	// be the port listen.transparent binds.
	RedirectPort int `json:"redirect_port"`
	// CapturePorts are the destination ports the redirect covers.
	CapturePorts []int `json:"capture_ports"`
	// Families are the address families programmed.
	Families []string `json:"families"`
	// RulesetDigest identifies the exact ruleset, so two sidecars are
	// compared without reading the tables.
	RulesetDigest string `json:"ruleset_digest"`
	// CapabilitiesDropped says the init container gave up CAP_NET_ADMIN once
	// the rules were in place. The drop covers the thread that programmed
	// them, which is the scope DropNetAdmin has, and the process exits as
	// soon as this receipt is written.
	CapabilitiesDropped bool `json:"capabilities_dropped"`
}

// NewReceipt describes what a configuration programmed.
func NewReceipt(cfg Config, programs []Program, verified bool, now time.Time) Receipt {
	families := make([]string, 0, len(programs))
	for _, program := range programs {
		families = append(families, program.Family.String())
	}
	return Receipt{
		Version:       receiptVersion,
		VerifiedAt:    now.UTC(),
		Verified:      verified,
		ProxyUID:      cfg.ProxyUID,
		RedirectPort:  cfg.RedirectPort,
		CapturePorts:  append([]int(nil), cfg.CapturePorts...),
		Families:      families,
		RulesetDigest: RulesetDigest(programs),
	}
}

// WriteReceipt writes the receipt at path, creating the directory it goes
// in.
//
// The file is 0644 and the directory 0755: the receipt is not a secret and
// the sidecar reads it as another uid, which also has to traverse the
// directory. Nothing but the owner can write either, which is what
// Containment checks.
func WriteReceipt(path string, receipt Receipt) error {
	if err := os.MkdirAll(filepath.Dir(path), receiptDirMode); err != nil {
		return fmt.Errorf("create the directory for %s: %w", path, err)
	}
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the receipt: %w", err)
	}
	if err := os.WriteFile(path, append(body, '\n'), receiptMode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// RemoveReceipt unlinks the receipt.
//
// A run that could not put the whole ruleset in force MUST call this. The
// receipt is the sidecar's only evidence of its own containment, and one an
// earlier run left behind says the rules are in force when they are not.
func RemoveReceipt(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the stale netsetup receipt %s: %w", path, err)
	}
	return nil
}

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
// check at one file and the read at another.
func readReceipt(path string) (Receipt, fs.FileInfo, error) {
	//nolint:gosec // G304: the path comes from this process's own configuration
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
		return Receipt{}, nil, fmt.Errorf("the netsetup receipt %s does not parse: %w", path, err)
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
func Containment(request ContainmentRequest) error {
	receipt, info, err := readReceipt(request.Path)
	if err != nil {
		return err
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
		return fmt.Errorf("%w:\n  %s", ErrNotContained, strings.Join(found, "\n  "))
	}
	return nil
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
		"Leave the sysctl at the kernel default of 1024 and keep the redirect port below it",
		start, receipt.RedirectPort)}
}

// receiptFileProblems refuses a receipt another uid can write, and a
// directory another uid can put a replacement in. Whoever can write either
// decides what this process believes about its own containment.
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

// receiptDirProblems refuses a directory another uid can put a replacement
// receipt in.
func receiptDirProblems(owner func(fs.FileInfo) (int, bool), request ContainmentRequest) []string {
	dir := filepath.Dir(request.Path)
	info, err := os.Stat(dir)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", dir, err)}
	}
	var found problems
	// A directory another uid can write lets that uid unlink the receipt
	// and put its own there, unless the sticky bit keeps each entry with
	// its owner.
	if info.Mode().Perm()&groupAndOtherWrite != 0 && info.Mode()&fs.ModeSticky == 0 {
		found.addf("%s is mode %#o, so a uid other than its owner can replace the receipt in it. Set the mode "+
			"to 0755", dir, info.Mode().Perm())
	}
	found.add(ownerProblems(owner, info, dir, request.UID, "so that uid can replace the receipt")...)
	return found
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
