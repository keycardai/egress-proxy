package netsetup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// receiptVersion is the schema version. It grows fields and never renames
// one, so a sidecar reading a receipt from a newer init container finds what
// it knows.
const receiptVersion = 1

// ErrCapabilitiesNotSupported is returned on a platform with no Linux
// capability sets. Nothing outside Linux programs these tables.
var ErrCapabilitiesNotSupported = errors.New("capabilities exist only on Linux")

// The modes the init container leaves behind. Anything looser lets another
// uid decide what the sidecar believes about its own containment.
const (
	receiptMode    = 0o644
	receiptDirMode = 0o755
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
// directory. Nothing but the owner can write either.
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
