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

// The modes WriteReceipt creates the receipt and its directory with.
const (
	receiptMode    = 0o644
	receiptDirMode = 0o755
)

// Receipt is what the init container programmed and verified.
//
// The sidecar runs without CAP_NET_ADMIN, so it cannot read the tables. The
// receipt tells it what the init container put in force.
//
// It holds no secret. It is trusted because of where it is: an emptyDir
// with medium Memory that the sidecar and the init container share and the
// workload does not mount.
type Receipt struct {
	Version int `json:"version"`
	// VerifiedAt is when the tables were last read back and found to hold
	// the whole ruleset, in UTC.
	VerifiedAt time.Time `json:"verified_at"`
	// Verified says the tables were read back and hold every rule.
	Verified bool `json:"verified"`
	// ProxyUID is the uid whose traffic is neither redirected nor dropped.
	// The sidecar must run as it: any other uid has its own egress
	// redirected into its own listener.
	ProxyUID int `json:"proxy_uid"`
	// RedirectPort is where the nat REDIRECT sends captured traffic. It must
	// be the port listen.transparent binds.
	RedirectPort int `json:"redirect_port"`
	// RedirectPortProtection is the --redirect-port-protection mode the run
	// used. A receipt without it says nothing about whether the port was
	// checked.
	RedirectPortProtection PortProtection `json:"redirect_port_protection,omitempty"`
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

// PortProtection says whether a run checked that a workload cannot bind the
// redirect port.
type PortProtection string

const (
	// PortProtectionRequired refuses a redirect port at or above
	// net.ipv4.ip_unprivileged_port_start.
	PortProtectionRequired PortProtection = "required"
	// PortProtectionAllowUnprotected skips the check. A workload can then
	// bind the redirect port while the sidecar is not listening.
	PortProtectionAllowUnprotected PortProtection = "allow-unprotected"
)

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

// WriteReceipt writes the receipt at path. The receipt is not a secret, and
// the sidecar reads it as another uid.
//
// A new file is created 0644 and a missing directory 0755. An existing file
// or directory keeps its mode. An emptyDir mount point is 0777 (kubernetes
// pkg/volume/emptydir/empty_dir.go, perm), so with the default path any uid
// that mounts the volume can replace the receipt.
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
