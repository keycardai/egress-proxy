//go:build acceptance

package acceptance_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rogpeppe/go-internal/testscript"
)

// errUnknownCondition is a bracketed condition no scenario defines.
var errUnknownCondition = errors.New("unknown condition")

// condition answers the bracketed conditions a script tests. [docker] holds
// when a Docker daemon answers.
func condition(cond string) (bool, error) {
	if cond == "docker" {
		return dockerAvailable(), nil
	}
	return false, fmt.Errorf("%w: %q", errUnknownCondition, cond)
}

// dockerAvailable reports whether a Docker daemon answers. A workstation
// with the client installed and the daemon stopped skips a Docker scenario
// the same way one with no client does.
func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").Run() == nil
}

// The lab network. Each run draws its own subnet, so two runs on one host
// do not collide.
const (
	// labOctetLow and labOctetSpan are the range the third octet of the IPv4
	// subnet is drawn from. They stay clear of the low numbers a home LAN
	// uses.
	labOctetLow  = 200
	labOctetSpan = 50
	// labImageRepo is tagged per run, so two runs never hand each other's
	// binaries to a container. The build cache is keyed by layer content,
	// so the package layers are still built once.
	labImageRepo = "egress-proxy-acceptance"
)

// cmdDockerLab creates the network the lab containers share and exports the
// names and addresses a script uses:
//
//	dockerlab
//
// It exports $LAB, a name unique to this run, $LAB_IMAGE, and the
// addresses $LAB_UPSTREAM4, $LAB_UPSTREAM6, $LAB_WORKLOAD4, $LAB_WORKLOAD6
// and $LAB_GATEWAY4. The containers $LAB-upstream and $LAB-workload, the
// network and the image are removed when the script ends, whether it passed
// or failed.
func cmdDockerLab(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 0 {
		ts.Fatalf("usage: dockerlab")
	}
	suffix := strings.ToLower(rand.Text()[:8])
	lab := "egress-lab-" + suffix
	image := labImageRepo + ":" + suffix
	sum := 0
	for _, b := range []byte(suffix) {
		sum += int(b)
	}
	octet := labOctetLow + sum%labOctetSpan
	four := fmt.Sprintf("192.168.%d.", octet)
	six := fmt.Sprintf("fd00:e9:%x::", octet)
	for name, value := range map[string]string{
		"LAB": lab, "LAB_IMAGE": image,
		"LAB_UPSTREAM4": four + "10", "LAB_UPSTREAM6": six + "10",
		"LAB_WORKLOAD4": four + "20", "LAB_WORKLOAD6": six + "20",
		"LAB_GATEWAY4": four + "1",
	} {
		ts.Setenv(name, value)
	}
	ts.Defer(func() {
		for _, name := range []string{lab + "-workload", lab + "-upstream"} {
			_ = exec.CommandContext(context.Background(), "docker", "rm", "-f", name).Run()
		}
		_ = exec.CommandContext(context.Background(), "docker", "network", "rm", lab).Run()
		_ = exec.CommandContext(context.Background(), "docker", "rmi", "-f", image).Run()
	})
	create := exec.CommandContext(context.Background(), "docker", "network", "create",
		"--subnet", four+"0/24", "--gateway", four+"1", "--ipv6", "--subnet", six+"/64", lab)
	if out, err := create.CombinedOutput(); err != nil {
		ts.Fatalf("docker network create: %v: %s", err, out)
	}
}

// cmdLinuxBin cross-compiles egress-netsetup and netfixture into DIR:
//
//	linuxbin DIR
//
// They are static and built for the architecture the Docker daemon runs, so
// the image needs no toolchain and the scenario drives the binary this
// module produces.
func cmdLinuxBin(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 1 {
		ts.Fatalf("usage: linuxbin DIR")
	}
	dir := ts.MkAbs(args[0])
	ts.Check(os.MkdirAll(dir, 0o750))
	arch, err := exec.CommandContext(context.Background(), "docker", "version", "--format", "{{.Server.Arch}}").Output()
	ts.Check(err)
	for _, pkg := range []string{"../../cmd/egress-netsetup", "./netfixture"} {
		build := exec.CommandContext(context.Background(), "go", "build", "-o", filepath.Join(dir, filepath.Base(pkg)), pkg)
		build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+strings.TrimSpace(string(arch)))
		build.Stderr = os.Stderr
		ts.Check(build.Run())
	}
}
