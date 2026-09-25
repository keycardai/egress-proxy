//go:build acceptance

package acceptance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/keycardai/egress-proxy/internal/ca"
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
	// certificatePEMSize estimates one PEM certificate when sizing the leaf
	// chain buffer.
	certificatePEMSize = 1024
)

// cmdDockerLab creates the network the lab containers share and exports the
// names and addresses a script uses:
//
//	dockerlab
//
// It exports the Docker client settings, $LAB, a name unique to this run,
// $LAB_IMAGE, and the addresses $LAB_UPSTREAM4, $LAB_UPSTREAM6,
// $LAB_WORKLOAD4, $LAB_WORKLOAD6 and $LAB_GATEWAY4. The containers $LAB-upstream and $LAB-workload, the
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
	dockerClientEnv(ts)
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

// dockerClientEnv gives the script the Docker client settings of the
// process running the tests. testscript sets HOME to a directory that does
// not exist, and the client keeps its configuration under HOME unless
// DOCKER_CONFIG names another place.
func dockerClientEnv(ts *testscript.TestScript) {
	for _, name := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"} {
		if value, ok := os.LookupEnv(name); ok {
			ts.Setenv(name, value)
		}
	}
	config := os.Getenv("DOCKER_CONFIG")
	if config == "" {
		home, err := os.UserHomeDir()
		ts.Check(err)
		config = filepath.Join(home, ".docker")
	}
	ts.Setenv("DOCKER_CONFIG", config)
}

// cmdLinuxBin cross-compiles egress-proxy, egress-netsetup, and netfixture
// into DIR.
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
	for _, pkg := range []string{"../../cmd/egress-proxy", "../../cmd/egress-netsetup", "./netfixture"} {
		build := exec.CommandContext(context.Background(), "go", "build", "-o", filepath.Join(dir, filepath.Base(pkg)), pkg)
		build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+strings.TrimSpace(string(arch)))
		build.Stderr = os.Stderr
		ts.Check(build.Run())
	}
}

// cmdTLSCert writes a CA certificate and leaf for HOST into DIR.
//
//	tlscert DIR HOST
//
// The proxy verifies the upstream with DIR/ca.crt. The upstream serves
// DIR/leaf.crt with DIR/leaf.key.
func cmdTLSCert(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 2 {
		ts.Fatalf("usage: tlscert DIR HOST")
	}
	dir := ts.MkAbs(args[0])
	ts.Check(os.MkdirAll(dir, 0o750))
	authority, err := ca.New(ca.Options{CommonName: "acceptance lab upstream CA"})
	ts.Check(err)
	_, err = authority.WriteCertificate(dir)
	ts.Check(err)
	leaf, err := authority.Leaf(args[1])
	ts.Check(err)
	certPEM := make([]byte, 0, len(leaf.Certificate)*certificatePEMSize)
	for _, der := range leaf.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, ok := leaf.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		ts.Fatalf("tlscert: the leaf key is %T, not an ECDSA key", leaf.PrivateKey)
	}
	der, err := x509.MarshalECPrivateKey(key)
	ts.Check(err)
	ts.Check(os.WriteFile(filepath.Join(dir, "leaf.crt"), certPEM, 0o644))
	ts.Check(os.WriteFile(filepath.Join(dir, "leaf.key"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600))
}
