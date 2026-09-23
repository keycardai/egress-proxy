//go:build images

// Package images builds the three images this repository ships and drives
// what each one has to do in a container. It is behind the images build tag
// so `go test ./...` never builds an image. `make images` runs it, and so
// does the images job in CI.
//
// Nothing here pushes. Every build is local, and every image this lane
// makes is removed when it ends.
package images_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/ca"
)

// buildTimeout bounds one image build, which pulls a base image on a cold
// machine.
const buildTimeout = 20 * time.Minute

// runTimeout bounds one container run.
const runTimeout = 2 * time.Minute

// tag is the tag this lane builds under. It is removed when the lane ends,
// so it never collides with an image an operator built by hand.
const tag = "egress-proxy-images-test"

func TestMain(m *testing.M) {
	if !dockerAvailable() {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func dockerAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	return exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").Run() == nil
}

// repoRoot is the build context the two Dockerfiles take and the module ko
// builds from.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	return root
}

// run executes a command in the repository root and returns its combined
// output, failing the test on a non-zero exit.
func run(t *testing.T, timeout time.Duration, env []string, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s %s:\n%s", name, strings.Join(args, " "), out)
	return string(out)
}

// koRepo is where ko loads the proxy image. With --bare the reference is
// this name and the tag, and nothing here pushes.
const koRepo = "ko.local"

// runStdout is run, returning standard output alone.
func runStdout(t *testing.T, timeout time.Duration, env []string, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	require.NoError(t, err, "%s %s", name, strings.Join(args, " "))
	return string(out)
}

// removeImage drops an image the lane built, whether the test passed or
// failed.
func removeImage(t *testing.T, image string) {
	t.Helper()
	t.Cleanup(func() {
		_ = exec.CommandContext(context.Background(), "docker", "rmi", "-f", image).Run()
	})
}

// TestProxyImage builds the proxy image with ko and drives the probe
// subcommand in it. The image carries no shell, so this is the only way in.
func TestProxyImage(t *testing.T) {
	t.Parallel()
	removeImage(t, koRepo+":"+tag)
	// ko writes its logs to stderr and the reference it loaded to stdout,
	// so the lane drives the image ko built rather than one it guessed the
	// name of.
	image := strings.TrimSpace(runStdout(t, buildTimeout,
		[]string{"KO_CONFIG_PATH=images/proxy", "KO_DOCKER_REPO=" + koRepo},
		"go", "tool", "ko", "build", "--local", "--bare", "--tags", tag,
		"--platform", "linux/"+goarch(t), "./cmd/egress-proxy"))
	require.NotEmpty(t, image, "ko printed no image reference")

	// The socket is not there, so the probe fails. That failure is what
	// holds the workload container back while the proxy is starting.
	ctx, cancel := context.WithTimeout(t.Context(), runTimeout)
	defer cancel()
	probe := exec.CommandContext(ctx, "docker", "run", "--rm", image, "probe", "readyz")
	out, err := probe.CombinedOutput()
	require.Error(t, err, "probe readyz answered with no proxy running:\n%s", out)
	assert.Contains(t, string(out), "/run/egress/admin.sock",
		"the failure names the socket the probe dialled")

	// No shell, so the probe has to be the binary itself.
	shell := exec.CommandContext(ctx, "docker", "run", "--rm", "--entrypoint", "/bin/sh", image, "-c", "true")
	require.Error(t, shell.Run(), "the proxy image carries a shell")
}

// TestNetsetupImage builds the init container image and checks that it
// resolves the legacy iptables binaries the ruleset needs.
func TestNetsetupImage(t *testing.T) {
	t.Parallel()
	image := "egress-netsetup:" + tag
	removeImage(t, image)
	run(t, buildTimeout, nil, "docker", "build", "-f", "images/netsetup/Dockerfile", "-t", image, ".")

	// --dry-run prints the ruleset and applies nothing, so this needs no
	// capability and no network namespace of its own.
	out := run(t, runTimeout, nil, "docker", "run", "--rm", image,
		"--dry-run", "--dns-servers=10.96.0.10", "--ipv6=off")
	assert.Contains(t, out, ":EGRESS_PROXY_NAT_OUTPUT - [0:0]", "the dry run prints the nat chain")
	assert.Contains(t, out, "--uid-owner 1337", "the ruleset excludes the proxy uid")
	assert.Contains(t, out, "REDIRECT --to-ports 1015", "the ruleset redirects to the transparent listener")

	// The image resolves the binary through PATH, the way egress-netsetup
	// does, and it has to be the legacy backend: the sandbox runtimes this
	// proxy targets never apply an nf_tables ruleset.
	version := run(t, runTimeout, nil, "docker", "run", "--rm", "--entrypoint", "/bin/sh",
		image, "-c", "iptables-legacy --version && ip6tables-legacy --version")
	assert.Contains(t, version, "(legacy)", "the image resolves the legacy backend, not nf_tables")
	assert.NotContains(t, version, "nf_tables", "no binary the lane resolves uses the nf_tables backend")
}

// TestSandboxBaseImage builds the base image and drives its entrypoint
// against a fake /shared-ca, which is what the sidecar mounts in a pod. The
// two cases share one image, so they run one after the other.
func TestSandboxBaseImage(t *testing.T) {
	t.Parallel()
	image := "sandbox-base:" + tag
	removeImage(t, image)
	run(t, buildTimeout, nil, "docker", "build", "-t", image, "images/sandbox-base")

	t.Run("the agent starts with the proxy CA in its trust store", func(t *testing.T) {
		shared := t.TempDir()
		authority, err := ca.New(ca.Options{CommonName: "images lane CA"})
		require.NoError(t, err, "mint the authority the sidecar would write")
		_, err = authority.WriteCertificate(shared)
		require.NoError(t, err, "write ca.crt to the shared volume")
		//nolint:gosec // the fixture stands in for a volume the kubelet mounts world-readable
		require.NoError(t, os.Chmod(shared, 0o755), "the workload reads the volume read-only")

		// The agent runs as the uid the contract names, with no capability
		// and a read-only root, the way the pod runs it. openssl verify
		// against the rebuilt bundle is what proves the entrypoint installed
		// the certificate.
		out := run(t, runTimeout, nil, "docker", "run", "--rm",
			"--user", "1000:1000", "--cap-drop", "ALL", "--read-only",
			"--tmpfs", "/tmp", "--tmpfs", "/etc/ssl/certs:uid=1000,gid=1000",
			"--tmpfs", "/usr/local/share/ca-certificates:uid=1000,gid=1000",
			"-v", shared+":/shared-ca:ro", image,
			"/bin/sh", "-c", "openssl verify -CAfile \"$SSL_CERT_FILE\" /shared-ca/ca.crt")
		assert.Contains(t, out, "the proxy CA is trusted", "the entrypoint says what it did")
		assert.Contains(t, out, "/shared-ca/ca.crt: OK", "the rebuilt bundle verifies the proxy CA")
	})

	t.Run("the agent does not start without the certificate", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), runTimeout)
		defer cancel()
		wait := exec.CommandContext(ctx, "docker", "run", "--rm",
			"--user", "1000:1000", "-e", "KEYCARD_CA_TIMEOUT=2",
			"-v", t.TempDir()+":/shared-ca:ro", image, "/bin/sh", "-c", "echo the agent started")
		out, err := wait.CombinedOutput()
		require.Error(t, err, "the entrypoint started the agent with no certificate:\n%s", out)
		assert.Contains(t, string(out), "did not appear within 2s", "the refusal says what it waited for")
		assert.NotContains(t, string(out), "the agent started", "the agent must not run")
	})
}

func goarch(t *testing.T) string {
	t.Helper()
	out := run(t, time.Minute, nil, "docker", "version", "--format", "{{.Server.Arch}}")
	return strings.TrimSpace(out)
}
