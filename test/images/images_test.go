//go:build images

// Package images builds the three images this repository ships and checks
// each one in a container. It is behind the images build tag
// so `go test ./...` never builds an image. `make images` runs it, and so
// does the images job in CI.
//
// Nothing here pushes. Every build is local, and every image this lane
// makes is removed when it ends.
package images_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/internal/config"
	"github.com/keycardai/egress-proxy/internal/netsetup"
	"github.com/keycardai/egress-proxy/test/baseimage"
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
		log.Fatal("docker is not available")
	}
	code := m.Run()
	// The proxy image is built once for the whole lane, so it is removed
	// here rather than by one test's cleanup.
	if err := exec.CommandContext(context.Background(), "docker", "rmi", "-f", proxyImageRef).Run(); err != nil {
		log.Printf("failed to remove image %q: %v", proxyImageRef, err)
	}
	os.Exit(code)
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

// debianImage is the Debian base the images under images/ pin.
func debianImage(t *testing.T) string {
	t.Helper()
	ref, err := baseimage.Debian(repoRoot(t))
	require.NoError(t, err, "read the Debian base image")
	return ref
}

// docker runs one docker command in the repository root and returns its
// combined output, failing the test on a non-zero exit.
func docker(t *testing.T, timeout time.Duration, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "docker %s:\n%s", strings.Join(args, " "), out)
	return string(out)
}

// proxyImageRef is the reference `make image-proxy` leaves behind.
const proxyImageRef = "egress-proxy:" + tag

// buildProxyImage runs the target a release runs, so the lane drives the
// image the Makefile produces rather than one it assembled itself. It runs
// once for the whole lane.
var buildProxyImage = sync.OnceValue(func() error { //nolint:gochecknoglobals // one build for the lane
	root, err := filepath.Abs("../..")
	if err != nil {
		return fmt.Errorf("resolve the repository root: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "make", "image-proxy", "IMAGE_TAG="+tag)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("make image-proxy: %w\n%s", err, out)
	}
	return nil
})

// makeImage runs one Makefile image target and returns the reference it left
// behind.
func makeImage(t *testing.T, target, name string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), buildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "make", target, "IMAGE_TAG="+tag)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "make %s:\n%s", target, out)
	image := name + ":" + tag
	removeImage(t, image)
	return image
}

// proxyImage is the reference `make image-proxy` tagged.
func proxyImage(t *testing.T) string {
	t.Helper()
	require.NoError(t, buildProxyImage(), "build the proxy image")
	return proxyImageRef
}

// runStdout runs one command in the repository root and returns its
// standard output alone, passing standard error through.
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

// TestProxyImage builds the proxy image and drives the two subcommands in
// it. The image has no shell, so they are the only way in.
func TestProxyImage(t *testing.T) {
	t.Parallel()
	image := proxyImage(t)

	// The socket is not there, so the probe fails. While the proxy starts,
	// this failure keeps the workload container from starting.
	ctx, cancel := context.WithTimeout(t.Context(), runTimeout)
	defer cancel()
	probe := exec.CommandContext(ctx, "docker", "run", "--rm", image, "probe", "readyz")
	out, err := probe.CombinedOutput()
	require.Error(t, err, "probe readyz answered with no proxy running:\n%s", out)
	assert.Contains(t, string(out), "/run/egress/admin/admin.sock",
		"the failure names the socket the probe dialled")

	// No shell, so the probe has to be the binary itself.
	shell := exec.CommandContext(ctx, "docker", "run", "--rm", "--entrypoint", "/bin/sh", image, "-c", "true")
	require.Error(t, shell.Run(), "the proxy image has a shell")

	// The settings surface answers with no document and no socket, which is
	// how a chart lint outside this repository reads it.
	published := runStdout(t, runTimeout, nil, "docker", "run", "--rm", image, "settings")
	var report struct {
		EnvPrefix string `json:"env_prefix"`
		Settings  []struct {
			Env string `json:"env"`
		} `json:"settings"`
		Netsetup struct {
			ProxyUID int `json:"proxy_uid"`
		} `json:"netsetup"`
	}
	require.NoError(t, json.Unmarshal([]byte(published), &report), "settings printed:\n%s", published)
	assert.Equal(t, config.EnvPrefix, report.EnvPrefix, "env_prefix")
	assert.NotEmpty(t, report.Settings, "the image does not publish a variable")
	assert.Equal(t, netsetup.DefaultProxyUID, report.Netsetup.ProxyUID, "the proxy uid a pod has to match")
}

// TestProxyImageHoldsTheBindCapability reads the file capability back off
// the binary in the built image. The proxy image has no shell and no
// getcap, so the check copies the binary into a stage that has libcap2-bin
// and reads it there. A COPY between stages keeps the security.capability
// extended attribute, which is the same mechanism the image build itself
// relies on.
func TestProxyImageHoldsTheBindCapability(t *testing.T) {
	t.Parallel()
	image := proxyImage(t)

	reader := "egress-proxy-getcap:" + tag
	removeImage(t, reader)
	buildFromStdin(t, reader, capabilityReaderDockerfile, "PROXY_IMAGE="+image, "DEBIAN_IMAGE="+debianImage(t))

	out := docker(t, runTimeout, "run", "--rm", reader)
	assert.Contains(t, out, "/ko-app/egress-proxy cap_net_bind_service=ep",
		"getcap reads the capability off the binary the image ships")
}

// capabilityReaderDockerfile copies the binary out of the proxy image into
// a stage that can read a file capability. It is passed on standard input,
// so it does not need a build context.
const capabilityReaderDockerfile = `ARG PROXY_IMAGE
ARG DEBIAN_IMAGE
FROM ${PROXY_IMAGE} AS proxy
FROM ${DEBIAN_IMAGE}
RUN apt-get update \
	&& apt-get install --yes --no-install-recommends libcap2-bin \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=proxy /ko-app/egress-proxy /ko-app/egress-proxy
ENTRYPOINT ["getcap", "/ko-app/egress-proxy"]
`

// TestProxyImageBindsAPrivilegedPort runs the image the way a hardened pod
// runs it: a uid of its own, every capability dropped, no_new_privs on and
// the sysctl at 1024, so nothing but the capability can explain a bind
// below 1024. The two rows differ only in whether the container's bounding
// set holds NET_BIND_SERVICE.
//
// Without it the container does not reach main: a permitted file
// capability outside the bounding set makes the kernel refuse the execve.
// That is the failure an operator sees for a pod that drops ALL and adds
// nothing back.
func TestProxyImageBindsAPrivilegedPort(t *testing.T) {
	t.Parallel()
	image := proxyImage(t)
	config := privilegedBindConfig(t)

	tests := []struct {
		name string
		// capAdd is what the pod puts in the container's bounding set.
		capAdd string
		// wantServing says the proxy reached the bind and stayed up.
		wantServing bool
		wantLog     string
	}{
		{
			name:        "the pod puts NET_BIND_SERVICE in the bounding set",
			capAdd:      "NET_BIND_SERVICE",
			wantServing: true,
			wantLog:     `"connect":"[::]:1015"`,
		},
		{
			name:    "the pod drops every capability and adds none back",
			wantLog: "operation not permitted",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := []string{
				"run", "--detach",
				"--user", strconv.Itoa(netsetup.DefaultProxyUID) + ":" + strconv.Itoa(netsetup.DefaultProxyUID),
				"--cap-drop", "ALL",
				"--security-opt", "no-new-privileges=true",
				"--sysctl", "net.ipv4.ip_unprivileged_port_start=1024",
				"--tmpfs", "/run/egress", "--tmpfs", "/shared-ca", "--tmpfs", "/state",
				"--volume", config + ":/etc/keycard:ro",
			}
			if tc.capAdd != "" {
				args = append(args, "--cap-add", tc.capAdd)
			}
			args = append(args, image, "--config", "/etc/keycard/config.yaml")

			container := strings.TrimSpace(docker(t, runTimeout, args...))
			require.NotEmpty(t, container, "docker run printed no container id")
			t.Cleanup(func() {
				_ = exec.CommandContext(context.Background(), "docker", "rm", "-f", container).Run()
			})

			serving, logs := waitForServing(t, container)
			assert.Equal(t, tc.wantServing, serving, "the proxy bound every listener and stayed up:\n%s", logs)
			assert.Contains(t, logs, tc.wantLog, "the container said:\n%s", logs)
			if !tc.wantServing {
				return
			}
			// The kubelet runs the startup probe inside the running
			// container, so the probe inherits its uid, its bounding set
			// and no_new_privs, and execs the binary that holds the file
			// capability.
			probe := docker(t, runTimeout, "exec", container, "/ko-app/egress-proxy", "probe", "readyz")
			assert.Equal(t, "ok\n", probe, "probe readyz inside the running container")
		})
	}
}

// privilegedBindConfig writes the document the bind cases mount. The
// CONNECT frontend takes the redirect port, so the bind under test is one
// below 1024 and does not need a netsetup receipt. Nothing else in the
// document reaches the network.
func privilegedBindConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	document := "version: 1\n" +
		"sandbox:\n  id: images-lane\n" +
		"listen:\n  connect: \"0.0.0.0:" + strconv.Itoa(netsetup.DefaultRedirectPort) + "\"\n" +
		"ca:\n  state_dir: \"/state/ca\"\n" +
		"endpoints:\n  - url: https://upstream.test/\n"
	writeFile(t, filepath.Join(dir, "config.yaml"), []byte(document))
	//nolint:gosec // the proxy reads the document as its own uid, not as the host user
	require.NoError(t, os.Chmod(dir, 0o755), "the container reads the document")
	return dir
}

// waitForServing polls the container until the proxy logs that it is
// serving or the container exits, whichever comes first. The log line is a
// side effect of another process, so there is no signal to subscribe to.
func waitForServing(t *testing.T, container string) (bool, string) {
	t.Helper()
	deadline := time.Now().Add(runTimeout)
	for {
		logs := docker(t, time.Minute, "logs", container)
		if strings.Contains(logs, `"msg":"serving"`) {
			return true, logs
		}
		state := strings.TrimSpace(docker(t, time.Minute, "inspect", "-f", "{{.State.Running}}", container))
		if state == "false" {
			return false, logs
		}
		if time.Now().After(deadline) {
			t.Fatalf("the container neither served nor exited within %s:\n%s", runTimeout, logs)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// buildFromStdin builds one image from a Dockerfile on standard input, with
// no build context. args are --build-arg values.
func buildFromStdin(t *testing.T, image, dockerfile string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), buildTimeout)
	defer cancel()
	// A lone "-" is the Dockerfile on standard input with no build context.
	argv := make([]string, 0, 4+2*len(args))
	argv = append(argv, "build", "-t", image)
	for _, arg := range args {
		argv = append(argv, "--build-arg", arg)
	}
	cmd := exec.CommandContext(ctx, "docker", append(argv, "-")...)
	cmd.Dir = repoRoot(t)
	cmd.Stdin = strings.NewReader(dockerfile)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "docker build %s:\n%s", image, out)
}

// TestNetsetupImage builds the init container image and checks that it
// resolves the legacy iptables binaries the ruleset needs.
func TestNetsetupImage(t *testing.T) {
	t.Parallel()
	image := makeImage(t, "image-netsetup", "egress-netsetup")

	// --dry-run prints the ruleset and applies nothing, so this needs no
	// capability and no network namespace of its own.
	out := docker(t, runTimeout, "run", "--rm", image,
		"--dry-run", "--dns-servers=10.96.0.10", "--ipv6=off")
	assert.Contains(t, out, ":EGRESS_PROXY_NAT_OUTPUT - [0:0]", "the dry run prints the nat chain")
	assert.Contains(t, out, "--uid-owner 1337", "the ruleset excludes the proxy uid")
	assert.Contains(t, out, "REDIRECT --to-ports 1015", "the ruleset redirects to the transparent listener")

	// The image resolves the binary through PATH, the way egress-netsetup
	// does, and it has to be the legacy backend: the sandbox runtimes this
	// proxy targets never apply an nf_tables ruleset.
	version := docker(t, runTimeout, "run", "--rm", "--entrypoint", "/bin/sh",
		image, "-c", "iptables-legacy --version && ip6tables-legacy --version")
	assert.Contains(t, version, "(legacy)", "the image resolves the legacy backend, not nf_tables")
	assert.NotContains(t, version, "nf_tables", "no binary the lane resolves uses the nf_tables backend")

	// A run with the init container's capabilities, in the container's own
	// network namespace, loads both families through the image's restore
	// binaries and reads every rule back. --ipv6=off still programs the
	// ip6tables ruleset that denies IPv6, so both families are applied
	// whatever the namespace has. The host must have the legacy tables
	// loaded, because a container cannot load a kernel module. The sysctl
	// is the pod contract: netsetup refuses a redirect port at or above
	// net.ipv4.ip_unprivileged_port_start, and Docker sets that to 0.
	applied := docker(t, runTimeout, "run", "--rm",
		"--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--cap-add", "SETPCAP",
		"--sysctl", "net.ipv4.ip_unprivileged_port_start=1024",
		"--tmpfs", "/run/egress", image, "--dns-servers=10.96.0.10", "--ipv6=off")
	for _, want := range []string{
		`(?m)^# ipv4: \S+/iptables-legacy \(iptables v[0-9.]+ \(legacy\)\), \S+/iptables-legacy-restore$`,
		`(?m)^# ipv6: \S+/ip6tables-legacy \(ip6tables v[0-9.]+ \(legacy\)\), \S+/ip6tables-legacy-restore$`,
		`(?m)^# ipv4 verified: `,
		`(?m)^# ipv6 verified: `,
		`(?m)^# CAP_NET_ADMIN dropped from every capability set on this thread, no_new_privs set$`,
	} {
		assert.Regexp(t, want, applied, "the init container run said:\n%s", applied)
	}
}

// sharedCAMount is where the lane mounts the certificate the sidecar
// publishes. It is the proxy's own default for ca.out_dir, and no case
// sets KEYCARD_CA_FILE. If the image default and the proxy default differ,
// the entrypoint does not find the file and the test fails.
const sharedCAMount = config.DefaultCAOutDir

// TestSandboxBaseImage builds the base image and runs its entrypoint
// against a fake ca.out_dir, standing in for the volume the sidecar writes.
// The cases share one image, so they run one after the other.
//
//nolint:paralleltest,tparallel // the subtests share one image and run in sequence
func TestSandboxBaseImage(t *testing.T) {
	t.Parallel()
	image := makeImage(t, "image-sandbox-base", "sandbox-base")

	// The agent runs as the uid the contract names, with no capability.
	// openssl verify against the rebuilt bundle proves the entrypoint
	// installed the certificate. The rows differ only in where the trust
	// store directories come from: the image, whose ownership the Dockerfile
	// sets, or writable mounts under a read-only root. The read-only row
	// mounts exactly what docs/containers.md requires, and no writable /tmp.
	t.Run("the agent starts with the proxy CA in its trust store", func(t *testing.T) {
		tests := []struct {
			name string
			root []string
		}{
			{name: "the image's own trust store directories"},
			{
				name: "writable mounts under a read-only root",
				root: []string{
					"--read-only", "--tmpfs", "/etc/ssl/certs:uid=1000,gid=1000",
					"--tmpfs", "/usr/local/share/ca-certificates:uid=1000,gid=1000",
				},
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				shared, _ := sharedCA(t)
				args := append([]string{"run", "--rm", "--user", "1000:1000", "--cap-drop", "ALL"}, tc.root...)
				args = append(args, "-v", shared+":"+sharedCAMount+":ro", image,
					"/bin/sh", "-c", "openssl verify -CAfile \"$SSL_CERT_FILE\" "+sharedCAMount+"/ca.crt")
				out := docker(t, runTimeout, args...)
				assert.Contains(t, out, "the proxy CA is trusted", "the entrypoint says what it did")
				assert.Contains(t, out, sharedCAMount+"/ca.crt: OK", "the rebuilt bundle verifies the proxy CA")
			})
		}
	})

	// GIT_SSL_CAINFO names the bundle the entrypoint rebuilt, so git trusts
	// the sidecar's authority and nothing else new. The two rows differ only
	// in who signed the server's leaf: the authority the entrypoint
	// installed, or one it never saw.
	t.Run("git verifies a server against the rebuilt bundle", func(t *testing.T) {
		shared, signed := httpsFixture(t)
		_, foreign := httpsFixture(t)
		tests := []struct {
			name string
			// leaf is the directory holding the certificate and key the
			// server in the container presents.
			leaf    string
			wantErr bool
			wantOut string
		}{
			{name: "a leaf the installed authority signed", leaf: signed, wantOut: "refs/heads/main"},
			{
				name: "a leaf an authority the image never saw signed", leaf: foreign,
				wantErr: true, wantOut: "certificate",
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), runTimeout)
				defer cancel()
				out, err := exec.CommandContext(ctx, "docker", "run", "--rm",
					"--user", "1000:1000", "--cap-drop", "ALL", "--read-only",
					"--tmpfs", "/tmp:uid=1000,gid=1000",
					"--tmpfs", "/etc/ssl/certs:uid=1000,gid=1000",
					"--tmpfs", "/usr/local/share/ca-certificates:uid=1000,gid=1000",
					"-v", shared+":"+sharedCAMount+":ro", "-v", tc.leaf+":/tls:ro",
					image, "/bin/sh", "-c", gitOverHTTPS).CombinedOutput()
				if tc.wantErr {
					require.Error(t, err, "git took a leaf nothing in the bundle signed:\n%s", out)
					assert.NotContains(t, string(out), "refs/heads/main", "git listed the refs anyway")
				} else {
					require.NoError(t, err, "git against the rebuilt bundle:\n%s", out)
				}
				assert.Contains(t, string(out), tc.wantOut, "git said:\n%s", out)
			})
		}
	})

	// No row mounts a certificate, so every row must refuse to start the
	// agent. The rows differ in the timeout the entrypoint is given, which
	// decides whether it waits and how it exits.
	t.Run("the agent does not start without the certificate", func(t *testing.T) {
		tests := []struct {
			timeout  string
			wantCode int
			wantOut  string
		}{
			{timeout: "2", wantCode: 69, wantOut: "did not appear within 2s"},
			{timeout: "2m", wantCode: 64, wantOut: "KEYCARD_CA_TIMEOUT is 2m. Set it to a whole number of seconds"},
			{timeout: "-1", wantCode: 64, wantOut: "KEYCARD_CA_TIMEOUT is -1. Set it to a whole number of seconds"},
		}
		for _, tc := range tests {
			t.Run("KEYCARD_CA_TIMEOUT="+tc.timeout, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), runTimeout)
				defer cancel()
				wait := exec.CommandContext(ctx, "docker", "run", "--rm",
					"--user", "1000:1000", "-e", "KEYCARD_CA_TIMEOUT="+tc.timeout,
					"-v", t.TempDir()+":"+sharedCAMount+":ro", image, "/bin/sh", "-c", "echo the agent started")
				out, err := wait.CombinedOutput()
				var exit *exec.ExitError
				require.ErrorAs(t, err, &exit, "the entrypoint started the agent with no certificate:\n%s", out)
				assert.Equal(t, tc.wantCode, exit.ExitCode(), "exit code; the entrypoint said:\n%s", out)
				assert.Contains(t, string(out), tc.wantOut, "the refusal says why")
				assert.NotContains(t, string(out), "the agent started", "the agent must not run")
			})
		}
	})
}

// gitOverHTTPS serves a git repository over HTTPS inside the container,
// with a leaf the sidecar's authority signed, and lists its refs with the
// image's own git. The test checks the handshake: git reads the bundle
// the entrypoint rebuilt, through GIT_SSL_CAINFO.
const gitOverHTTPS = `set -e
export HOME=/tmp
git init -q -b main /tmp/work
cd /tmp/work
echo agent > file
git add file
git -c user.email=agent@example.invalid -c user.name=agent commit -q -m "one commit"
mkdir -p /tmp/srv
git clone -q --bare /tmp/work /tmp/srv/repo.git
git -C /tmp/srv/repo.git update-server-info

python3 - <<'PYTHON' &
import functools, http.server, socket, ssl

handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory="/tmp/srv")

class Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
server = Server(("::", 8443), handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PYTHON

for _ in $(seq 1 100); do
	curl -sk -o /dev/null https://localhost:8443/ && break
	sleep 0.2
done
git ls-remote https://localhost:8443/repo.git
`

// httpsFixture writes what the container mounts: the authority the sidecar
// would publish at ca.out_dir, and a leaf for localhost that the server in
// the container presents. It returns the two directories.
func httpsFixture(t *testing.T) (string, string) {
	t.Helper()
	shared, authority := sharedCA(t)
	leaf, err := authority.Leaf("localhost")
	require.NoError(t, err, "mint the server leaf")
	key, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	require.NoError(t, err, "marshal the leaf key")

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "tls.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}))
	writeFile(t, filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	//nolint:gosec // the server in the container reads the leaf as uid 1000
	require.NoError(t, os.Chmod(dir, 0o755), "the container reads the leaf")
	return shared, dir
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, data, 0o644), "write %s", path)
}

// sharedCA writes the authority the sidecar publishes at ca.out_dir and
// returns the directory the workload mounts and the authority itself.
func sharedCA(t *testing.T) (string, *ca.Authority) {
	t.Helper()
	authority, err := ca.New(ca.Options{CommonName: "images lane CA"})
	require.NoError(t, err, "mint the authority the sidecar would write")
	dir := t.TempDir()
	_, err = authority.WriteCertificate(dir)
	require.NoError(t, err, "write ca.crt to the shared volume")
	//nolint:gosec // the fixture stands in for a volume the kubelet mounts world-readable
	require.NoError(t, os.Chmod(dir, 0o755), "the workload reads the volume read-only")
	return dir, authority
}
