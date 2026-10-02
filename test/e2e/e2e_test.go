//go:build e2e

// Package e2e drives the images this repository ships in a k3d cluster. It
// builds them locally, imports them into the cluster, applies a sandbox pod
// that runs them, and makes requests from inside the agent container.
package e2e_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/support/k3d"
)

// clusterName is the cluster this suite creates and deletes.
const clusterName = "egress-proxy-e2e"

// k3sImage pins the node image.
const k3sImage = "rancher/k3s:v1.34.5-k3s1"

// imageTag is the tag this suite builds under. Images with this tag is removed
// during cleanup.
const imageTag = "egress-proxy-e2e"

// upstreamImage is the upstream the sandbox fetches from. go-httpbin echoes the
// request headers, which is how the test reads the credential that the proxy
// wrote.
const upstreamImage = "ghcr.io/mccutchen/go-httpbin:v2.16.0"

// The timeouts one step of the test gets.
const (
	// buildTimeout bounds one image build, which pulls a base image on a
	// cold machine.
	buildTimeout = 20 * time.Minute
	// clusterTimeout bounds creating and deleting the cluster.
	clusterTimeout = 10 * time.Minute
	// importTimeout bounds importing one image into the cluster.
	importTimeout = 5 * time.Minute
	// readyTimeout bounds waiting for a pod to report ready.
	readyTimeout = 5 * time.Minute
	// commandTimeout bounds one command run inside a container.
	commandTimeout = time.Minute
)

func TestMain(m *testing.M) {
	if reason := missing(); reason != "" {
		if os.Getenv("GITHUB_ACTIONS") != "" {
			log.Fatal("e2e: missing required dependencies and CI detected")
		}
		fmt.Fprintf(os.Stderr, "e2e: skipping the cluster tests: %s\n", reason)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// missing names the first thing the test needs and does not have, empty
// when it can run. The test never installs a provider: a machine without
// one skips.
func missing() string {
	if _, err := exec.LookPath("docker"); err != nil {
		return "docker is not on PATH"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").Run(); err != nil {
		return "no Docker daemon answers"
	}
	if _, err := exec.LookPath("k3d"); err != nil {
		return "k3d is not on PATH"
	}
	return ""
}

// test is one run: the cluster, the clients that reach it, and the images
// it runs.
type test struct {
	cluster   *k3d.Cluster
	client    klient.Client
	clientset *kubernetes.Clientset
	// images maps a role to the reference the cluster pulls it by.
	images map[string]string
}

// The roles a built image fills in the sandbox pod.
const (
	roleProxy    = "proxy"
	roleNetsetup = "netsetup"
	roleSandbox  = "sandbox"
	roleZone     = "zone"
	roleUpstream = "upstream"
)

// start builds the images, creates the cluster and imports them. The
// cluster is deleted when the test ends, whether it passed or failed.
func start(t *testing.T) *test {
	t.Helper()
	images := buildImages(t)

	// NEVER let the framework install a provider. Cluster.Create runs
	// `go install` for the k3d it pins when the binary it was given is not
	// on PATH, so the test looks up k3d here and stops when the machine
	// has none.
	k3dPath, err := exec.LookPath("k3d")
	require.NoError(t, err, "k3d is not on PATH")

	// Cluster.Create adopts a cluster of the same name, and this test then
	// fails on the objects the earlier run left behind. A run that was
	// killed leaves one, so delete it first. k3d reads the name exactly,
	// so a cluster of the operator's is never touched.
	removeCluster(t, k3dPath)

	cluster := k3d.NewCluster(clusterName)
	cluster.WithPath(k3dPath)
	t.Cleanup(func() { destroy(t, cluster) })

	ctx, cancel := context.WithTimeout(context.Background(), clusterTimeout)
	defer cancel()
	// The framework writes its own kubeconfig file, so k3d leaves the
	// operator's default kubeconfig and current context alone.
	kubeconfig, err := cluster.Create(ctx, "--image", k3sImage, "--wait",
		"--kubeconfig-update-default=false", "--kubeconfig-switch-context=false")
	require.NoError(t, err, "create the k3d cluster %s", clusterName)
	t.Logf("e2e: cluster %s is up, kubeconfig %s", clusterName, kubeconfig)

	for role, image := range images {
		importCtx, importCancel := context.WithTimeout(context.Background(), importTimeout)
		imported := cluster.LoadImage(importCtx, image)
		importCancel()
		require.NoError(t, imported, "import the %s image %s", role, image)
	}

	client, err := klient.New(cluster.KubernetesRestConfig())
	require.NoError(t, err, "build the cluster client")
	clientset, err := kubernetes.NewForConfig(cluster.KubernetesRestConfig())
	require.NoError(t, err, "build the typed cluster client")
	return &test{cluster: cluster, client: client, clientset: clientset, images: images}
}

// removeCluster deletes the test cluster before a run creates it. k3d
// exits 0 when it finds nothing of that name, so this is also the no-op on
// a clean machine.
func removeCluster(t *testing.T, k3dPath string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), clusterTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, k3dPath, "cluster", "delete", clusterName).CombinedOutput()
	require.NoError(t, err, "delete a leftover k3d cluster %s:\n%s", clusterName, out)
}

// destroy deletes the cluster. A cluster left running costs memory until
// someone notices, so this runs on a failure as well as on a pass.
func destroy(t *testing.T, cluster *k3d.Cluster) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), clusterTimeout)
	defer cancel()
	if err := cluster.Destroy(ctx); err != nil {
		t.Errorf("delete the k3d cluster %s: %v", clusterName, err)
	}
}

// buildImages builds every image the pod runs and returns the reference for
// each role. The three images this repository ships come from their
// Makefile targets, so the test runs what a release builds. The fake zone
// comes from ko, and the upstream is a published image the test pulls so
// the cluster needs no registry.
func buildImages(t *testing.T) map[string]string {
	t.Helper()
	images := map[string]string{
		roleProxy:    makeImage(t, "image-proxy", "egress-proxy"),
		roleZone:     koBuild(t, "egress-fakeas", "./test/fakeas/cmd/fakeas", "test/e2e/testdata/ko", dockerArch(t)),
		roleNetsetup: makeImage(t, "image-netsetup", "egress-netsetup"),
		roleSandbox:  makeImage(t, "image-sandbox-base", "sandbox-base"),
		roleUpstream: upstreamImage,
	}
	docker(t, buildTimeout, "pull", upstreamImage)
	return images
}

// makeImage runs one Makefile image target under the test image tag and
// returns the reference it left behind. The target owns how the image is
// built, so the test and a release build the same thing.
func makeImage(t *testing.T, target, name string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "make", target, "IMAGE_TAG="+imageTag)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "make %s:\n%s", target, out)
	image := name + ":" + imageTag
	removeImage(t, image)
	return image
}

// koBuild builds one main package into a local image and tags it under
// name, which is the reference the pod spec names. ko writes the reference
// it loaded to standard output, so the test tags what ko built rather than
// a name it guessed. Each build gets its own ko repository, so two of them
// never share a reference.
//
// ko leaves the image under two references of its own, the one it prints
// and the one --tags names, and both are removed when the test ends.
func koBuild(t *testing.T, name, main, configPath, arch string) string {
	t.Helper()
	repo := "ko.local/" + name
	built := strings.TrimSpace(runStdout(t, buildTimeout,
		[]string{"KO_CONFIG_PATH=" + configPath, "KO_DOCKER_REPO=" + repo},
		"go", "tool", "ko", "build", "--local", "--bare",
		"--tags", imageTag, "--platform", "linux/"+arch, main))
	require.NotEmpty(t, built, "ko printed no image reference for %s", main)
	image := name + ":" + imageTag
	docker(t, commandTimeout, "tag", built, image)
	removeImage(t, built)
	removeImage(t, repo+":"+imageTag)
	removeImage(t, image)
	return image
}

// removeImage removes an image the test built when the test ends.
func removeImage(t *testing.T, image string) {
	t.Helper()
	t.Cleanup(func() {
		_ = exec.CommandContext(context.Background(), "docker", "rmi", "-f", image).Run()
	})
}

// dockerArch is the architecture the daemon runs, which is the platform the
// cluster nodes run too.
func dockerArch(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(docker(t, commandTimeout, "version", "--format", "{{.Server.Arch}}"))
}

// repoRoot is the build context the Dockerfiles take and the module ko
// builds from.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	require.NoError(t, err)
	return strings.TrimSuffix(root, "/test/e2e")
}

// docker runs one docker command in the repository root and returns its
// combined output, failing the test on a non-zero exit.
func docker(t *testing.T, timeout time.Duration, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "docker %s:\n%s", strings.Join(args, " "), out)
	return string(out)
}

// runStdout runs a build tool in the repository root and returns its
// standard output, passing its standard error through.
func runStdout(t *testing.T, timeout time.Duration, env []string, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	require.NoError(t, err, "%s %s", name, strings.Join(args, " "))
	return string(out)
}
