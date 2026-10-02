//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	utilexec "k8s.io/client-go/util/exec"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"

	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/internal/netsetup"
	"github.com/keycardai/egress-proxy/test/fakeas"
)

// What the fixtures are named. The ServiceAccount is named after the user
// the proxy impersonates: the zone reads the ServiceAccount subject out of
// the projected token and permits the exchange only for the user of the
// same name.
const (
	namespace      = "agents"
	serviceAccount = "igmua2g0fwapl21qll7tczdw7t"
	clientID       = "e2e-app-credential"
	// audience is what the projected token names and what the zone
	// requires of a client assertion.
	audience        = "keycard"
	zoneHost        = "zone." + namespace + ".svc.cluster.local"
	upstreamHost    = "upstream." + namespace + ".svc.cluster.local"
	deniedHost      = "denied." + namespace + ".svc.cluster.local"
	grantedResource = "https://" + upstreamHost + "/"
	//nolint:gosec // G101: the credential the fake zone issues, which is a fixture value
	zoneCredential  = "e2e-zone-issued-credential"
	fixtureCAConfig = "fixture-ca"
	agentContainer  = "agent"
	proxyContainer  = "proxy"
	zonePod         = "zone"
	upstreamPod     = "upstream"
	agentUID        = 1000
	// forgedTokenSecret holds a workload token this test suite signed. The
	// API server did not sign it, so the zone refuses the assertion.
	forgedTokenSecret = "forged-workload-token"
	// proxyUID is the uid the sidecar runs as and the uid the capture
	// exempts. It is the published default, and it is not the agent's, so
	// the capture tells the two apart.
	proxyUID = netsetup.DefaultProxyUID
	// placeholder is what the workload holds for the credentialed
	// endpoint. The proxy replaces it, so it never reaches the upstream.
	placeholder = "workload-placeholder"
)

// clusterRanges are the pod and service ranges k3s numbers this cluster
// out of. The platform deny list covers them as RFC 1918 space, so the
// sandbox document names them as deny list exceptions to reach the zone
// and the upstream at their cluster addresses.
var clusterRanges = []string{"10.42.0.0/16", "10.43.0.0/16"} //nolint:gochecknoglobals // one fixture value

// deployFixtures creates the namespace, the ServiceAccount, the fixture
// authority's material and the two servers the sandbox reaches, and waits
// for both servers to report ready.
func deployFixtures(t *testing.T, run *test) {
	t.Helper()
	ctx := context.Background()
	res := run.client.Resources()

	require.NoError(t, res.Create(ctx, &corev1.Namespace{
		Name: namespace,
	}), "create the namespace")
	require.NoError(t, res.Create(ctx, &corev1.ServiceAccount{
		Name: serviceAccount, Namespace: namespace,
	}), "create the ServiceAccount the projected token names")

	authority, err := ca.New(ca.Options{CommonName: "egress-proxy e2e fixture CA"})
	require.NoError(t, err, "mint the fixture authority")
	createTLSSecret(t, res, "zone-tls", authority, zoneHost)
	createTLSSecret(t, res, "upstream-tls", authority, upstreamHost)
	require.NoError(t, res.Create(ctx, &corev1.ConfigMap{
		Name: fixtureCAConfig, Namespace: namespace,
		Data: map[string]string{ca.CertificateFileName: string(authority.CertificatePEM())},
	}), "publish the fixture authority for tls.upstream_ca_files")
	createForgedToken(t, run, res)

	apply(t, run, "fixtures.yaml", map[string]string{
		"Namespace":         namespace,
		"ZoneImage":         run.images[roleZone],
		"UpstreamImage":     run.images[roleUpstream],
		"ClientID":          clientID,
		"Audience":          audience,
		"GrantedResource":   grantedResource,
		"GrantedCredential": zoneCredential,
	})
	waitReady(t, run, zonePod)
	waitReady(t, run, upstreamPod)
}

// createForgedToken publishes a workload token signed by a key the API
// server does not hold. Its issuer, audience and subject are the ones a
// projected token has, so the zone can refuse it only on the signature.
func createForgedToken(t *testing.T, run *test, res *resources.Resources) {
	t.Helper()
	signer, err := fakeas.NewSigner(clusterIssuer(t, run), audience)
	require.NoError(t, err, "build the key the API server does not hold")
	token, err := signer.Token("system:serviceaccount:" + namespace + ":" + serviceAccount)
	require.NoError(t, err, "sign the forged workload token")
	require.NoError(t, res.Create(context.Background(), &corev1.Secret{
		Name: forgedTokenSecret, Namespace: namespace,
		StringData: map[string]string{"token": token},
	}), "create the forged workload token")
}

// clusterIssuer reads the service account issuer from the API server's
// discovery document.
func clusterIssuer(t *testing.T, run *test) string {
	t.Helper()
	raw, err := run.clientset.Discovery().RESTClient().Get().
		AbsPath("/.well-known/openid-configuration").DoRaw(context.Background())
	require.NoError(t, err, "read the service account issuer discovery document")
	var document struct {
		Issuer string `json:"issuer"`
	}
	require.NoError(t, json.Unmarshal(raw, &document), "decode the discovery document: %s", raw)
	require.NotEmpty(t, document.Issuer, "the discovery document names an issuer: %s", raw)
	return document.Issuer
}

// createTLSSecret mints a leaf for host and publishes it as a TLS secret.
// Every leaf has one SAN, so a server is reachable under the one name its
// leaf authenticates.
func createTLSSecret(t *testing.T, res *resources.Resources, name string, authority *ca.Authority, host string) {
	t.Helper()
	leaf, err := authority.Leaf(host)
	require.NoError(t, err, "mint the leaf for %s", host)
	key, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	require.NoError(t, err, "marshal the leaf key for %s", name)
	secret := &corev1.Secret{
		Name: name, Namespace: namespace,
		Type: corev1.SecretTypeTLS,
		StringData: map[string]string{
			corev1.TLSCertKey:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})),
			corev1.TLSPrivateKeyKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
		},
	}
	require.NoError(t, res.Create(context.Background(), secret), "create the %s secret", name)
}

// sandboxSpec is one sandbox the test suite applies.
type sandboxSpec struct {
	// name is the pod and the sandbox id.
	name string
	// user is what the document impersonates.
	user string
	// forgedToken mounts the token this test suite signed in place of the
	// projected one.
	forgedToken bool
}

// sandbox applies one sandbox pod and its configuration document, and waits
// for it to report ready.
func sandbox(t *testing.T, run *test, spec sandboxSpec) {
	t.Helper()
	name, user := spec.name, spec.user
	document := render(t, "sandbox-config.yaml", map[string]any{
		"ZoneHost":           zoneHost,
		"ClientID":           clientID,
		"ImpersonateUser":    user,
		"RedirectPort":       netsetup.DefaultRedirectPort,
		"DNSPort":            netsetup.DefaultDNSPort,
		"DenyListExceptions": "[" + strings.Join(quoted(clusterRanges), ", ") + "]",
		"UpstreamHost":       upstreamHost,
		"GrantedResource":    grantedResource,
	})
	configMap := name + "-config"
	require.NoError(t, run.client.Resources().Create(context.Background(), &corev1.ConfigMap{
		Name: configMap, Namespace: namespace,
		Data: map[string]string{"config.yaml": document},
	}), "create the configuration document for %s", name)

	forged := ""
	if spec.forgedToken {
		forged = forgedTokenSecret
	}
	apply(t, run, "sandbox-pod.yaml", map[string]any{
		"Name":           name,
		"Namespace":      namespace,
		"ServiceAccount": serviceAccount,
		"ConfigMap":      configMap,
		"NetsetupImage":  run.images[roleNetsetup],
		"ProxyImage":     run.images[roleProxy],
		"SandboxImage":   run.images[roleSandbox],
		"ProxyUID":       proxyUID,
		"AgentUID":       agentUID,
		"Placeholder":    placeholder,
		"Audience":       audience,
		"ForgedToken":    forged,
	})
	waitReady(t, run, name)
}

// serviceAddress is a Service's cluster address. A client that opens a
// connection to it names no host, which is the connection-scoped decision
// no name lookup takes part in.
func serviceAddress(t *testing.T, run *test, name string) string {
	t.Helper()
	service := &corev1.Service{}
	require.NoError(t, run.client.Resources().Get(context.Background(), name, namespace, service),
		"read the %s service", name)
	require.NotEmpty(t, service.Spec.ClusterIP, "the %s service has a cluster address", name)
	return service.Spec.ClusterIP
}

// quoted wraps each entry in double quotes, so a Go slice renders as a
// YAML flow sequence.
func quoted(values []string) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = `"` + value + `"`
	}
	return out
}

// render reads a template under testdata and fills it in.
func render(t *testing.T, name string, data any) string {
	t.Helper()
	parsed, err := template.ParseFiles("testdata/" + name)
	require.NoError(t, err, "parse %s", name)
	var out bytes.Buffer
	require.NoError(t, parsed.Execute(&out, data), "render %s", name)
	return out.String()
}

// apply renders a manifest and creates every object in it, in the order
// the file writes them.
func apply(t *testing.T, run *test, name string, data any) {
	t.Helper()
	res := run.client.Resources()
	err := decoder.DecodeEach(context.Background(), strings.NewReader(render(t, name, data)),
		decoder.CreateHandler(res))
	require.NoError(t, err, "apply %s", name)
}

// waitReady waits for a pod to report ready. The sandbox pod reports ready
// once the proxy's startup probe passes and the agent container starts, so
// this is the signal the test waits on rather than a sleep.
func waitReady(t *testing.T, run *test, name string) {
	t.Helper()
	pod := &corev1.Pod{Name: name, Namespace: namespace}
	ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
	defer cancel()
	err := wait.For(conditions.New(run.client.Resources()).PodReady(pod),
		wait.WithContext(ctx), wait.WithTimeout(readyTimeout))
	if err != nil {
		dump(t, run, name)
	}
	require.NoError(t, err, "pod %s did not report ready", name)
}

// dump writes what every container in a pod logged, so a failure names why
// the pod did not come up.
func dump(t *testing.T, run *test, name string) {
	t.Helper()
	pod := &corev1.Pod{}
	if err := run.client.Resources().Get(context.Background(), name, namespace, pod); err != nil {
		t.Logf("e2e: read pod %s: %v", name, err)
		return
	}
	t.Logf("e2e: pod %s phase %s", name, pod.Status.Phase)
	for _, status := range append(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses...) {
		t.Logf("e2e: pod %s container %s ready=%t restarts=%d state=%+v",
			name, status.Name, status.Ready, status.RestartCount, status.State)
		t.Logf("e2e: pod %s container %s log:\n%s", name, status.Name, containerLog(t, run, name, status.Name, false))
		if status.RestartCount == 0 {
			continue
		}
		t.Logf("e2e: pod %s container %s last termination %+v", name, status.Name, status.LastTerminationState)
		t.Logf("e2e: pod %s container %s previous log:\n%s",
			name, status.Name, containerLog(t, run, name, status.Name, true))
	}
}

// containerLog reads what one container in a pod has written so far. The
// container log holds the audit stream on standard output and the process
// log on standard error, in the order the process wrote them.
func containerLog(t *testing.T, run *test, pod, container string, previous bool) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	stream, err := run.clientset.CoreV1().Pods(namespace).
		GetLogs(pod, &corev1.PodLogOptions{Container: container, Previous: previous}).Stream(ctx)
	if err != nil {
		return "read the log: " + err.Error()
	}
	defer func() { _ = stream.Close() }()
	body, err := io.ReadAll(stream)
	if err != nil {
		return "read the log: " + err.Error()
	}
	return string(body)
}

// execInAgent runs a command in a sandbox's agent container and returns
// what it wrote and the status it exited with.
func execInAgent(t *testing.T, run *test, pod string, command ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	err := run.client.Resources().ExecInPod(ctx, namespace, pod, agentContainer, command, &stdout, &stderr)
	status := 0
	var coded utilexec.CodeExitError
	switch {
	case err == nil:
	case errors.As(err, &coded):
		status = coded.ExitStatus()
	default:
		require.NoError(t, err, "run %v in %s: %s", command, pod, stderr.String())
	}
	return stdout.String(), stderr.String(), status
}
