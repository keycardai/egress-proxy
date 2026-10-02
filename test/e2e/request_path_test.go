//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/policy"
)

// The sandboxes the test suite applies. All run the same images against the
// same zone. wrongUserPod impersonates a user the zone's policy refuses.
// forgedTokenPod authenticates with a token the API server did not sign.
const (
	sandboxPod   = "sandbox"
	wrongUserPod = "wrong-user"
	// wrongUser is a user the pod's ServiceAccount is not named after.
	wrongUser      = "someone-else"
	forgedTokenPod = "forged-token"
)

// actor is the ServiceAccount subject the zone reads out of the projected
// token. The API server signs that half, so a pod cannot claim another.
const actor = "system:serviceaccount:" + namespace + ":" + serviceAccount

// resolveExit is the status curl leaves for a name it could not resolve.
// The allowlist resolver answers NXDOMAIN for a name no endpoint declares,
// so a denied host fails before any connection is opened.
const resolveExit = 6

// tlsConnectExit is the status curl leaves when the peer closes the
// connection during the TLS handshake, which is what a refused connection
// looks like to the client.
const tlsConnectExit = 35

// attackerName is a name no endpoint declares. The cluster resolver would
// answer for it as readily as for any other name outside the cluster, so
// the allowlist is what refuses it.
const attackerName = "data.attacker.example"

// TestRequestPath proves the request path in a cluster: the images this
// repository ships, a pod that runs them, and requests made from inside the
// agent container. Every check reads the proxy's audit stream and the
// zone's request log back out of the containers that wrote them.
//
//nolint:paralleltest // the test owns one cluster and its checks read one shared zone log
func TestRequestPath(t *testing.T) {
	run := start(t)
	deployFixtures(t, run)
	sandbox(t, run, sandboxSpec{name: sandboxPod, user: serviceAccount})
	sandbox(t, run, sandboxSpec{name: wrongUserPod, user: wrongUser})
	sandbox(t, run, sandboxSpec{name: forgedTokenPod, user: serviceAccount, forgedToken: true})
	t.Cleanup(func() {
		if t.Failed() {
			dump(t, run, sandboxPod)
			dump(t, run, wrongUserPod)
			dump(t, run, forgedTokenPod)
			t.Logf("e2e: zone log:\n%s", containerLog(t, run, zonePod, zonePod, false))
		}
	})

	t.Run("the proxy answers the sandbox's name lookups", func(t *testing.T) {
		announced := containerLog(t, run, sandboxPod, proxyContainer, false)
		assert.Contains(t, announced, "name resolution in force",
			"the start-up log says the resolver is running")
		// The whole /info body also holds endpoint_hosts, so the
		// assertions read the dns object alone.
		resolves := reportedResolves(t, run, sandboxPod)
		for _, host := range []string{upstreamHost, zoneHost} {
			assert.Contains(t, resolves, host, "/info reports that %s resolves", host)
		}
		assert.NotContains(t, resolves, deniedHost, "/info reports no name the document does not declare")
	})

	t.Run("the proxy announces the deny list exceptions it runs with", func(t *testing.T) {
		announced := containerLog(t, run, sandboxPod, proxyContainer, false)
		for _, prefix := range clusterRanges {
			assert.Contains(t, announced, prefix, "the start-up log names the exception %s", prefix)
		}
		reported := probeInfo(t, run, sandboxPod)
		for _, prefix := range clusterRanges {
			assert.Contains(t, reported, prefix, "/info reports the exception %s", prefix)
		}
	})

	// The upstream's cluster address, which a client can open a connection
	// to without looking up a name.
	upstreamAddress := serviceAddress(t, run, upstreamPod)

	tests := []struct {
		name string
		pod  string
		// command runs in the agent container. It names no proxy: the
		// capture is what puts the request in front of the proxy.
		command []string
		// wantExit is the status the command leaves.
		wantExit int
		// wantStdout is what the command writes, exactly, when set.
		wantStdout string
		// wantContains and wantAbsent are substrings of what the command
		// wrote.
		wantContains []string
		wantAbsent   []string
		// wantRecord is the audit record the proxy writes for this request.
		wantRecord audited
		// wantExchanges is every token exchange this request made, in
		// order. An empty slice pins that the request cost the zone
		// nothing.
		wantExchanges []exchange
	}{
		{
			name:       "an allowed fetch with no credential succeeds",
			pod:        sandboxPod,
			command:    curl("https://" + upstreamHost + "/status/200"),
			wantStdout: "200",
			wantRecord: audited{
				scope: audit.ScopeRequest, verdict: policy.VerdictAllow, reason: policy.ReasonEndpointAllowed,
				host: upstreamHost, path: "/status/200", endpoint: upstreamHost + ":443/status/", status: 200,
			},
			wantExchanges: []exchange{},
		},
		{
			name:    "a credentialed fetch arrives at the upstream with the credential the zone issued",
			pod:     sandboxPod,
			command: curlWithPlaceholder("https://" + upstreamHost + "/headers"),
			wantContains: []string{
				`"Bearer ` + zoneCredential + `"`,
				`"` + upstreamHost + `"`,
			},
			wantAbsent: []string{placeholder},
			wantRecord: audited{
				scope: audit.ScopeRequest, verdict: policy.VerdictAllow, reason: policy.ReasonEndpointAllowed,
				host: upstreamHost, path: "/headers", endpoint: upstreamHost + ":443/headers", status: 200,
			},
			wantExchanges: []exchange{
				{Client: clientID, Actor: actor, Subject: serviceAccount, Resource: grantedResource},
			},
		},
		{
			name:       "a path no endpoint names is refused and makes no exchange",
			pod:        sandboxPod,
			command:    curl("https://" + upstreamHost + "/anything"),
			wantStdout: "403",
			wantRecord: audited{
				scope: audit.ScopeRequest, verdict: policy.VerdictDeny, reason: policy.ReasonNoMatchingEndpoint,
				host: upstreamHost, path: "/anything",
			},
			wantExchanges: []exchange{},
		},
		{
			// The host runs in the cluster and CoreDNS answers for it, so
			// the allowlist is what refuses the name. The refusal comes
			// at the lookup rather than at the connection, which is why
			// curl exits 6 and the record has scope dns.
			name:     "a denied host does not resolve and is refused with a named reason",
			pod:      sandboxPod,
			command:  curl("https://" + deniedHost + "/headers"),
			wantExit: resolveExit,
			wantRecord: audited{
				scope: audit.ScopeDNS, verdict: policy.VerdictDeny,
				reason: policy.ReasonNoMatchingEndpoint, host: deniedHost,
			},
			wantExchanges: []exchange{},
		},
		{
			name:     "a name no endpoint declares does not resolve",
			pod:      sandboxPod,
			command:  curl("https://" + attackerName + "/"),
			wantExit: resolveExit,
			wantRecord: audited{
				scope: audit.ScopeDNS, verdict: policy.VerdictDeny,
				reason: policy.ReasonNoMatchingEndpoint, host: attackerName,
			},
			wantExchanges: []exchange{},
		},
		{
			// No name is looked up, so this is the connection-scoped
			// decision. RFC 6066 section 3 forbids an IP literal in
			// server_name, so the ClientHello names no host and the proxy
			// has nothing to decide against.
			name:     "a connection to a cluster address offers no server name and is refused",
			pod:      sandboxPod,
			command:  curlInsecure("https://" + upstreamAddress + "/"),
			wantExit: tlsConnectExit,
			wantRecord: audited{
				scope: audit.ScopeConnection, verdict: policy.VerdictDeny,
				reason: policy.ReasonNoSNI, host: upstreamAddress,
			},
			wantExchanges: []exchange{},
		},
		{
			name:       "a configuration that names a different user is refused with exchange_denied",
			pod:        wrongUserPod,
			command:    curl("https://" + upstreamHost + "/headers"),
			wantStdout: "403",
			wantRecord: audited{
				scope: audit.ScopeRequest, verdict: policy.VerdictDeny, reason: policy.ReasonExchangeDenied,
				host: upstreamHost, path: "/headers", endpoint: upstreamHost + ":443/headers",
			},
			wantExchanges: []exchange{
				{Client: clientID, Actor: actor, Subject: wrongUser, Resource: grantedResource, Error: "access_denied"},
			},
		},
		{
			name:       "a workload token the API server did not sign is refused with exchange_failed",
			pod:        forgedTokenPod,
			command:    curl("https://" + upstreamHost + "/headers"),
			wantStdout: "502",
			wantRecord: audited{
				scope: audit.ScopeRequest, verdict: policy.VerdictDeny, reason: policy.ReasonExchangeFailed,
				host: upstreamHost, path: "/headers", endpoint: upstreamHost + ":443/headers",
			},
			// The zone refuses the assertion, so the record names no actor.
			wantExchanges: []exchange{
				{Client: clientID, Subject: serviceAccount, Resource: grantedResource, Error: "invalid_client"},
			},
		},
	}

	exchanges := 0
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := zoneExchanges(t, run)
			stdout, stderr, status := execInAgent(t, run, tc.pod, tc.command...)
			assert.Equal(t, tc.wantExit, status, "%v exited %d: %s", tc.command, status, stderr)
			if tc.wantStdout != "" {
				assert.Equal(t, tc.wantStdout, strings.TrimSpace(stdout), "what the command wrote")
			}
			for _, want := range tc.wantContains {
				assert.Contains(t, stdout, want, "what the command wrote")
			}
			for _, absent := range tc.wantAbsent {
				assert.NotContains(t, stdout, absent, "what the command wrote")
			}

			record := waitForRecord(t, run, tc.pod, tc.wantRecord)
			assertRecord(t, tc.wantRecord, record)
			assert.Equal(t, tc.pod, record.SandboxID, "the record names the sandbox that decided")

			after := waitForExchanges(t, run, len(before)+len(tc.wantExchanges))
			assert.Equal(t, tc.wantExchanges, after[len(before):], "the exchanges this request made")
			exchanges += len(tc.wantExchanges)
		})
	}

	// The per-check windows above would miss an exchange that arrived after
	// the last one closed, so the total is pinned once at the end.
	assert.Len(t, zoneExchanges(t, run), exchanges, "the exchanges the whole test made")
}

// curl fetches a URL and writes the status it got back and nothing else.
// It names no proxy variable, so a request that crosses the proxy proves
// the capture put it there.
func curl(url string) []string {
	return []string{"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", url}
}

// curlInsecure fetches a URL without verifying the server certificate, so
// a connection the proxy refuses fails on the refusal rather than on the
// name the leaf authenticates.
func curlInsecure(url string) []string {
	return append(curl(url), "-k")
}

// curlWithPlaceholder fetches a URL with the placeholder the workload
// holds in the Authorization header, and writes what came back. The shell
// expands UPSTREAM_TOKEN, the variable the document's credential.env
// names, so the request reaches the proxy with the value the placement has
// to replace.
func curlWithPlaceholder(url string) []string {
	return []string{"sh", "-c", `curl -sS -H "Authorization: Bearer $UPSTREAM_TOKEN" ` + url}
}

// audited is the audit record a check expects. The proxy writes one record
// per connection-scoped decision and one per request-scoped decision, so a
// check names the scope it reads.
type audited struct {
	scope   audit.Scope
	verdict policy.Verdict
	reason  policy.Reason
	host    string
	// path is empty on a connection-scoped record, which no path took part
	// in.
	path     string
	endpoint string
	// status is the upstream's answer, zero where no request reached one.
	status int
}

// matches finds the record a check is about: the scope and destination it
// names, and the path when it has one.
func (a audited) matches(record audit.Record) bool {
	if record.Scope != a.scope || record.Destination.Host != a.host {
		return false
	}
	if a.path == "" {
		return true
	}
	return record.Request != nil && record.Request.Path == a.path
}

// assertRecord pins every field of the decision, one assertion per field so
// a failure names the field that differs.
func assertRecord(t *testing.T, want audited, record audit.Record) {
	t.Helper()
	assert.Equal(t, want.verdict, record.Decision.Verdict, "decision.verdict")
	assert.Equal(t, want.reason, record.Decision.Reason, "decision.reason")
	assert.Equal(t, want.endpoint, record.Decision.Endpoint, "decision.endpoint")
	if want.status == 0 {
		assert.Nil(t, record.Outcome, "a denied request has no outcome")
		return
	}
	require.NotNil(t, record.Outcome, "an allowed request records what the upstream answered")
	assert.Equal(t, want.status, record.Outcome.Status, "outcome.status")
}

// waitForRecord reads the proxy container's log until the record a check is
// about is in it. The container log is another process's output, so it is
// polled rather than subscribed to.
func waitForRecord(t *testing.T, run *test, pod string, want audited) audit.Record {
	t.Helper()
	var found audit.Record
	waitFor(t, "the audit record for "+want.host+want.path, func() bool {
		for _, record := range auditRecords(t, run, pod) {
			if want.matches(record) {
				found = record
				return true
			}
		}
		return false
	})
	return found
}

// auditRecords reads the decision records out of a sandbox's proxy
// container. The container log holds the audit stream and the process log
// together, so a line that does not parse as a record is skipped.
func auditRecords(t *testing.T, run *test, pod string) []audit.Record {
	t.Helper()
	var records []audit.Record
	for line := range strings.SplitSeq(containerLog(t, run, pod, proxyContainer, false), "\n") {
		var record audit.Record
		if json.Unmarshal([]byte(line), &record) != nil || record.Scope == "" {
			continue
		}
		records = append(records, record)
	}
	return records
}

// exchange is one token request the zone read, as its log writes it.
type exchange struct {
	Client   string
	Actor    string
	Subject  string
	Resource string
	// Error is the OAuth error code the zone answered with, empty on a
	// token.
	Error string
}

// exchangeLine matches what fakeas.LogExchanges writes.
var exchangeLine = regexp.MustCompile(
	`^exchange client=(\S*) actor="([^"]*)" subject=(\S*) resource=(\S*) error="([^"]*)"$`,
)

// zoneExchanges reads every token request the zone has recorded, in order.
func zoneExchanges(t *testing.T, run *test) []exchange {
	t.Helper()
	found := []exchange{}
	for line := range strings.SplitSeq(containerLog(t, run, zonePod, zonePod, false), "\n") {
		fields := exchangeLine.FindStringSubmatch(strings.TrimSpace(line))
		if fields == nil {
			continue
		}
		found = append(found, exchange{
			Client: fields[1], Actor: fields[2], Subject: fields[3], Resource: fields[4], Error: fields[5],
		})
	}
	return found
}

// waitForExchanges reads the zone's log until it holds count lines. The
// zone is another pod, so its log is polled.
func waitForExchanges(t *testing.T, run *test, count int) []exchange {
	t.Helper()
	var found []exchange
	waitFor(t, "the zone to record every exchange", func() bool {
		found = zoneExchanges(t, run)
		return len(found) >= count
	})
	return found
}

// reportedResolves is the names /info says the resolver answers for.
func reportedResolves(t *testing.T, run *test, pod string) []string {
	t.Helper()
	var info struct {
		DNS struct {
			Resolves []string `json:"resolves"`
		} `json:"dns"`
	}
	body := probeInfo(t, run, pod)
	require.NoError(t, json.Unmarshal([]byte(body), &info), "parse /info from %s:\n%s", pod, body)
	require.NotEmpty(t, info.DNS.Resolves, "/info names what resolves in %s", pod)
	return info.DNS.Resolves
}

// probeInfo runs the probe subcommand in the proxy container, which is how
// the admin socket is reached from outside a container with no shell.
func probeInfo(t *testing.T, run *test, pod string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	err := run.client.Resources().ExecInPod(ctx, namespace, pod, proxyContainer,
		[]string{"/ko-app/egress-proxy", "probe", "info"}, &stdout, &stderr)
	require.NoError(t, err, "probe info in %s: %s", pod, stderr.String())
	return stdout.String()
}

// logInterval is how often a poll re-reads another process's output, and
// logDeadline bounds the wait.
const (
	logInterval = 500 * time.Millisecond
	logDeadline = 60 * time.Second
)

// waitFor polls until ready reports true. Polling is the fallback for a
// side effect of another process: a container log reaches this test only
// once the kubelet has collected it.
func waitFor(t *testing.T, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(logDeadline)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s", logDeadline, what)
		}
		time.Sleep(logInterval)
	}
}
