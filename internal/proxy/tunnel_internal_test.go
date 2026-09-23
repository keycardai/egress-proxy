package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/internal/policy"
)

// recordingSink collects the records a test emits.
type recordingSink struct {
	mu      sync.Mutex
	records []audit.Record
}

func (s *recordingSink) Emit(record audit.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, record)
}

func (s *recordingSink) all() []audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Record(nil), s.records...)
}

// unmintableHost carries a character an IA5String cannot hold, so
// x509.CreateCertificate refuses the SAN and the authority cannot mint a
// leaf for it. It is the reachable way to fail a mint for a name the policy
// allowed.
const unmintableHost = "аpple.com"

// TestGetCertificateRecordsAMintFailure covers the arm of the handshake
// where policy allows the name and the mint fails anyway. It calls
// GetCertificate directly, because crypto/tls will not carry this server
// name over the wire.
func TestGetCertificateRecordsAMintFailure(t *testing.T) {
	t.Parallel()
	deny, err := policy.NewDenyList(nil, nil)
	require.NoError(t, err, "NewDenyList")
	matcher, err := policy.Compile([]policy.Endpoint{{Host: unmintableHost, Port: 443, PathPrefix: "/"}}, deny)
	require.NoError(t, err, "Compile")
	authority, err := ca.New(ca.Options{})
	require.NoError(t, err, "ca.New")
	store, err := ca.NewStore(authority, 4)
	require.NoError(t, err, "ca.NewStore")
	sink := &recordingSink{}
	server, err := New(Options{
		Matcher:       matcher,
		Certificates:  store,
		Audit:         sink,
		UpstreamRoots: x509.NewCertPool(),
	})
	require.NoError(t, err, "New")

	state := &tunnel{connectionID: "conn-1", host: unmintableHost, port: 443}
	certificate, err := server.tlsConfig(state).GetCertificate(&tls.ClientHelloInfo{ServerName: unmintableHost})
	require.Error(t, err, "GetCertificate for a name the authority cannot mint")
	assert.Nil(t, certificate, "a failed mint yields no certificate")

	records := sink.all()
	require.Len(t, records, 1, "the failure emits one record")
	record := records[0]
	assert.Equal(t, audit.ScopeConnection, record.Scope, "record scope")
	assert.Equal(t, "conn-1", record.ConnectionID, "record connection")
	assert.Equal(t, policy.VerdictDeny, record.Decision.Verdict, "record verdict")
	assert.Equal(t, policy.ReasonCertificateUnavailable, record.Decision.Reason, "record reason")
	assert.NotEmpty(t, record.Decision.Error, "the record says why the mint failed")
	assert.Equal(t, unmintableHost, record.Destination.SNI, "record SNI")
}

// TestStatusForCertificateUnavailable pins the status the new reason maps
// to. The reason never reaches a response, so nothing else would notice a
// switch arm that forgot it.
func TestStatusForCertificateUnavailable(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 500, statusFor(policy.ReasonCertificateUnavailable), "the status for a failed mint")
}
