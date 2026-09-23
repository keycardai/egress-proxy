package audit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/audit"
)

func TestJSONSinkWritesOneLinePerRecord(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	sink := audit.NewJSONSink(&buf)
	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	stamped := audit.NewStamped(sink, audit.Stamp{
		SandboxID: "sbx-1", DocumentDigest: "sha256:abc", ConfigDigest: "sha256:def",
	}, func() time.Time { return at })

	stamped.Emit(audit.Record{
		ConnectionID: "c1",
		Scope:        audit.ScopeConnection,
		Destination:  audit.Destination{Host: "api.github.com", Port: 443},
		Decision:     audit.Decision{Verdict: "deny", Reason: "no_matching_endpoint"},
	})
	stamped.Emit(audit.Record{
		ConnectionID: "c2",
		RequestID:    "r1",
		Scope:        audit.ScopeRequest,
		Destination:  audit.Destination{Host: "pypi.org", Port: 443, SNI: "pypi.org"},
		Request:      &audit.RequestInfo{Method: "GET", Path: "/simple/", Host: "pypi.org"},
		Decision:     audit.Decision{Verdict: "allow", Reason: "endpoint_allowed", Endpoint: "pypi.org/"},
		Outcome:      &audit.Outcome{Status: 200},
	})

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	require.Len(t, lines, 2, "one line per record, got:\n%s", buf.String())
	want := []string{
		`{"ts":"2026-09-21T12:00:00Z","sandbox_id":"sbx-1","document":{"digest":"sha256:abc"},` +
			`"config":{"digest":"sha256:def"},` +
			`"connection_id":"c1","scope":"connection","destination":{"host":"api.github.com","port":443},` +
			`"decision":{"verdict":"deny","reason":"no_matching_endpoint"}}`,
		`{"ts":"2026-09-21T12:00:00Z","sandbox_id":"sbx-1","document":{"digest":"sha256:abc"},` +
			`"config":{"digest":"sha256:def"},` +
			`"connection_id":"c2","request_id":"r1","scope":"request",` +
			`"destination":{"host":"pypi.org","port":443,"sni":"pypi.org"},` +
			`"request":{"method":"GET","path":"/simple/","host":"pypi.org"},` +
			`"decision":{"verdict":"allow","reason":"endpoint_allowed","endpoint":"pypi.org/"},` +
			`"outcome":{"status":200}}`,
	}
	for i, line := range lines {
		assert.Equal(t, want[i], line, "line %d", i)
		assert.True(t, json.Valid([]byte(line)), "line %d is not JSON", i)
	}
}

func TestJSONSinkDoesNotInterleaveConcurrentRecords(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	sink := audit.NewJSONSink(&buf)
	var group sync.WaitGroup
	const writers, each = 8, 50
	for range writers {
		group.Go(func() {
			for range each {
				sink.Emit(audit.Record{Scope: audit.ScopeRequest, Destination: audit.Destination{Host: "x"}})
			}
		})
	}
	group.Wait()
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	require.Len(t, lines, writers*each, "one line per record")
	for _, line := range lines {
		require.True(t, json.Valid([]byte(line)), "interleaved line: %s", line)
	}
}

type failingWriter struct{}

var errWrite = errors.New("write refused")

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }

func TestJSONSinkCountsWriteFailures(t *testing.T) {
	t.Parallel()
	sink := audit.NewJSONSink(failingWriter{})
	sink.Emit(audit.Record{})
	sink.Emit(audit.Record{})
	assert.Equal(t, int64(2), sink.Failures(), "both write failures counted")
}
