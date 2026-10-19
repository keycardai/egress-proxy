// Package audit records every proxy decision to a sink which receives
// structured events. The default sink is a log of JSON objects (JSONL).
//
// The proxy writes one record for each connection-scoped decision and one for
// each request-scoped decision. Failure to write a record NEVER fails a
// request. The sink counts a write failure, and the request proceeds as
// decided.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keycardai/egress-proxy/internal/policy"
)

// Scope says which decision a record covers.
type Scope string

// The scopes.
const (
	ScopeConnection Scope = "connection"
	ScopeRequest    Scope = "request"
	// ScopeDNS is one name lookup answered by the allowlist resolver. The
	// record names the question and the response code, and the destination
	// host is the name that was asked for.
	ScopeDNS Scope = "dns"
)

// Record is one audited decision.
type Record struct {
	TS time.Time `json:"ts"`
	// SandboxID is sandbox.id from the document, on every record, unless a
	// request's assertion named a sandbox, in which case it is that name.
	SandboxID string `json:"sandbox_id"`
	// SandboxUUID is the runtime's own identifier for the asserted sandbox.
	// Absent where no assertion identified one.
	SandboxUUID string `json:"sandbox_uuid,omitempty"`
	// Application is the kind of sandbox the assertion named. Absent where
	// the assertion named none.
	Application string `json:"application,omitempty"`
	// OnBehalfOf is the principal who created the asserted sandbox, as the
	// runtime authenticated them. It is what the runtime asserted, not an
	// identity the proxy verified. Absent where the assertion named none.
	OnBehalfOf string `json:"on_behalf_of,omitempty"`
	// Identity is the identity the proxy acted as for an asserted sandbox.
	Identity *Identity `json:"identity,omitempty"`
	// Document identifies the configuration document that decided, and
	// Config the settings the process enforced. Both are needed: the
	// document digest covers the mounted file, and the config digest covers
	// what a flag, a variable or a default made of it.
	Document DocumentRef `json:"document"`
	Config   ConfigRef   `json:"config"`
	// ConnectionID joins the connection-scoped record to every request on
	// the same tunnel. RequestID identifies one request.
	ConnectionID string      `json:"connection_id,omitempty"`
	RequestID    string      `json:"request_id,omitempty"`
	Scope        Scope       `json:"scope"`
	Destination  Destination `json:"destination"`
	// Request is absent on a connection-scoped record.
	Request *RequestInfo `json:"request,omitempty"`
	// Query is the DNS question, present on a record with scope dns.
	Query    *QueryInfo `json:"query,omitempty"`
	Decision Decision   `json:"decision"`
	// Outcome is what came of an allowed request.
	Outcome *Outcome `json:"outcome,omitempty"`
}

// Identity names the application the proxy exchanged as for a request, and
// the user it exchanged for.
type Identity struct {
	ClientID string `json:"client_id,omitempty"`
	// User is the Keycard user id the exchange impersonated: the asserted
	// sandbox's owner_id, where the identity impersonates the sandbox
	// owner. Absent where the identity acts as itself.
	User string `json:"user,omitempty"`
}

// DocumentRef identifies the document by its digest, "sha256:<hex>" over the
// JCS-canonical form.
type DocumentRef struct {
	Digest string `json:"digest"`
}

// ConfigRef identifies the settings in force by a digest of the same shape.
// Two sidecars that answer every request alike share it.
type ConfigRef struct {
	Digest string `json:"digest"`
}

// Destination is where the connection or request was going. Host is the name
// the proxy decided on: the CONNECT authority for a connection, the SNI for
// a request.
type Destination struct {
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
	SNI  string `json:"sni,omitempty"`
	// OriginalAddress is the address the client opened the connection to,
	// before the redirect rewrote it, as "address:port". The transparent
	// frontend recovers it and the proxy records it without dialling it. It
	// is absent on a CONNECT tunnel, so its presence says the connection was
	// captured rather than proxied by configuration.
	OriginalAddress string `json:"original_address,omitempty"`
}

// RequestInfo is the request line, without the query.
type RequestInfo struct {
	Method string `json:"method"`
	// Path is the escaped path, the bytes the proxy sends upstream.
	// Decoding it would lose the difference the decision turns on:
	// "/a%2Fb" is one segment and "/a/b" is two.
	Path string `json:"path"`
	// Host is the Host header as the workload sent it. The request decision
	// compares it with the SNI.
	Host string `json:"host,omitempty"`
}

// QueryInfo is the DNS question a record covers. The name itself is
// Destination.Host.
type QueryInfo struct {
	// Type is the query type, such as A or AAAA. It is the numeric type
	// for one this build has no name for.
	Type string `json:"type"`
	// Class is the query class. Only IN resolves.
	Class string `json:"class"`
	// Protocol is udp or tcp. A resolver falls back to TCP for an answer
	// that does not fit in a datagram, RFC 7766 section 5.
	Protocol string `json:"protocol"`
	// Rcode is the response code the resolver sent, such as NOERROR,
	// NXDOMAIN or SERVFAIL.
	Rcode string `json:"rcode"`
}

// Decision is the verdict and why.
type Decision struct {
	Verdict policy.Verdict `json:"verdict"`
	Reason  policy.Reason  `json:"reason"`
	// Endpoint is the endpoint that matched, host plus path prefix.
	Endpoint string `json:"endpoint,omitempty"`
	// Error is why a check failed, when the denial came from a failure and
	// not from policy.
	Error string `json:"error,omitempty"`
}

// Outcome is the upstream's answer to an allowed request.
type Outcome struct {
	Status int `json:"status"`
	// Error is why the request did not complete.
	Error string `json:"error,omitempty"`
}

// Sink receives records.
type Sink interface {
	Emit(record Record)
}

// JSONSink writes one JSON object per line to a writer, serialized so
// concurrent decisions never interleave.
type JSONSink struct {
	mu       sync.Mutex
	out      io.Writer
	failures atomic.Int64
}

// NewJSONSink writes records to out.
func NewJSONSink(out io.Writer) *JSONSink {
	return &JSONSink{out: out}
}

// Emit writes the record. A write or encoding failure raises the failure
// count and nothing else.
func (s *JSONSink) Emit(record Record) {
	line, err := json.Marshal(record)
	if err != nil {
		s.failures.Add(1)
		return
	}
	line = append(line, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.out.Write(line); err != nil {
		s.failures.Add(1)
	}
}

// Failures counts the records the sink failed to write.
func (s *JSONSink) Failures() int64 {
	return s.failures.Load()
}

// Stamp is what every record of one process holds, whatever the decision.
type Stamp struct {
	SandboxID      string
	DocumentDigest string
	ConfigDigest   string
}

// Stamped fills in the Stamp and the time on each record, then forwards it.
type Stamped struct {
	sink  Sink
	stamp Stamp
	now   func() time.Time
}

// NewStamped returns a sink that stamps records before passing them to next.
// A nil clock means time.Now.
func NewStamped(next Sink, stamp Stamp, now func() time.Time) *Stamped {
	if now == nil {
		now = time.Now
	}
	return &Stamped{sink: next, stamp: stamp, now: now}
}

// Emit stamps and forwards the record.
func (s *Stamped) Emit(record Record) {
	record.TS = s.now().UTC()
	// A request whose assertion named a sandbox keeps that name. The
	// process-level sandbox fills every other record.
	if record.SandboxID == "" {
		record.SandboxID = s.stamp.SandboxID
	}
	record.Document = DocumentRef{Digest: s.stamp.DocumentDigest}
	record.Config = ConfigRef{Digest: s.stamp.ConfigDigest}
	s.sink.Emit(record)
}
