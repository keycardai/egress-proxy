// Package policy decides which destinations and requests can leave the
// sandbox. It answers in two steps: the platform deny list, then the
// endpoint list of the configuration document.
//
// The deny list comes first. No document can name a destination the list
// covers. When a permitted name resolves into a denied range, the dialer
// refuses the connection.
package policy

// Verdict is how a decision is written on an audit record.
type Verdict string

// The verdicts.
const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
)

// Reason is the stable machine-readable code for a decision. An audit query
// and an agent's error handling both key on it, so NEVER change a code to
// improve its wording. Add a new code instead.
type Reason string

// The reason codes.
const (
	// ReasonDenyAlways means the destination is on the platform deny list,
	// by name or by the address it resolved to.
	ReasonDenyAlways Reason = "deny_always"
	// ReasonNoMatchingEndpoint means no endpoint covers the destination: no
	// endpoint names the host, or one does and none covers the path. Read
	// the record's scope to tell those apart. One code covers both because
	// the endpoint is the unit a document declares, which holds even where a
	// protocol matches on something other than a path.
	ReasonNoMatchingEndpoint Reason = "no_matching_endpoint"
	// ReasonHostMismatch means two names for one destination disagree.
	// Either the Host header is not the SNI, or the SNI is not the CONNECT
	// authority.
	ReasonHostMismatch Reason = "host_mismatch"
	// ReasonNoSNI means the TLS handshake named no server. The proxy cannot
	// evaluate a host-scoped policy without a host.
	ReasonNoSNI Reason = "no_sni"
	// ReasonMalformedRequest means the proxy cannot reduce the request to a
	// host and an absolute, normalized path.
	ReasonMalformedRequest Reason = "malformed_request"
	// ReasonNotAProxyRequest means the request arrived at the CONNECT
	// listener in origin form. The listener is a proxy and serves nothing of
	// its own.
	ReasonNotAProxyRequest Reason = "not_a_proxy_request"
	// ReasonCredentialUnavailable means the endpoint names a credential and
	// this process has no source for it. The proxy refuses the request, so
	// the placeholder the workload holds never reaches the upstream.
	ReasonCredentialUnavailable Reason = "credential_unavailable" //nolint:gosec // G101: a reason code, not a credential
	// ReasonUpstreamFailed means an allowed request produced no response
	// from the upstream.
	ReasonUpstreamFailed Reason = "upstream_failed"
	// ReasonEndpointAllowed is the reason on every allow. A request-scoped
	// record names the endpoint that matched; a connection-scoped record
	// names none, because no path took part in that decision.
	ReasonEndpointAllowed Reason = "endpoint_allowed"
)
