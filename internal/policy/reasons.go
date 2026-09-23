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
	// evaluate a host-scoped policy without a host. A redirected connection
	// opened straight to an address has no server name either, because
	// RFC 6066 section 3 forbids an IP literal there.
	ReasonNoSNI Reason = "no_sni"
	// ReasonCleartextNotForwarded means the connection sends cleartext
	// HTTP. The proxy forwards nothing cleartext, whatever the endpoint
	// list says, so the destination is unreachable until the client speaks
	// HTTPS. A deny-list hit keeps its own reason, because that answer is
	// more specific.
	ReasonCleartextNotForwarded Reason = "cleartext_not_forwarded"
	// ReasonNotRedirected means the destination recovered from a connection
	// on the transparent listener is that listener's own address. The
	// connection was opened to the proxy rather than redirected into it, so
	// there is no destination to decide.
	ReasonNotRedirected Reason = "not_redirected"
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
	// ReasonExchangeDenied means that the authorization server refused the
	// token exchange. Its policy does not permit the configured user on the
	// endpoint resource, or it does not permit this client to impersonate.
	// The refusal is permanent, so a retry returns the same answer.
	ReasonExchangeDenied Reason = "exchange_denied"
	// ReasonExchangeFailed means that the token exchange did not complete.
	// Discovery failed, the zone was unreachable, the exchange exceeded its
	// budget, or the zone returned an error that is not a policy refusal.
	ReasonExchangeFailed Reason = "exchange_failed"
	// ReasonUpstreamFailed means an allowed request produced no response
	// from the upstream.
	ReasonUpstreamFailed Reason = "upstream_failed"
	// ReasonCertificateUnavailable means the proxy could not mint a leaf for
	// a server name the policy allowed. The handshake fails and the tunnel
	// serves no request.
	ReasonCertificateUnavailable Reason = "certificate_unavailable"
	// ReasonEndpointAllowed is the reason on every allow, at both scopes.
	ReasonEndpointAllowed Reason = "endpoint_allowed"
)
