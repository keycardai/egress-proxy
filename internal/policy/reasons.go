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
	// a server name the policy allowed. The handshake fails and no request
	// crosses the tunnel.
	ReasonCertificateUnavailable Reason = "certificate_unavailable"
	// ReasonProxyUnauthenticated means the CONNECT carried no
	// Proxy-Authorization matching listen.connect_auth_file. The proxy
	// answers 407 before any decision or leaf.
	ReasonProxyUnauthenticated Reason = "proxy_unauthenticated"
	// ReasonSandboxUnidentified means sandbox_assertion is configured and
	// the request carried no assertion, more than one, or one the proxy
	// could not verify: a bad signature, the wrong audience, an expired or
	// over-long lifetime, or a missing claim.
	ReasonSandboxUnidentified Reason = "sandbox_unidentified"
	// ReasonSandboxUnknown means the assertion verified, names no
	// application, and names a sandbox that no entry in sandboxes maps to
	// an identity.
	ReasonSandboxUnknown Reason = "sandbox_unknown"
	// ReasonApplicationUnknown means the assertion verified and its app
	// claim names an application that no entry in applications maps to an
	// identity. The sandbox map is not consulted for such a request.
	ReasonApplicationUnknown Reason = "application_unknown"
	// ReasonEndpointAllowed is the reason on every allow, at both scopes.
	ReasonEndpointAllowed Reason = "endpoint_allowed"
)

// Title is the sentence a refusal body carries for the reason, for a human
// reading it off a client that shows the body and nothing else. It is short
// and ends without a period. The code is the contract; a title may be
// reworded.
//
//nolint:cyclop // one arm per reason code, so exhaustive fails the build on a code with no title
func (r Reason) Title() string {
	switch r {
	case ReasonDenyAlways:
		return "The destination is on the platform deny list"
	case ReasonNoMatchingEndpoint:
		return "No endpoint in the document matches this request"
	case ReasonHostMismatch:
		return "The request names two different hosts"
	case ReasonNoSNI:
		return "The TLS handshake named no server"
	case ReasonCleartextNotForwarded:
		return "The proxy forwards no cleartext HTTP"
	case ReasonNotRedirected:
		return "The connection was opened to the proxy itself"
	case ReasonMalformedRequest:
		return "The request has no well-formed host and path"
	case ReasonNotAProxyRequest:
		return "The proxy listener serves no requests of its own"
	case ReasonCredentialUnavailable:
		return "No credential is available for this endpoint"
	case ReasonExchangeDenied:
		return "The zone refused to issue a credential"
	case ReasonExchangeFailed:
		return "The token exchange did not complete"
	case ReasonUpstreamFailed:
		return "The upstream produced no response"
	case ReasonCertificateUnavailable:
		return "The proxy could not mint a certificate for this server"
	case ReasonProxyUnauthenticated:
		return "The CONNECT carried no valid proxy credential"
	case ReasonSandboxUnidentified:
		return "The request carried no verifiable sandbox assertion"
	case ReasonSandboxUnknown:
		return "The assertion names a sandbox the proxy does not know"
	case ReasonApplicationUnknown:
		return "The assertion names an application the proxy does not know"
	case ReasonEndpointAllowed:
		return "The request is allowed"
	default:
		return "The request was refused"
	}
}
