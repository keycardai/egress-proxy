# Security model

This document lists the proxy enforcement surfaces, the threats against them,
their mitigations, and the tests for those mitigations. Add each surface when
the change that ships it is merged. Before a public release, read this document
against the code for every shipped surface. Do not tag a public release until
this document covers every shipped surface and the code review is complete.

`docs/configuration.md` defines the settings that this document names.

## Security posture

The proxy runs as a sidecar. It terminates the workload TLS with an authority
that it mints, evaluates every connection and request against a configured
endpoint list, and writes one audit record for each decision.

The proxy may share a network namespace with the workload that it governs in
some configurations, with network interception configured within that namespace.
The security claim is that every route out terminates at the proxy for an
unprivileged workload.

## Current guarantees

- The proxy fails closed. Every path that cannot produce a decision denies
  with a named reason. Examples include a CONNECT to an unlisted host, a
  handshake without an SNI, a `Host` header that differs from the SNI, a path
  that no endpoint covers, an endpoint without a credential source, and a name
  that resolves into a denied range. Tests in `internal/proxy` pin each
  reason.
- The proxy makes the decision before it spends resources. It refuses a
  denied host at CONNECT time, before it mints a leaf or dials an upstream.
  The test asserts zero minted leaves and zero upstream connections for a
  refused destination.
- The proxy uses the SNI as the decision key. It does not use the `Host`
  header because the workload controls that header and could use it to send a
  credential to another peer. The leaf matches the SNI. The SNI must match the
  CONNECT authority. The request `Host` must match the SNI and CONNECT port.
  The upstream connection uses the SNI, and its certificate must validate for
  that name.
- The proxy denies a connection with no SNI because it has no name to
  evaluate.
- The platform deny list takes precedence over the document. The proxy
  rejects a document that names a covered host at start-up. It rejects a
  permitted name that resolves into a covered range at dial time. Operators
  can configure exceptions, and the proxy reports them at every start. An
  exception can never cover the cloud metadata address.
- The proxy verifies upstream TLS with the system roots and
  `tls.upstream_ca_files`. It requires TLS 1.2 or later and never uses another
  proxy.
- The proxy streams responses without adding a buffer between the upstream
  and the workload.
- The audit stream cannot be turned off. It is the process stdout, with one
  JSON object per decision and the `sandbox_id` and document digest.

## Surfaces and threats

### CONNECT listener

The workload reaches this frontend through `HTTPS_PROXY`.

| Threat | Mitigation | Test |
|---|---|---|
| A workload crashes the sidecar with a malformed request. goproxy v1.9.1 dereferences a nil URL on an asterisk-form target inside a tunnel when `Host` carries a port. The library starts the handler in its own goroutine, so recovery outside that goroutine cannot catch the panic. | The loop inside the tunnel belongs to net/http, which recovers once per connection. `OPTIONS *` reaches the handler and is rejected with `malformed_request`. The TLS handshake runs in a proxy-owned goroutine that recovers. goproxy handles only the CONNECT line. | `TestCrashersAreRefusedAndTheProcessKeepsServing`, `TestACleartextPrefaceInATunnelClosesIt` |
| A workload opens connections until the sidecar runs out of file descriptors. | `limits.max_connections` caps simultaneous connections on the listener. Further accepts wait until a connection ends. | `TestConnectionCap` |
| A workload holds slow or silent connections open. | `limits.idle_timeout` closes a connection that neither reads nor writes on the frontend and inside a tunnel. The proxy limits a request head to 10 seconds and a TLS handshake to 10 seconds. | `TestIdleConnectionsAreClosed` |
| A workload pins the connection cap with requests to an upstream that never answers. The idle limit does not apply while a request waits on an upstream. | Four budgets bound an upstream that goes quiet: the dial, the TLS handshake, `limits.response_header_timeout` for the response head, and `limits.idle_timeout` on the upstream connection for a body that stops arriving. A request that exceeds one is rejected with `upstream_failed`, which frees the frontend connection. No budget bounds a whole request, because a server-sent event stream is a long request that is working. | `TestAStalledUpstreamIsBoundedByTheResponseHeaderTimeout`, `TestResponsesStream` |
| An origin-form request reaches the listener and probes for a service that the proxy does not provide. | The listener provides no service of its own. It rejects the request with `not_a_proxy_request` and writes an audit record. The admin socket provides health and information endpoints. | `TestCleartextAndNonProxyRequests` |
| A cleartext `http://` request carries a placeholder to a destination in cleartext. | Endpoints name HTTPS destinations. A cleartext request matches no endpoint and is rejected. | `TestCleartextAndNonProxyRequests` |

### Decision process

| Threat | Mitigation | Test |
|---|---|---|
| The workload opens a tunnel to an allowed host, then sends requests for another host. A future credential could reach that other host. | The SNI must match the CONNECT authority. The request `Host` must match the SNI and port. A mismatch produces `host_mismatch`. The upstream request uses the SNI. | `TestHandshakeRefusals`, `TestDeniedRequestsInsideAnAllowedTunnel` |
| A path falls outside an endpoint prefix, or dot segments send a request to another upstream path. | The path must be absolute and use its shortest form. If it does not, the proxy returns `malformed_request`. The longest matching prefix decides, and no match returns `no_matching_endpoint`. | `TestMatcherDecisions`, `TestDeniedRequestsInsideAnAllowedTunnel` |
| DNS points an allowed name at a cluster or metadata address. | The dialer checks every resolved address against the deny list before it opens a socket. A match returns `deny_always` and opens no connection. | `TestANameResolvingIntoADeniedRangeIsRefusedAtTheDial` |
| A document widens the platform list by naming a covered host or excepting the metadata address. | The proxy rejects both cases at start-up. | `TestCompileRefusals`, `TestDenyListRefusesAnExceptionCoveringTheMetadataAddress` |
| A request reaches an endpoint with a credential before a credential source exists. The request could carry the workload placeholder upstream. | The proxy rejects the request with `credential_unavailable`. | `TestDeniedRequestsInsideAnAllowedTunnel` |

### Certificate authority

| Threat | Mitigation | Test |
|---|---|---|
| The CA key reaches the workload through the shared certificate mount. | The proxy writes only the certificate to `ca.out_dir`. It writes the key only to `ca.state_dir`. It rejects a `state_dir` under or over `out_dir` twice: once against the text of the document, with both paths cleaned so a trailing slash or a dot segment cannot hide the nesting, and again after creating both directories and resolving their symlinks, before any key exists. | `TestWriteCertificateWritesOnlyTheCertificate`, `TestPrepareDirectoriesRefusesASymlinkedStateDirectory`, config `state dir under out dir` |
| The CA key persists on disk after the pod ends. | `ca.state_dir` must use tmpfs. The process checks the file system type and rejects every other type. It also rejects every directory on a platform that cannot show tmpfs. Files use mode 0600 in a directory with mode 0700. | `TestLoadOrNewRefusesADiskDirectory`, `TestLoadOrNewPersistsInAMemoryDirectory` |
| A leaf minted for one name authenticates another name. | Every leaf has exactly one SAN. The authority has path-length zero, so it cannot sign an intermediate. | `TestLeafVerifiesAgainstThePoolAndNothingElse` |
| The proxy trusts stored material that is corrupt or close to expiry. | Loading rejects a key that does not parse or does not match the certificate. It also rejects a certificate that expires within five minutes. | `TestLoadOrNewRefusesCorruptMaterial` |

### Admin socket

| Threat | Mitigation | Test |
|---|---|---|
| The workload reads the sandbox allowlist or probes health over loopback. | The admin surface uses a Unix socket in the proxy mount namespace. The socket has mode 0600 in a directory with mode 0700. The proxy rejects a relative path and a TCP address. | `TestServerAnswersHealthAndInfo`, `TestNewRefusals` |
| A wrong socket path causes the proxy to delete a file at start-up. | The proxy unlinks only an existing socket. Any other object at the path stops the process. | `TestNewRefusals`, `TestNewReplacesAStaleSocket` |

### Configuration document

| Threat | Mitigation | Test |
|---|---|---|
| A misspelled, repeated, or case-variant key silently changes enforcement. | The parser rejects unknown keys, repeated keys, and keys that differ only in case. | `TestParseRefusals` |
| An audit record cannot be tied to the document that made the decision. | Every record carries the document canonical digest. | `TestDigestIsOverTheDocumentAsWritten`, `TestJSONSinkWritesOneLinePerRecord` |
| An environment variable or flag changes enforcement without changing the digest. | Every record also carries `config.digest` over the settings after an override applies, so two sidecars that enforce differently never share it. The endpoints and policy still come from the document alone. The start-up log and `/info` name every overridden key, and the `EGRESS_PROXY_` prefix gives a manifest lint one namespace to inspect. | `TestConfigDigestCoversTheEffectiveSettings`, `TestOverrides`, `TestCommandResolvesFlagsAndEnvironment` |
| A build that denies different destinations is indistinguishable in the records. | `config.digest` covers a digest of the ranges, host names and suffixes compiled into the binary, so two builds that deny differently never share it. | `TestConfigDigestCoversTheEffectiveSettings` |

## Known limits

- The proxy does not offer HTTP/2 to the workload. The tunnel negotiates
  `http/1.1` only. gRPC through the proxy is not yet supported. Server-sent
  events (SSE) should work through the proxy.
- The proxy closes a cleartext preface inside a tunnel without sending a
  response. The proxy terminates TLS on every tunnel. Bytes that are not a TLS
  handshake fail the handshake, and the proxy closes the connection. The
  connection allow record remains, and the proxy logs the failure.
- An idle timeout does not limit a request in flight. A response that is still
  transferring is not idle. A stalled upstream keeps its connection until the
  workload or upstream closes it.
- goproxy discards bytes buffered after the CONNECT head. A client that sends
  its ClientHello before it reads the 200 loses those bytes, and the handshake
  fails. Clients wait for the 200, as RFC 9110 section 9.3.6 describes.
