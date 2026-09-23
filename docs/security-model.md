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
  that no endpoint covers, an endpoint whose credential the proxy cannot
  supply, and a name that resolves into a denied range. Tests in
  `internal/proxy` pin each reason.
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
  permitted name that resolves into a covered range at dial time.
- `policy.deny_list_exceptions` can remove any address range from the
  platform deny list except the cloud metadata address `169.254.169.254`.
  That one address is the whole floor. A single entry can remove several
  ranges at once: `0.0.0.0/1` removes loopback, `10.0.0.0/8`, shared
  address space and `0.0.0.0/8` together. A document can also except the
  link-local range around the metadata address by naming the prefixes on
  either side of it. Treat the setting as an operator decision that widens
  reachability, and review it the way you review the endpoint list.
  An exception applies to addresses alone, so every compiled host name
  stays denied inside an excepted range, including the metadata names and
  the DNS-over-HTTPS resolvers. The proxy logs a warning for each exception
  on every start, `/info` lists them, and `config.digest` covers them.
- The proxy verifies upstream TLS with the system roots and
  `tls.upstream_ca_files`. It requires TLS 1.2 or later and never uses another
  proxy.
- The proxy streams responses without adding a buffer between the upstream
  and the workload.
- The proxy writes a credential into a request only at the placement the
  endpoint names, and the credential reaches no log line and no audit record.
- The audit stream cannot be turned off. It is the process stdout, with one
  JSON object per decision and the `sandbox_id` and document digest.

## Surfaces and threats

### CONNECT listener

The workload reaches this frontend through `HTTPS_PROXY`.

| Threat | Mitigation | Test |
|---|---|---|
| A workload crashes the sidecar with a malformed request. goproxy v1.9.1 dereferences a nil URL on an asterisk-form target inside a tunnel when `Host` carries a port. The library starts the handler in its own goroutine, so recovery outside that goroutine cannot catch the panic. | The loop inside the tunnel belongs to net/http, which recovers once per connection. `OPTIONS *` reaches the handler and is rejected with `malformed_request`. The TLS handshake runs in a proxy-owned goroutine that recovers. goproxy handles only the CONNECT line. | `TestCrashersAreRefusedAndTheProcessKeepsServing`, `TestACleartextPrefaceInATunnelClosesIt` |
| A workload opens connections until the sidecar runs out of file descriptors. | `limits.max_connections` caps simultaneous connections on the listener. Further accepts wait until a connection ends. | `TestConnectionCap` |
| A workload holds the connection cap by opening tunnels and then stalling the TLS handshake. | The handshake inside a tunnel has a ten-second budget. A handshake that spends it is closed, and the proxy logs it at warning level with the connection id and the authority, so the operator can see a client that holds slots this way. | `TestHandshakeFailureLogging`, `TestConnectionCap` |
| A workload holds slow or silent connections open. | `limits.idle_timeout` closes a connection that neither reads nor writes on the frontend and inside a tunnel. The proxy limits a request head to 10 seconds and a TLS handshake to 10 seconds. | `TestIdleConnectionsAreClosed`, `TestActiveStreamOutlivesIdleTimeout` |
| A workload keeps egress open after the sidecar is told to stop, by upgrading a tunnelled request to another protocol. `http.Server.Close` does not reach a connection the reverse proxy hijacked for the upgrade. | The drain is bounded by the shutdown grace. Every request still open when it ends is cancelled, which closes the upgraded connection and its upstream leg. `Run` waits for the handler, bounded by five seconds, so the request's record lands before the process exits unless the handler or the audit sink stalls past the bound, and the record reports the 101 rather than an informational status sent before it. | `TestShutdownDrainsInFlightRequest`, `TestShutdownEndsAnUpgradedConnection`, `TestAnUpgradedRequestIsAuditedBeforeRunReturns` |
| A workload pins the connection cap with requests to an upstream that never answers. The idle limit does not apply while a request waits on an upstream. | Four budgets bound an upstream that goes quiet: the dial, the TLS handshake, `limits.response_header_timeout` for the response head, and `limits.idle_timeout` on the upstream connection for a body that stops arriving. A request that exceeds one is rejected with `upstream_failed`, which frees the frontend connection. No budget bounds a whole request, because a server-sent event stream is a long request that is working. | `TestAStalledUpstreamIsBoundedByTheResponseHeaderTimeout`, `TestResponsesStream` |
| An origin-form request reaches the listener and probes for a service that the proxy does not provide. | The listener provides no service of its own. It rejects the request with `not_a_proxy_request` and writes an audit record. The admin socket provides health and information endpoints. | `TestCleartextAndNonProxyRequests` |
| A cleartext `http://` request carries a placeholder to a destination in cleartext. | Endpoints name HTTPS destinations. A cleartext request matches no endpoint and is rejected. | `TestCleartextAndNonProxyRequests` |

### Decision process

| Threat | Mitigation | Test |
|---|---|---|
| The workload opens a tunnel to an allowed host, then sends requests for another host. A future credential could reach that other host. | The SNI must match the CONNECT authority. The request `Host` must match the SNI and port. A mismatch produces `host_mismatch`. The upstream request uses the SNI. | `TestHandshakeRefusals`, `TestDeniedRequestsInsideAnAllowedTunnel` |
| A path falls outside an endpoint prefix, or dot segments send a request to another upstream path. | The path must be absolute and use its shortest form. If it does not, the proxy returns `malformed_request`. The longest matching prefix decides, and no match returns `no_matching_endpoint`. | `TestMatcherDecisions`, `TestDeniedRequestsInsideAnAllowedTunnel` |
| Escaping hides a path from the decision. The proxy judges one form and the upstream reads another, so `/api/%2e%2e/secret` passes a prefix check and reaches `/api/secret`, or `/a%2Fb` is judged as a child of `/a/` and arrives as one segment. | The decision reads the escaped path, the bytes the upstream receives, so the match and the forwarded request cannot disagree. Both that form and its decoded form must be in shortest form, which refuses escaped dot segments. A prefix must hold only characters a path carries unescaped. | `TestMatcherDecisions`, `TestAnEscapedPathReachesTheUpstreamUnchanged`, `TestDeniedRequestsInsideAnAllowedTunnel`, `connect_allow_deny.txtar` |
| A query that does not parse reaches the upstream shorter than the workload wrote it. `httputil.ReverseProxy` re-encodes a query it cannot parse and drops the pairs it could not read, so the upstream receives a request the workload did not send and the record describes the one the proxy was given. | The request decision parses the query and refuses with `malformed_request`. The credential writer refuses the same query, so a placement never writes into a query the proxy could not read. | `TestDeniedRequestsInsideAnAllowedTunnel`, `TestWriterReplacesWhatTheWorkloadSent`, `credential_injection.txtar` |
| DNS points an allowed name at a cluster or metadata address. | The dialer checks every resolved address against the deny list before it opens a socket. A match returns `deny_always` and opens no connection. | `TestANameResolvingIntoADeniedRangeIsRefusedAtTheDial` |
| A document widens the platform list by naming a covered host or excepting the metadata address. | The proxy rejects both cases at start-up. | `TestCompileRefusals`, `TestDenyListRefusesAnExceptionCoveringTheMetadataAddress` |
| An exception opens more of the platform deny list than the operator meant to open, such as `0.0.0.0/1`. | The proxy accepts it. The only range it refuses to except is the cloud metadata address. Each exception is a warning in the start-up log, `/info` lists the set in force, and `config.digest` covers it, so an audit record names the deny list the decision used. | `TestDenyListAddresses`, `TestConfigDigestCoversTheEffectiveSettings`, `connect_allow_deny.txtar` |
| An endpoint names an address in a spelling that is not an IP literal, such as `0177.0.0.1` or `2852039166`, which a resolver still reads as an address. | A host must be a DNS name of ASCII labels whose last label is not all digits. The endpoint list refuses the rest at start-up, and the dial guard refuses the address whatever the name. | `TestParseRefusesInvalidEndpoints`, `TestANameResolvingIntoADeniedRangeIsRefusedAtTheDial` |
| An endpoint carries a path prefix that covers more than it names, such as an empty prefix or one with dot segments. | Compile validates every prefix itself, so a list assembled outside the document parser gets the same refusal. | `TestCompileRefusals` |
| A listed host runs another service on another port, and the workload reaches it because the document named only the host. | An endpoint covers one port, 443 unless it names another. The connection decision matches the CONNECT port against the endpoint list, and a port no endpoint names is refused with `no_matching_endpoint` before any leaf is minted. | `TestDeniedConnections`, `TestMatcherDecisions`, `connect_allow_deny.txtar` |
| A request reaches an endpoint with a credential that the proxy cannot supply. The request could carry the workload placeholder upstream. | The proxy rejects the request with `credential_unavailable` when the process has no source, when the source holds no credential for the endpoint resource, and when this build does not write the placement. Nothing is dialed. | `TestCredentialRefusals`, `TestDeniedRequestsInsideAnAllowedTunnel` |

### Credential injection

The proxy writes the credential into a request at the place the endpoint
names.

| Threat | Mitigation | Test |
|---|---|---|
| A workload sends its own value at the placement and reaches the upstream with it, or keeps a value the proxy was meant to replace. | The placement is authoritative. A header placement replaces every value under that header name, and a query placement replaces every value under that parameter name. | `TestWriterReplacesWhatTheWorkloadSent`, `TestCredentialInjection` |
| A workload names the placement header in `Connection`, so the proxy writes a credential that the reverse proxy then drops as hop-by-hop. | The proxy writes the credential in the rewrite, which runs after the reverse proxy has removed the headers `Connection` names. | `TestCredentialInjection` |
| A credential holding a carriage return or newline splits the outbound request head and injects a header. | The proxy refuses a credential with a control character, at load and again when a source returns one, and denies the request with `credential_unavailable`. | `TestValidate`, `TestLoadStaticFileRefusals` |
| A header placement names `Host` and sends the credential to another peer, or names a header that would split the request head. | The document is refused at start-up for a `Host` placement, and the writer refuses a name that is not a valid header name, which denies the request. | config `a header placement naming Host`, `TestNewWriterRefusals` |
| A credential reaches the audit stream or the log, where it outlives the request. | A record carries the method, the path without its query, and the host. Every other text the proxy writes passes through `credential.Redact`. | `TestNoCredentialReachesARecordOrALogLine`, `TestRedact` |
| The static credential file is readable by another user of the node or by the workload. | The loader refuses a file with any group or other permission bit, and refuses anything that is not a regular file. | `TestLoadStaticFileRefusals` |
| Two credential sources answer, and a record cannot say which one did. | The document is refused when it names both a static file and an identity. | config `a static credential file together with an identity` |

### Certificate authority

| Threat | Mitigation | Test |
|---|---|---|
| The CA key reaches the workload through the shared certificate mount. | The proxy writes only the certificate to `ca.out_dir`. It writes the key only to `ca.state_dir`. It rejects a `state_dir` under or over `out_dir` twice: once against the text of the document, with both paths cleaned so a trailing slash or a dot segment cannot hide the nesting, and again after creating both directories and resolving their symlinks, before any key exists. | `TestWriteCertificateWritesOnlyTheCertificate`, `TestPrepareDirectoriesRefusesASymlinkedStateDirectory`, config `state dir under out dir` |
| The CA key persists on disk after the pod ends. | `ca.state_dir` must use tmpfs. The process checks the file system type and rejects every other type. It also rejects every directory on a platform that cannot show tmpfs. Files use mode 0600 in a directory with mode 0700. | `TestLoadOrNewRefusesADiskDirectory`, `TestLoadOrNewPersistsInAMemoryDirectory` |
| A leaf minted for one name authenticates another name. | Every leaf has exactly one SAN. The authority has path-length zero, so it cannot sign an intermediate. | `TestLeafVerifiesAgainstThePoolAndNothingElse` |
| The proxy trusts stored material that is corrupt, unusable or close to expiry. | Loading rejects a key that does not parse or does not match the certificate, a certificate that is not a CA, one that cannot sign certificates, and one that expires within five minutes. | `TestLoadChecksMaterial`, `TestLoadOrNewRefusesCorruptMaterial` |
| A tunnel the policy allowed fails to mint a leaf and the refusal goes unrecorded. | A failed mint emits a connection-scoped `certificate_unavailable` record and fails the handshake, so no request crosses the tunnel. | `TestGetCertificateRecordsAMintFailure` |

### Admin socket

| Threat | Mitigation | Test |
|---|---|---|
| The workload reads the sandbox allowlist or probes health over loopback. | The admin surface uses a Unix socket in the proxy mount namespace. The socket has mode 0600 in a directory with mode 0700. The proxy rejects a relative path and a TCP address. | `TestServerAnswersHealthAndInfo`, `TestNewRefusals` |
| A container sharing the socket volume connects to the admin socket, or unlinks it and binds its own. | The socket directory is set to mode 0700 on every start, because a mounted directory already exists and keeps the mode the container runtime gave it. The proxy refuses to start when the directory does not end up at 0700. The directory mode also covers the window between the bind, which honors the process umask, and the chmod of the socket to 0600. | `TestNewSetsTheDirectoryMode`, `TestCheckDirMode` |
| A wrong socket path causes the proxy to delete a file at start-up. | The proxy unlinks only an existing socket. Any other object at the path stops the process. | `TestNewRefusals`, `TestNewReplacesAStaleSocket` |

### Configuration document

| Threat | Mitigation | Test |
|---|---|---|
| A misspelled, repeated, or case-variant key silently changes enforcement. | The parser rejects unknown keys, repeated keys, keys that differ only in case, and a second YAML document. | `TestParseRefusesMalformedDocuments` |
| An audit record cannot be tied to the document that made the decision. | Every record carries the document canonical digest. | `TestDigestIsOverTheDocumentAsWritten`, `TestJSONSinkWritesOneLinePerRecord`, `TestTruncatedResponseIsAudited` |
| An environment variable or flag changes enforcement without changing the digest. | Every record also carries `config.digest` over the settings after an override applies, so two sidecars that enforce differently never share it. The endpoints and policy still come from the document alone. The start-up log and `/info` name every overridden key, and the `EGRESS_PROXY_` prefix gives a manifest lint one namespace to inspect. | `TestConfigDigestCoversTheEffectiveSettings`, `TestOverrides`, `TestCommandResolvesFlagsAndEnvironment` |
| A build that denies different destinations is indistinguishable in the records. | `config.digest` covers a digest of the ranges, host names and suffixes compiled into the binary, so two builds that deny differently never share it. | `TestConfigDigestCoversTheEffectiveSettings` |

## Known limits

- The proxy does not offer HTTP/2 to the workload. The tunnel negotiates
  `http/1.1` only. gRPC through the proxy is not yet supported. Server-sent
  events (SSE) should work through the proxy.
- The proxy closes a cleartext preface inside a tunnel without sending a
  response. The proxy terminates TLS on every tunnel. Bytes that are not a TLS
  handshake fail the handshake, and the proxy closes the connection. The proxy
  logs the failure at info level. A client that stalls rather than failing
  holds the connection, and its slot against `limits.max_connections`, for the
  ten-second handshake budget. That case logs at warning level. A handshake
  that fails for a reason the policy did not decide carries no audit record in
  either case, because the connection-scoped allow is written only once the
  tunnel is established.
- An idle timeout does not limit a request in flight. A response that is still
  transferring is not idle. A stalled upstream keeps its connection until the
  workload or upstream closes it.
- goproxy discards bytes buffered after the CONNECT head. A client that sends
  its ClientHello before it reads the 200 loses those bytes. The handshake then
  waits for a ClientHello that already went missing and spends the whole
  budget, which is the warning above. Clients wait for the 200, as RFC 9110
  section 9.3.6 describes.
