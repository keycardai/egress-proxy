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
- The proxy mints the upstream credential only after the endpoint list allows
  the request. The exchange sends the user name without a signature, so the
  zone's policy must refuse an unauthorized user.
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
| A query that does not parse reaches the upstream shorter than the workload wrote it. `httputil.ReverseProxy` re-encodes an invalid query and drops pairs it cannot read. The upstream then receives a request the workload did not send. | The request decision parses the query and refuses it with `malformed_request`. The credential writer applies the same check, so it never writes to an invalid query. | `TestDeniedRequestsInsideAnAllowedTunnel`, `TestWriterReplacesWhatTheWorkloadSent`, `credential_injection.txtar` |
| DNS points an allowed name at a cluster or metadata address. | The dialer checks every resolved address against the deny list before it opens a socket. A match returns `deny_always` and opens no connection. | `TestANameResolvingIntoADeniedRangeIsRefusedAtTheDial` |
| A document widens the platform list by naming a covered host or excepting the metadata address. | The proxy rejects both cases at start-up. | `TestCompileRefusals`, `TestDenyListRefusesAnExceptionCoveringTheMetadataAddress` |
| An exception opens more of the platform deny list than the operator meant to open, such as `0.0.0.0/1`. | The proxy accepts it. The only range it refuses to except is the cloud metadata address. Each exception is a warning in the start-up log, `/info` lists the set in force, and `config.digest` covers it, so an audit record names the deny list the decision used. | `TestDenyListAddresses`, `TestConfigDigestCoversTheEffectiveSettings`, `connect_allow_deny.txtar` |
| An endpoint names an address in a spelling that is not an IP literal, such as `0177.0.0.1` or `2852039166`, which a resolver still reads as an address. | A host must be a DNS name of ASCII labels whose last label is not all digits. The endpoint list refuses the rest at start-up, and the dial guard refuses the address whatever the name. | `TestParseRefusesInvalidEndpoints`, `TestANameResolvingIntoADeniedRangeIsRefusedAtTheDial` |
| An endpoint carries a path prefix that covers more than it names, such as an empty prefix or one with dot segments. | Compile validates every prefix itself, so a list assembled outside the document parser gets the same refusal. | `TestCompileRefusals` |
| A listed host runs another service on another port, and the workload reaches it because the document named only the host. | An endpoint covers one port, 443 unless it names another. The connection decision matches the CONNECT port against the endpoint list, and a port no endpoint names is refused with `no_matching_endpoint` before any leaf is minted. | `TestDeniedConnections`, `TestMatcherDecisions`, `connect_allow_deny.txtar` |
| A request reaches an endpoint with a credential that the proxy cannot supply. The request can carry the workload placeholder upstream. | The proxy rejects the request with `credential_unavailable` when it has no source, when the source has no credential for the endpoint resource, or when it does not support the placement. Nothing is dialed. | `TestCredentialRefusals`, `TestDeniedRequestsInsideAnAllowedTunnel` |

### Credential injection

The proxy writes a credential only at the placement that the endpoint names.

| Threat | Mitigation | Test |
|---|---|---|
| A workload sends its own value at the placement and reaches the upstream with it, or keeps a value the proxy must replace. | The placement wins. A header placement replaces every value under that header name. A query placement replaces every value under that parameter name. | `TestWriterReplacesWhatTheWorkloadSent`, `TestCredentialInjection` |
| A workload names the placement header in `Connection`, so the proxy writes a credential that the reverse proxy then drops as hop-by-hop. | The proxy writes the credential after the reverse proxy removes the headers named by `Connection`. | `TestCredentialInjection` |
| A credential holding a carriage return or newline splits the outbound request head and injects a header. | The proxy refuses a credential with a control character when it loads the source and when the source returns one. It denies the request with `credential_unavailable`. | `TestValidate`, `TestLoadStaticFileRefusals` |
| A header placement names a header that the connection, the proxy, or the upstream trusts, such as `Host`. `net/http` writes `Host` from the request target, so the credential would not reach the wire. | `credential.NewWriter` refuses banned names. The document parser and endpoints built in code get the same refusal. The list includes the hop-by-hop headers in RFC 9110 section 7.6.1, `Content-Length`, `Host`, `Forwarded`, and the `x-forwarded-` and `sec-` families. `Authorization` is allowed. | `TestNewWriterRefusesABannedHeaderName`, `TestNewWriterAcceptsAHeaderName`, config `a header placement naming Host` |
| A header placement names a header that would split the request head. | The writer refuses a name that is not a valid header name, which denies the request. | `TestNewWriterRefusals` |
| The credential writer fails and the request reaches the upstream with whatever the workload sent at the placement. | The rewrite records the failure. The round trip rejects the request before it dials. The request is denied with `credential_unavailable` and nothing is opened. | `TestAFailedCredentialWriteDenies` |
| A credential reaches the audit stream or the log, where it outlives the request. | A record carries the method, the path without its query, and the host. `credential.Redact` processes request error text written by the proxy. It replaces both the raw header form and the percent-encoded query form. Raw ReverseProxy diagnostics are disabled because body-read errors can quote upstream response bytes. Incomplete responses still produce an audit record with an outcome error. | `TestRedact`, `TestEmitForwardedRedactsTheCredential`, `TestNoCredentialReachesARecordOrALogLine`, `credential_injection.txtar` |
| A malformed credential document puts secret values, keys, or paths in a parser error printed at startup. | The static-file parser reports the file path and failing stage without including parser diagnostics. | `TestStaticFileParseErrorsDoNotExposeCredentials`, `credential_injection.txtar` |
| The static credential file is readable by another user of the node or by the workload. | The loader refuses a file with any group or other permission bit, and refuses anything that is not a regular file. | `TestLoadStaticFileRefusals` |
| Two credential sources answer, and a record cannot identify the source. | The proxy refuses a document that names both a static file and an identity. It also refuses an identity that names both client authentication mechanisms. `config.digest` covers the source in force, so two sidecars that read different sources never share it. | config `a static credential file together with an identity`, `identity with both client authentication mechanisms`, `TestConfigDigestCoversTheEffectiveSettings` |

### Token exchange

The proxy exchanges for the upstream credential at `identity.zone_url` for
each request that an endpoint with a credential allows. The exchange
impersonates `identity.impersonate.user` and uses the client secret at
`identity.client_secret_file`. This build refuses `identity.workload_token_file`.

| Threat | Mitigation | Test |
|---|---|---|
| The workload reads the client secret and mints credentials for itself, bypassing the endpoint list. | The proxy reads the file at the configured path and writes it nowhere else. The secret reaches no log line, audit record, `/info` answer, or form parameter because the proxy sends it in HTTP basic credentials. The file must be readable by its owner alone, and the proxy refuses any non-regular file. The pod controls whether the workload can read the path. This repository does not define that pod contract. | `TestReadSecretFileRefusals`, `TestDescribeNamesTheSourceAndNoSecret`, `TestTheWireForm`, `token_exchange.txtar` |
| `identity.zone_url` resolves into the cluster or onto the metadata address, so the client secret is offered to something that is not the zone. | The exchange uses the platform deny list for the zone connection. It refuses a resolved address on that list before it opens a socket. | `TestADeniedZoneAddressIsNotDialed` |
| A server that is not the zone answers discovery, takes the client secret, and issues credentials the proxy writes into requests. | The exchange verifies the zone with the system roots and `tls.upstream_ca_files`. It requires TLS 1.2 or later and uses no proxy. RFC 8414 section 3.3 requires the metadata to name the configured zone as its issuer. A mismatch fails the exchange before the proxy posts a secret. | `TestTheZoneIssuerMustMatchTheConfiguredZone` |
| Metadata that names the configured zone as its issuer points `token_endpoint` at another host or at cleartext, so the client secret goes somewhere else. RFC 8414 section 3.3 binds the issuer and says nothing about `token_endpoint`. | Every request the exchange makes must be https, discovery and the token request alike. A cleartext endpoint reaches no socket. The exchange also refuses to follow a redirect, so a 307 from the token endpoint cannot move the secret to another host or to another port on the same host. | `TestTheTokenEndpointMustBeHTTPS`, `TestTheExchangeRefusesAnUnsafeZone/the_token_endpoint_redirects` |
| A zone streams a large body inside the exchange budget, which spends the sidecar's memory, or returns an access token too large for the upstream to accept. | The exchange reads at most 64 KiB from the zone and fails the exchange past that. | `TestTheExchangeRefusesAnUnsafeZone/the_token_response_is_larger_than_the_limit` |
| A request the endpoint list already denies still spends an exchange, so the zone sees traffic the policy refused. | The exchange runs only after the request decision allows and the endpoint names a credential. A denied request reaches no zone. | `TestTheSourceReachesTheZoneOnlyOnCredential`, `token_exchange.txtar` |
| A zone that accepts the connection and then goes quiet holds the request and its slot against `limits.max_connections` indefinitely. | `limits.exchange_timeout` bounds one exchange, including discovery. The dial and TLS handshake to the zone each have five seconds inside this budget. A request that spends the budget is denied with `exchange_failed`. | `TestFailuresAreTwoClasses/the_zone_accepts_the_request_and_never_answers` |
| A refusal by the zone's policy is indistinguishable from a zone that could not be reached, so an operator cannot tell a misconfigured policy from an outage, and an agent retries what will never succeed. | The proxy uses separate reason codes. `exchange_denied` means that the zone read its policy and refused, and it answers 403. The zone says so with `access_denied`, `unauthorized_client`, or `invalid_grant`, and each of those is permanent. `exchange_failed` covers every other failure and answers 502 because the proxy does not know what the zone would have said. | `TestFailuresAreTwoClasses`, `TestAPolicyRefusalIsExchangeDenied`, `TestASourceFailureClassIsItsDenialReason`, `token_exchange.txtar` |
| The credential the zone issued reaches the audit stream or the log. | The record holds the method, the path without its query, and the host. Text on the forward path passes through `credential.Redact`. `/info` and the start-up announcement name the zone, the user, and the mechanism, never the credential or secret. | `TestNoCredentialReachesARecordOrALogLine`, `TestDescribeNamesTheSourceAndNoSecret`, `token_exchange.txtar` |
| The zone's error text reaches the audit stream. | `decision.error` holds the zone's `error_description` as the zone wrote it. The proxy does not redact that field, and a Keycard zone does not put secrets in it. The 64 KiB response limit bounds how much of it can reach one record. Treat the field as text the zone controls when a zone outside Keycard is configured. | `TestTheExchangeRefusesAnUnsafeZone` |

The substitute-user token is unsigned. The proxy can send any user name, and
the zone's policy is the only control that can refuse it. A client secret gives
the zone no ServiceAccount identity to use for that decision.

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

- The proxy mints a credential for each request which is not cached. A busy
  resource receives one exchange per request.
- A rotated client secret takes effect on the next start because the proxy
  reads the file once.
- A zone that accepts a client secret for impersonation permits it based on
  the secret alone. The exchange names no ServiceAccount, so the zone cannot
  limit the exchange to one user. Anything that holds the secret can act for
  any user that the zone permits. Bind the application credential to one user
  in the zone, and treat the secret as equal in power to every credential the
  exchange can mint.
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
