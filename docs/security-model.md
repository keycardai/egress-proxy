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
| A cleartext `http://` request carries a placeholder to a destination in cleartext. | The proxy forwards nothing cleartext. A cleartext request is rejected with `cleartext_not_forwarded`, and an endpoint that covers the host on that port does not make it reachable. | `TestCleartextAndNonProxyRequests`, `TestRedirectedConnectionsAreRefused` |

### Netsetup ruleset

The `egress-netsetup` init container programs an iptables ruleset in the
pod's network namespace. The nat chain redirects the workload's outbound TCP
on the capture ports to the sidecar's transparent listener. The filter
chain's terminal DROP refuses every port outside the capture and redirect.
`internal/netsetup` builds and applies the rules. `cmd/egress-netsetup`
verifies them, drops CAP_NET_ADMIN and writes the receipt.

The pod contract requires the init container to hold NET_ADMIN, NET_RAW, and
SETPCAP and to run before every other container. The sidecar runs as the
proxy uid with NET_BIND_SERVICE. The pod sets
`net.ipv4.ip_unprivileged_port_start` above the redirect port, normally 1024.
The workload holds no capability and runs as another uid. The receipt is on
an emptyDir with medium Memory that the workload does not mount.
The pod sets `hostNetwork: false`, so every container is in the pod's own
network namespace. The sidecar's namespace check does not detect
`hostNetwork: true`. Both containers are then in the node's network
namespace, and the identities match.

`--redirect-port-protection` defaults to `required`. Program and verify runs
then read `net.ipv4.ip_unprivileged_port_start` from `--port-start-file` and
refuse a redirect port at or above it. A file that is missing or does not
hold a port number fails the run. gVisor netstack release `20260921.0` does
not enforce privileged ports and does not expose this sysctl
([google/gvisor#14972](https://github.com/google/gvisor/pull/14972)).

`allow-unprotected` skips the check. The run prints a warning and the
receipt records the mode in `redirect_port_protection`. The rules, their
verification and the capability drop are unchanged. A workload can then bind
the redirect port while the sidecar starts or restarts, and receive captured
traffic that the proxy never sees. The workload's own traffic still goes
through the ruleset. A receipt without `redirect_port_protection` says
nothing about whether the port was checked.

| Threat | Mitigation | Test |
|---|---|---|
| A workload calls `setuid` to the proxy uid. The nat chain returns early for that uid and the filter chain accepts it, so the workload's own traffic would be neither redirected nor dropped. This bypass is published against Istio (https://pulsesecurity.co.nz/advisories/istio-egress-bypass), and Istio states the same limit (https://istio.io/latest/docs/ops/best-practices/security/#understand-traffic-capture-limitations). | Traffic capture is not a boundary on its own. The workload securityContext is: run as a uid that is not the proxy's, `allowPrivilegeEscalation` false, `capabilities.drop` ALL. Without CAP_SETUID the call fails, and `no_new_privs` keeps an execve from granting it. The ruleset excludes the proxy uid and no other. The proxy uid may not be 0, which would exempt every root process in the pod. | `TestProgramRules`, `TestValidate` |
| A workload binds the redirect port before the sidecar starts or while it restarts. | The workload holds no NET_BIND_SERVICE. Before it programs or verifies the rules, netsetup refuses a redirect port at or above `net.ipv4.ip_unprivileged_port_start`, and fails when it cannot read that value. `allow-unprotected` skips this check and the receipt records it. | `TestCheckRedirectPort`, `TestPortCheckPrecedesTableAccess`, `netsetup_ruleset.txtar` |
| A workload leaves over UDP: QUIC or HTTP/3 on port 443, or any other datagram protocol. The redirect covers TCP alone. | The filter chain's terminal DROP covers every protocol. The only accepts above it are the replies conntrack knows, loopback, the proxy's own uid, DNS to the named resolvers, and the ICMPv6 Neighbour Discovery the kernel sends. | `TestProgramRules`, `TestTheTerminalDropIsLast`, `netsetup_ruleset.txtar` |
| A process with CAP_NET_RAW sends ICMPv6 of a neighbour discovery type, with any payload, to any IPv6 address. The ip6tables filter chain must accept neighbour discovery, because the kernel needs it to reach any IPv6 neighbour. | The ICMPv6 accepts match only packets from the kernel's own sockets: `-m owner ! --uid-owner 0-4294967294`. xt_owner matches a process's socket by its uid, and a kernel socket only when every uid condition is negated (linux `net/netfilter/xt_owner.c`, `owner_mt`). No process can send ICMPv6 past the DROP, whatever its uid. | `TestProgramRules`, `netsetup_ruleset.txtar` |
| A workload leaves over IPv6, on a kernel whose ip6tables rules were never programmed. | Both address families are programmed. `--ipv6 auto` follows the kernel, `--ipv6 on` requires IPv6, and `--ipv6 off` programs an ip6tables ruleset that drops every IPv6 packet the pod sends. A probe that cannot tell whether the kernel has IPv6 fails the run. | `TestProgramRules`, `TestIPv6Modes`, `TestKernelHasIPv6`, `netsetup_ruleset.txtar` |
| A rule another component put in OUTPUT decides the packet ahead of the ruleset, or a rule is added to a chain this package owns. | Each OUTPUT jump is inserted at position 1. After applying, the init container reads every rule back with `-C`, counts each chain it owns and checks that the first rule in each OUTPUT chain is exactly the jump. The nat chain must end with the REDIRECT and then an unconditional RETURN, so every exemption comes before the REDIRECT. The IPv6 deny nat chain holds only the RETURN. An extra rule, a misplaced jump or a reordered nat rule fails verification. | `TestApply`, `TestVerifyProblems`, `netsetup_ruleset.txtar` |
| The process that programmed the rules changes them after it verified them. | The init container drops CAP_NET_ADMIN from the permitted, effective and inheritable sets and the bounding set of the thread that programmed the rules, sets `no_new_privs`, reads all of them back, and exits once it has written the receipt. The receipt records whether the drop happened. See the known limit on the drop's scope. | `TestKeepNetAdminIsRecorded`, `netsetup_ruleset.txtar` |
| A rule the init container could not apply leaves the pod half governed, and an earlier run's receipt says it is contained. | Each family's ruleset goes in with one `iptables-restore --noflush` run. The kernel replaces each table in one operation at its `COMMIT` line, so a table that fails to load keeps the rules it held. The filter table commits before the nat table, so a nat table that fails leaves captured TCP dropped. A run that programs the rules unlinks the receipt before it reads its configuration, so any failure leaves none. | `TestApply`, `TestRestoreInsertsOnlyTheJumpsItIsGiven`, `TestAFailedRunLeavesNoReceipt`, `TestRemoveReceiptLeavesNothingBehind`, `netsetup_ruleset.txtar` |
| A `--verify` run writes a receipt for rules it did not program, or replaces a receipt that says CAP_NET_ADMIN was kept. | `--verify` reads the tables back and writes nothing. It never writes or removes the receipt and never drops a capability. | `TestVerifyWritesNothing` |
| Re-running the init container replaces the filter chain while the OUTPUT jump an earlier run installed still points at it. An empty chain under that jump lets the OUTPUT policy, ACCEPT in a pod, allow every protocol and port. | The flush and the refill are one table replacement in one `iptables-restore` run. Apply makes no other write. The chain holds its old rules or its new ones and is never empty under a live jump. | `TestApply`, `netsetup_ruleset.txtar` |
| The init container talks to the nft backend, whose rules the sandbox runtimes this proxy targets never apply. | The backend of the iptables binary and of the restore binary beside it is read from each version string, not from the name, and a version that names no backend is refused. With no override the legacy-specific name is tried before the generic one. | `TestOpenAssertsTheLegacyBackend`, `TestOpenSearchesPathForTheLegacyName` |

### Transparent frontend

The netsetup ruleset sends the workload's outbound TCP to
`listen.transparent_port` on loopback, with no proxy variable set. `internal/transparent`
accepts those connections, and the proxy sends each through the same decision
pipeline as a CONNECT tunnel.

The pod must set `net.ipv4.ip_unprivileged_port_start` to `1024` in
`securityContext.sysctls`. The sidecar drops every capability and adds
NET_BIND_SERVICE, which keeps that capability in its bounding set. Its binary
has the file capability `cap_net_bind_service=+ep`, so the kernel grants it
only when the bounding set allows it. An execve fails with EPERM when the set
lacks it (capabilities(7), the transformation of capabilities during
execve). The binary must be the sidecar's entrypoint. With
`allowPrivilegeEscalation: false`, `no_new_privs` keeps only capabilities the
caller held in its permitted set (Linux `security/commoncap.c`,
`cap_bprm_creds_from_file`). The runtime puts added capabilities in that set
when it execs the entrypoint (containerd `oci/spec_opts.go`,
`WithAddedCapabilities`). A shell between the runtime and the binary has no
capability to pass on.

| Threat | Mitigation | Test |
|---|---|---|
| A workload binds the redirect port during a sidecar restart and decides its own traffic. | The redirect target is port 1015. A process without CAP_NET_BIND_SERVICE can bind it only when `net.ipv4.ip_unprivileged_port_start` is at or below 1015, in either address family (Linux `net/ipv6/af_inet6.c`, `__inet6_bind`). The sidecar reads the sysctl and refuses to start in that case. containerd 2.0 and later, and Docker, set it to 0 unless the pod sets it. The pod sets it to 1024. Kubernetes lists it as a safe sysctl (https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/). | `TestContainment`, `TestContainmentReadsThisProcess`, `TestUnprivilegedPortStart`, `transparent_capture.txtar` (`bind EACCES`) |
| The proxy cannot bind the redirect port, so it cannot serve captured connections. | The filter chain drops traffic the listener does not receive. The proxy binds the port with CAP_NET_BIND_SERVICE from a file capability. A bind that fails with EACCES names the capability the sidecar needs and requires the binary to be its entrypoint. | `transparent_capture.txtar` (the `no_new_privs` refusal) |
| The sidecar starts with rules that were not applied, target another uid or port, or remain changeable by this process. | The sidecar reads the netsetup receipt at start-up. It refuses an unverified receipt, a receipt that says the capability was kept, a mismatched proxy uid or redirect port, uid 0, a receipt with no family, or a process that holds CAP_NET_ADMIN in its effective or permitted set. | `TestContainment`, `TestContainmentReadsThisProcess`, `TestCapture`, `transparent_capture.txtar` (the refusal naming uid 1000) |
| Another container replaces the receipt on the shared volume, so the sidecar starts with data the init container did not write. | The sidecar refuses a receipt that group or other can write, or a receipt or directory owned by a uid other than root or its own. An emptyDir mount point is 0777 (Kubernetes `pkg/volume/emptydir/empty_dir.go`, `perm`), so any uid that mounts it can create a file there. The owner check refuses that file. The sidecar opens the receipt once without following a symlink or blocking, so its mode, owner, and contents come from one descriptor. | `TestContainment`, `TestReadReceiptRefusals`, `transparent_capture.txtar` (the receipt on a 0777 volume) |
| The sidecar starts on a receipt written in another network namespace. The rules it describes govern that namespace, not the one the sidecar and the workload share. | The init container records the device and inode of `/proc/self/ns/net` in the receipt. Two processes are in the same network namespace when both values are equal (namespaces(7), The /proc/[pid]/ns/ directory). The sidecar reads its own and refuses a receipt that names another namespace or none. The check does not detect `hostNetwork: true`. See the netsetup pod contract. | `TestContainment`, `TestContainmentReadsThisProcess`, `TestNetNamespaceAt`, `TestKeepNetAdminIsRecorded`, `TestCapture`, `transparent_capture.txtar` (the proxy in a second container) |
| Another pod connects to the transparent listener, or a DNAT rule in the pod sends outside traffic to it. SO_ORIGINAL_DST then returns the pre-DNAT address, so the connection looks redirected and would be served with this sandbox's credentials. | The listener binds 127.0.0.1 and ::1 and no other address. REDIRECT sends a locally generated packet to loopback (Linux `net/netfilter/nf_nat_redirect.c`, gVisor `pkg/tcpip/stack/iptables_targets.go`), so every captured connection still arrives. The kernel drops an IPv4 packet to 127.0.0.0/8 that arrives on another interface unless `route_localnet` is set (Linux `Documentation/networking/ip-sysctl.rst`), and drops an IPv6 packet to ::1 (Linux `net/ipv6/ip6_input.c`, `ip6_rcv_core`, RFC 4291 section 2.5.3). | `TestListen`, `transparent_capture.txtar` (the connection from the upstream container, the DNAT to 127.0.0.1) |
| A workload connects straight to the transparent listener instead of being redirected, so the recovered destination is the proxy itself. | The frontend compares the recovered destination with the address it accepted on. It denies a match with `not_redirected` before reading from the connection. | `TestTheFrontendRecoversWhatAConnectionWasOpenedTo`, `TestRedirectedConnectionsAreRefused`, `transparent_capture.txtar` (the workload's connection to 127.0.0.1) |
| A redirected TLS connection has no server name, so the proxy cannot evaluate a host policy. A direct connection to an address has no server name because RFC 6066 section 3 forbids an IP literal in `server_name`. | The connection is denied with `no_sni` and closed. The refusal records the pre-redirect address, so the audit record shows its destination. | `TestTheFrontendRecoversWhatAConnectionWasOpenedTo`, `TestRedirectedConnectionsAreRefused`, `transparent_capture.txtar` |
| A redirected connection names a destination that differs from its original address, so the proxy decides one host and reaches another. | The name must carry the original port. An address literal must match the original address. A mismatch gets `host_mismatch`. The proxy resolves the name again before dialing, so the dial guard still catches a permitted name that resolves into a denied range. | `TestTheFrontendRecoversWhatAConnectionWasOpenedTo` |
| A client sends nothing or a partial ClientHello and holds a goroutine and connection slot. | The peek has a ten-second read deadline. The connection then gets `no_sni`, or `cleartext_not_forwarded` on a cleartext port. The transparent listener has required connection and idle limits. The peek waits for one byte beyond the data it has served, then hands over all data it received. | `TestTheFrontendRecoversWhatAConnectionWasOpenedTo` (silent and partial clients), `TestTheConnectionCapHoldsUntilAConnectionCloses`, `TestNewRefusals`, `TestCapturedConnectionsAreServedOneAfterAnother` |
| A captured cleartext connection sends a credential to a destination in cleartext. | Endpoints name HTTPS destinations. The frontend reads the `Host` header on a cleartext port, then denies the connection with `cleartext_not_forwarded`. A deny-listed host gets `deny_always`, and an uncovered host gets `no_matching_endpoint`. The proxy forwards no cleartext, even to a covered host and port. | `TestRedirectedConnectionsAreRefused` (a cleartext connection to a covered name and port), `transparent_capture.txtar` (the `http://` request) |

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
impersonates `identity.impersonate.user`. The proxy authenticates with exactly
one of `identity.workload_token_file` and `identity.client_secret_file`.

| Threat | Mitigation | Test |
|---|---|---|
| The proxy names a user it cannot act for. The substitute-user token is unsigned, so the proxy can put any user ID on the wire. | The zone gets authority from client authentication, not from the subject token. Workload identity sends a projected token signed by the API server. The zone reads the ServiceAccount from it, and its policy allows that ServiceAccount to impersonate one user. The API server signs the token, so the pod cannot forge one for another ServiceAccount. The cluster lane covers that signature; `test/fakeas` verifies none. The zone refuses another user with OAuth code `access_denied`. The proxy maps it to `exchange_denied` and returns 403. | `TestFailuresAreTwoClasses/the_ServiceAccount_is_not_the_one_the_impersonated_user_is_named_after`, `TestASourceFailureClassIsItsDenialReason`, `workload_identity_exchange.txtar` |
| The kubelet rotates the projected token and the proxy keeps offering the expired one. | The token file is read again for every exchange. The kubelet rewrites the projected token once it passes 80% of its lifetime, which defaults to one hour, and does not restart the pod. It writes the new token to a timestamped directory and renames the `..data` symlink onto it, so a read never sees a partial write ([`AtomicWriter.Write`](https://github.com/kubernetes/kubernetes/blob/v1.34.5/pkg/volume/util/atomic_writer.go#L86-L140)). A writer that rewrites the path in place instead would make an exchange fail with `exchange_failed` until the write completes. A rotated client secret takes effect after the next start because the proxy reads it once. | `TestTheWorkloadTokenIsReadOnEveryExchange` |
| The token path is a FIFO or another non-regular file, and a read of it never returns. The proxy stops before it binds a listener, or an exchange outlives its budget, because the file read takes no context. | The proxy stats the path at start-up and refuses anything that is not a regular file no larger than 64 KiB. | `TestCheckTokenFileRefusals`, `TestNewRefusals/a_workload_token_file_that_is_not_a_regular_file` |
| The projected token becomes unreadable while the process runs. | Any failure to read the file denies. The proxy sends no exchange request without client authentication. | `TestFailuresAreTwoClasses/the_kubelet_removed_the_projected_token`, `TestFailuresAreTwoClasses/the_projected_token_is_empty`, `TestFailuresAreTwoClasses/the_projected_token_holds_only_whitespace` |
| The workload reads the projected ServiceAccount token or the client secret and mints credentials for itself, bypassing the endpoint list. | The proxy reads each file at the configured path and writes it nowhere else. Neither reaches a log line, an audit record, or an `/info` answer. The secret reaches no form parameter either, because the proxy sends it in HTTP basic credentials. Both paths must name a regular file: a client secret file no larger than a megabyte, a token file no larger than 64 KiB. A client secret file must in addition be readable by its owner alone. The pod controls whether the workload can read either path. This repository does not define that pod contract. | `TestReadSecretFileRefusals`, `TestCheckTokenFileRefusals`, `TestDescribeNamesTheSourceAndNoSecret`, `TestTheWireForm`, `token_exchange.txtar`, `workload_identity_exchange.txtar` |
| `identity.zone_url` resolves into the cluster or onto the metadata address, so the client authentication is offered to something that is not the zone. | The exchange uses the platform deny list for the zone connection. It refuses a resolved address on that list before it opens a socket. | `TestADeniedZoneAddressIsNotDialed` |
| A server that is not the zone answers discovery, takes the client authentication, and issues credentials the proxy writes into requests. | The exchange verifies the zone with the system roots and `tls.upstream_ca_files`. It requires TLS 1.2 or later and uses no proxy. RFC 8414 section 3.3 requires the metadata to name the configured zone as its issuer. A mismatch fails the exchange before the proxy posts a secret. | `TestTheZoneIssuerMustMatchTheConfiguredZone` |
| Metadata that names the configured zone as its issuer points `token_endpoint` at another host or at cleartext, so the client secret goes somewhere else. RFC 8414 section 3.3 binds the issuer and says nothing about `token_endpoint`. | Every request the exchange makes must be https, discovery and the token request alike. A cleartext endpoint reaches no socket. The exchange also refuses to follow a redirect, so a 307 from the token endpoint cannot move the secret to another host or to another port on the same host. | `TestTheTokenEndpointMustBeHTTPS`, `TestTheExchangeRefusesAnUnsafeZone/the_token_endpoint_redirects` |
| A zone streams a large body inside the exchange budget, which spends the sidecar's memory. | The exchange reads at most 1 MiB from the zone and fails the exchange past that. | `TestTheExchangeRefusesAnUnsafeZone/the_token_response_is_larger_than_the_limit` |
| A request the endpoint list already denies still spends an exchange, so the zone sees traffic the policy refused. | The exchange runs only after the request decision allows and the endpoint names a credential. A denied request reaches no zone. | `TestTheSourceReachesTheZoneOnlyOnCredential`, `token_exchange.txtar` |
| A zone that accepts the connection and then goes quiet holds the request and its slot against `limits.max_connections` indefinitely. | `limits.exchange_timeout` bounds one exchange, including discovery. The dial and TLS handshake to the zone each have five seconds inside this budget. A request that spends the budget is denied with `exchange_failed`. | `TestFailuresAreTwoClasses/the_zone_accepts_the_request_and_never_answers` |
| A refusal by the zone's policy is indistinguishable from a zone that could not be reached, so an operator cannot tell a misconfigured policy from an outage, and an agent retries what will never succeed. | The proxy uses separate reason codes. `exchange_denied` means that the zone read its policy and refused, and it answers 403. The zone says so with `access_denied`, `unauthorized_client`, or `invalid_grant`, and each of those is permanent. `exchange_failed` covers every other failure and answers 502 because the proxy does not know what the zone would have said. | `TestFailuresAreTwoClasses`, `TestAPolicyRefusalIsExchangeDenied`, `TestASourceFailureClassIsItsDenialReason`, `token_exchange.txtar` |
| The credential the zone issued reaches the audit stream or the log. | The record holds the method, the path without its query, and the host. Text on the forward path passes through `credential.Redact`. `/info` and the start-up announcement name the zone, the user, and the mechanism, never the credential or secret. | `TestNoCredentialReachesARecordOrALogLine`, `TestDescribeNamesTheSourceAndNoSecret`, `token_exchange.txtar` |
| The zone's error text reaches the audit stream. | `decision.error` holds the zone's `error_description` as the zone wrote it. The proxy does not redact that field, and a Keycard zone does not put secrets in it. The 1 MiB response limit bounds how much of it can reach one record. Treat the field as text the zone controls when a zone outside Keycard is configured. | `TestTheExchangeRefusesAnUnsafeZone` |

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

- Traffic capture is not a security boundary. A workload that can reach the
  proxy uid escapes the redirect and the filter exclusion together. The
  workload securityContext closes that. See the netsetup ruleset surface.
- DNS is an open channel out. The filter chain accepts UDP and TCP port 53 to
  every resolver in `/etc/resolv.conf`, unconditionally and unread. A workload
  can encode data in query names and read data back out of the answers. That
  traffic reaches no endpoint rule and no audit record.
- `ESTABLISHED` in OUTPUT is an open channel to any peer that opens a
  connection into the pod. It is the first accept in the filter chain of both
  families. An outbound flow reaches ESTABLISHED only after its own first
  packet was accepted, so it widens nothing the workload initiates. INPUT is
  untouched and its policy is ACCEPT, so a peer that connects into the pod
  creates a conntrack entry. The workload then has an unrestricted two-way
  channel to that peer on that tuple, over TCP or UDP. A NetworkPolicy on
  ingress closes it.
- The pod sends no ICMP error about inbound traffic. The filter chain accepts
  `ESTABLISHED` and not `RELATED`, and an ICMP error is `RELATED`. A peer
  sending UDP to a closed port in the pod gets no port unreachable and waits
  for its own timeout.
- The init container drops CAP_NET_ADMIN on one thread. `capset`,
  `PR_CAPBSET_DROP` and `PR_SET_NO_NEW_PRIVS` each act on the calling thread
  (capabilities(7), prctl(2)). The other threads the Go runtime started keep
  the capability in their permitted and bounding sets. The process runs no
  code of its own on them and exits once it has written the receipt.
- The connection cap is per frontend. `limits.max_connections` bounds the
  CONNECT and transparent frontends separately, so a process configured for
  1024 can hold 2048. The transparent frontend takes a slot after accept, so
  each socket also holds one unread connection at the limit.
- The pod does not meet the baseline Pod Security Standard. The netsetup
  init container adds NET_ADMIN and NET_RAW, which baseline does not allow
  (https://kubernetes.io/docs/concepts/security/pod-security-standards/).
  The namespace needs the privileged level or an exemption for this pod.
- The transparent frontend forwards no cleartext. It reads `Host` on a
  cleartext port and then refuses the connection because every endpoint names
  an HTTPS destination.
- The proxy checks the netsetup receipt once at start-up. It cannot detect a
  later rule change, so the init container gives up CAP_NET_ADMIN before it
  writes the receipt and the sidecar refuses to start with that capability.
- The proxy mints a credential for each request which is not cached. A busy
  resource receives one exchange per request.
- A rotated client secret takes effect on the next start because the proxy
  reads the file once. A rotated workload token takes effect on the next
  exchange.
- A zone that accepts a client secret for impersonation permits it based on
  the secret alone. The exchange names no ServiceAccount, so the zone cannot
  limit it to one user as it can with workload identity. Anyone who holds the
  secret can act for any user that the zone permits. Bind the application
  credential to one user in the zone, and treat the secret as equal in power
  to every credential the exchange can mint. Use workload identity in a
  cluster.
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
