# Security model

This document lists the proxy enforcement surfaces, the threats against them,
their mitigations, and the tests for those mitigations. Add each surface when
the change that ships it is merged. Before a public release, read this document
against the code for every shipped surface. Do not tag a public release until
this document covers every shipped surface and the code review is complete.

`docs/configuration.md` defines the settings that this document names.
`docs/containers.md` states what the containers this repository ships need.

## Security posture

The proxy runs as a sidecar. It terminates the workload TLS with an authority
that it mints, evaluates every connection and request against a configured
endpoint list, and writes one audit record for each decision.

The proxy may share a network namespace with the workload that it governs in
some configurations, with network interception configured within that namespace.
The security claim is that every route out terminates at the proxy for an
unprivileged workload.

## Outside the threat model

The proxy controls which requests leave the pod and which credential each
request gets. It does not control what an upstream sends back.

- The proxy streams every upstream response to the workload unchanged. If
  the upstream echoes the injected credential in a header, a body, or a
  redirect `Location`, the workload reads it. The workload can then use the
  credential without the proxy, outside the endpoint policy. A credential
  can be encoded in a response in too many ways to filter reliably, so the
  proxy does not inspect responses for it.
- Do not attach a credential to an endpoint whose upstream reflects request
  headers or query parameters, such as a request-echo service. Prefer a
  credential from the token exchange over a static one, because the zone
  sets how long an exchanged token lasts.

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
- The sidecar answers the sandbox's name lookups. It refuses every name
  that is not an endpoint host or the zone host, over UDP and over TCP. A
  refused name answers `NXDOMAIN` and does not reach the cluster resolver.
  For an allowed name, the resolver builds a new message from the
  canonical name, the type and the class. The query type is the only value
  the workload chooses that reaches the authoritative server, and the
  audit record includes it.
- The audit stream cannot be turned off. It is the process stdout, with one
  JSON object per decision and the `sandbox_id` and document digest. A name
  lookup is a decision: it gets a record with scope `dns`, the question and
  the response code.

## What the e2e tests prove

`make e2e` runs the request path in a k3d cluster with the images this
repository ships. The init container installs the capture rules and the
proxy runs as a sidecar. The agent container sends requests with no proxy
variable set, so requests reach the proxy only through the capture. The
tests add no mitigation. They check that the mitigations below work
together in a pod. Table rows they cover list `TestRequestPath`.

The zone and the upstream have cluster addresses. These are RFC 1918
addresses, which the platform deny list blocks, so the sandbox document
lists the pod and service ranges in `policy.deny_list_exceptions`. The tests
check that the proxy reports these exceptions in its start-up log and in
`probe info`.

The sidecar runs as uid 1337 with `drop: ["ALL"]` and
`add: ["NET_BIND_SERVICE"]`, as `docs/containers.md` describes. The
workload runs as uid 1000, so the capture rules can tell the two apart.
The proxy binds the redirect port below 1024. This shows that the file
capability and the pod grant work together.

## Surfaces and threats

### CONNECT listener

The workload reaches this frontend through `HTTPS_PROXY`.

| Threat | Mitigation | Test |
|---|---|---|
| A workload crashes the sidecar with a malformed request. goproxy v1.9.1 dereferences a nil URL on an asterisk-form target inside a tunnel when `Host` has a port. The library starts the handler in its own goroutine, so recovery outside that goroutine cannot catch the panic. | The loop inside the tunnel belongs to net/http, which recovers once per connection. `OPTIONS *` reaches the handler and is rejected with `malformed_request`. The TLS handshake runs in a proxy-owned goroutine that recovers. goproxy handles only the CONNECT line. | `TestCrashersAreRefusedAndTheProcessKeepsServing`, `TestACleartextPrefaceInATunnelClosesIt` |
| A workload opens connections until the sidecar runs out of file descriptors. | `limits.max_connections` caps simultaneous connections on the listener. Further accepts wait until a connection ends. | `TestConnectionCap` |
| A workload holds the connection cap by opening tunnels and then stalling the TLS handshake. | The handshake inside a tunnel has a ten-second budget. A handshake that spends it is closed, and the proxy logs it at warning level with the connection id and the authority, so the operator can see a client that holds slots this way. | `TestHandshakeFailureLogging`, `TestConnectionCap` |
| A workload holds slow or silent connections open. | `limits.idle_timeout` closes a connection that neither reads nor writes on the frontend and inside a tunnel. The proxy limits a request head to 10 seconds and a TLS handshake to 10 seconds. | `TestIdleConnectionsAreClosed`, `TestActiveStreamOutlivesIdleTimeout` |
| A workload keeps egress open after the sidecar is told to stop, by upgrading a tunnelled request to another protocol. `http.Server.Close` does not reach a connection the reverse proxy hijacked for the upgrade. | The drain is bounded by the shutdown grace. Every request still open when it ends is cancelled, which closes the upgraded connection and its upstream leg. `Run` waits for the handler, bounded by five seconds, so the request's record lands before the process exits unless the handler or the audit sink stalls past the bound, and the record reports the 101 rather than an informational status sent before it. | `TestShutdownDrainsInFlightRequest`, `TestShutdownEndsAnUpgradedConnection`, `TestAnUpgradedRequestIsAuditedBeforeRunReturns` |
| A workload pins the connection cap with requests to an upstream that never answers. The idle limit does not apply while a request waits on an upstream. | Four budgets bound an upstream that goes quiet: the dial, the TLS handshake, `limits.response_header_timeout` for the response head, and `limits.idle_timeout` on the upstream connection for a body that stops arriving. A request that exceeds one is rejected with `upstream_failed`, which frees the frontend connection. No budget bounds a whole request, because a server-sent event stream is a long request that is working. | `TestAStalledUpstreamIsBoundedByTheResponseHeaderTimeout`, `TestResponsesStream` |
| An origin-form request reaches the listener and probes for a service that the proxy does not provide. | The listener provides no service of its own. It rejects the request with `not_a_proxy_request` and writes an audit record. The admin socket provides health and information endpoints. | `TestCleartextAndNonProxyRequests` |
| A cleartext `http://` request sends a placeholder to a destination in cleartext. | The proxy forwards nothing cleartext. A cleartext request is rejected with `cleartext_not_forwarded`, and an endpoint that covers the host on that port does not make it reachable. | `TestCleartextAndNonProxyRequests`, `TestRedirectedConnectionsAreRefused` |

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
The sandbox chart composes the pod, and its lint refuses a manifest that
departs from this contract.
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
| A workload leaves over UDP: QUIC or HTTP/3 on port 443, or any other datagram protocol. The redirect covers TCP alone. | The filter chain's terminal DROP covers every protocol. The only accepts above it are the replies on connections opened into the pod, the packets on established flows that no process socket sends, loopback, the proxy's own uid, and the ICMPv6 Neighbour Discovery the kernel sends. There is no accept for DNS to a resolver: the nat chain redirects every query to the sidecar's resolver on loopback. | `TestProgramRules`, `TestTheTerminalDropIsLast`, `netsetup_ruleset.txtar` |
| A workload sends from a source port the proxy uid just used, to the same peer. Conntrack keys a flow on its addresses, ports and protocol, not on the socket, so the packet joins the proxy's flow. The nat table is consulted only for a packet that creates a new connection (iptables(8)), so the redirect does not run. A UDP entry lasts 30 seconds after its last packet (`nf_conntrack_udp_timeout`), and a DNS query sent this way would reach the cluster resolver unread and unrecorded. | The ESTABLISHED accept matches the reply direction only (`--ctdir REPLY`). A packet the pod sends in the original direction of a flow must pass the loopback or proxy uid accept, so the workload's packet reaches the DROP. A second ESTABLISHED accept matches only packets from no process socket: `-m owner ! --uid-owner 0-4294967294`. These are the unsent data and retransmits of a TCP socket its process has closed (linux `include/net/sock.h`, `sock_orphan`) and the kernel's answers for a TIME_WAIT socket. Without it an upstream the proxy closed first waits in LAST_ACK. | `TestProgramRules`, `TestVerifyProblems`, `netsetup_ruleset.txtar` (the datagram from port 40053, `lastack`) |
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
| A workload binds the redirect port during a sidecar restart and decides its own traffic. | The redirect target is port 1015. A process without CAP_NET_BIND_SERVICE can bind it only when `net.ipv4.ip_unprivileged_port_start` is at or below 1015, in either address family (Linux `net/ipv6/af_inet6.c`, `__inet6_bind`). The sidecar reads the sysctl and refuses to start in that case. It skips this check when the receipt records `allow-unprotected`. containerd 2.0 and later, and Docker, set it to 0 unless the pod sets it. The pod sets it to 1024. Kubernetes lists it as a safe sysctl (https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/). | `TestContainmentPortStart`, `TestContainmentReadsThisProcess`, `TestUnprivilegedPortStart`, `transparent_capture.txtar` (`bind EACCES`, the allow-unprotected pod) |
| The proxy cannot bind the redirect port, so it cannot serve captured connections. | The filter chain drops traffic the listener does not receive. The proxy binds the port with CAP_NET_BIND_SERVICE from a file capability. A bind that fails with EACCES names the capability the sidecar needs and requires the binary to be its entrypoint. | `transparent_capture.txtar` (the `no_new_privs` refusal), `TestProxyImageBindsAPrivilegedPort` |
| The sidecar starts with rules that were not applied, target another uid or port, or remain changeable by this process. | The sidecar reads the netsetup receipt at start-up. It refuses an unverified receipt, a receipt that says the capability was kept, a mismatched proxy uid, redirect port or DNS port, uid 0, a receipt with no family, or a process that holds CAP_NET_ADMIN in its effective or permitted set. | `TestContainment`, `TestContainmentReadsThisProcess`, `TestCapture`, `transparent_capture.txtar` (the refusal naming uid 1000) |
| Another container replaces the receipt on the shared volume, so the sidecar starts with data the init container did not write. | The sidecar refuses a receipt that group or other can write, or a receipt or directory owned by a uid other than root or its own. An emptyDir mount point is 0777 (Kubernetes `pkg/volume/emptydir/empty_dir.go`, `perm`), so any uid that mounts it can create a file there. The owner check refuses that file. The sidecar opens the receipt once without following a symlink or blocking, so its mode, owner, and contents come from one descriptor. | `TestContainment`, `TestReadReceiptRefusals`, `transparent_capture.txtar` (the receipt on a 0777 volume) |
| The sidecar starts on a receipt written in another network namespace. The rules it describes govern that namespace, not the one the sidecar and the workload share. | The init container records the device and inode of `/proc/self/ns/net` in the receipt. Two processes are in the same network namespace when both values are equal (namespaces(7), The /proc/[pid]/ns/ directory). The sidecar reads its own and refuses a receipt that names another namespace or none. The check does not detect `hostNetwork: true`. See the netsetup pod contract. | `TestContainment`, `TestContainmentReadsThisProcess`, `TestNetNamespaceAt`, `TestKeepNetAdminIsRecorded`, `TestCapture`, `transparent_capture.txtar` (the proxy in a second container) |
| Another pod connects to the transparent listener, or a DNAT rule in the pod sends outside traffic to it. SO_ORIGINAL_DST then returns the pre-DNAT address, so the connection looks redirected and would be served with this sandbox's credentials. | The listener binds 127.0.0.1 and ::1 and no other address. REDIRECT sends a locally generated packet to loopback (Linux `net/netfilter/nf_nat_redirect.c`, gVisor `pkg/tcpip/stack/iptables_targets.go`), so every captured connection still arrives. The kernel drops an IPv4 packet to 127.0.0.0/8 that arrives on another interface unless `route_localnet` is set (Linux `Documentation/networking/ip-sysctl.rst`), and drops an IPv6 packet to ::1 (Linux `net/ipv6/ip6_input.c`, `ip6_rcv_core`, RFC 4291 section 2.5.3). | `TestListen`, `transparent_capture.txtar` (the connection from the upstream container, the DNAT to 127.0.0.1) |
| A workload connects straight to the transparent listener instead of being redirected, so the recovered destination is the proxy itself. | The frontend compares the recovered destination with the address it accepted on. It denies a match with `not_redirected` before reading from the connection. | `TestTheFrontendRecoversWhatAConnectionWasOpenedTo`, `TestRedirectedConnectionsAreRefused`, `transparent_capture.txtar` (the workload's connection to 127.0.0.1) |
| A redirected TLS connection has no server name, so the proxy cannot evaluate a host policy. A direct connection to an address has no server name because RFC 6066 section 3 forbids an IP literal in `server_name`. | The connection is denied with `no_sni` and closed. The refusal records the pre-redirect address, so the audit record shows its destination. | `TestTheFrontendRecoversWhatAConnectionWasOpenedTo`, `TestRedirectedConnectionsAreRefused`, `transparent_capture.txtar` |
| A redirected connection names a destination that differs from its original address, so the proxy decides one host and reaches another. | The name must hold the original port. An address literal must match the original address. A mismatch gets `host_mismatch`. The proxy resolves the name again before dialing, so the dial guard still catches a permitted name that resolves into a denied range. | `TestTheFrontendRecoversWhatAConnectionWasOpenedTo` |
| A client sends nothing or a partial ClientHello and holds a goroutine and connection slot. | The peek has a ten-second read deadline. The connection then gets `no_sni`, or `cleartext_not_forwarded` on a cleartext port. The transparent listener has required connection and idle limits. The peek waits for one byte beyond the data it has served, then hands over all data it received. | `TestTheFrontendRecoversWhatAConnectionWasOpenedTo` (silent and partial clients), `TestTheConnectionCapHoldsUntilAConnectionCloses`, `TestNewRefusals`, `TestCapturedConnectionsAreServedOneAfterAnother` |
| A captured cleartext connection sends a credential to a destination in cleartext. | Endpoints name HTTPS destinations. The frontend reads the `Host` header on a cleartext port, then denies the connection with `cleartext_not_forwarded`. A deny-listed host gets `deny_always`, and an uncovered host gets `no_matching_endpoint`. The proxy forwards no cleartext, even to a covered host and port. | `TestRedirectedConnectionsAreRefused` (a cleartext connection to a covered name and port), `transparent_capture.txtar` (the `http://` request) |

### Name resolution

A DNS query is not a connection, so a destination the endpoint list refuses
still leaves the pod as a query unless the resolver is constrained. A
workload can encode data in query names and read data back out of the
answers.

`internal/dns` answers name lookups on the pod loopback over UDP and TCP.
The netsetup init container redirects UDP and TCP port 53 to it, whatever
resolver the client named. The filter chain does not accept DNS to any
resolver. The resolver answers `NXDOMAIN` for a name outside the allowlist
and forwards the rest to the cluster resolvers the receipt names.

The allowlist is the endpoint hosts plus the zone host, taken from the
document. No setting changes it. The match is exact equality on the whole
name, case-insensitive. The connection decision matches a host the same
way.

| Threat | Mitigation | Test |
|---|---|---|
| A workload encodes data in a query name and reads data back out of the answers, reaching no endpoint rule and no audit record. | A name that is not an endpoint host or the zone host answers `NXDOMAIN`, and the query is not forwarded. Every lookup writes a record with scope `dns` and the reason `no_matching_endpoint`. | `TestTheAllowlistDecidesEveryName`, `dns_allowlist.txtar`, `TestRequestPath` |
| A workload sends the query straight at the cluster resolver, around the loopback listener, or at a resolver outside the pod entirely. | The nat chain redirects UDP and TCP port 53 to the resolver ahead of the pod and service ranges, so a query at any address off the loopback interface is answered by the sidecar. The filter chain accepts DNS to no resolver, so a query the redirect missed reaches the terminal DROP. A query to a loopback address other than the one the resolver binds matches the `-o lo -j RETURN` above the redirect, so it is not rewritten and nothing answers it. | `TestProgramRules`, `dns_allowlist.txtar` |
| A workload encodes data in the parts of an allowed query the allowlist does not read: the name's case bits, the message id and an EDNS0 option. The receiver is the authoritative operator for a name the document declares. | The outbound message is built rather than copied. It holds the canonical name, the query type, the class, a message id of this resolver's own, and an OPT of this resolver's own where the client sent one. The query type is what remains, and the record names it. | `TestNothingTheClientSentReachesTheResolver` |
| A workload asks over TCP, which a resolver that filtered datagrams alone would pass. DNS falls back to TCP for an answer that does not fit in a datagram, RFC 7766 section 5. | Both protocols are redirected and both are served, and the allowlist decides them alike. Every table row runs over each transport, and the record names which one. | `TestTheAllowlistDecidesEveryName`, `dns_allowlist.txtar` |
| A subdomain of an endpoint host resolves, so the workload reaches a zone no endpoint declares. | The match is exact equality on the whole name. `data.upstream.example` is refused where `upstream.example` resolves. | `TestTheAllowlistDecidesEveryName`, `dns_allowlist.txtar` |
| A resolver that times out or errors leaves the query to be answered by something else. | A query no resolver answered gets `SERVFAIL` and an `upstream_failed` record. A message that is not one lookup gets `FORMERR` and a `malformed_request` record. Neither forwards. | `TestAResolverThatDoesNotAnswerDenies`, `TestAMessageThatIsNotAQueryDenies` |
| The redirect sends port 53 to a port that nothing binds, or the resolver binds a port that nothing redirects to. Every lookup fails. | The receipt records the port the rules redirect to, and the proxy refuses to start when it and `listen.dns` disagree, either way round. A sidecar that runs the resolver reads the receipt whether or not it also runs a transparent frontend. | `TestContainment`, `TestTheReceiptIsReadForEverySurfaceTheRulesFeed`, `dns_allowlist.txtar` |
| A workload binds the resolver port during a sidecar restart and answers its own lookups. | The port is 53, below 1024, so only a process holding CAP_NET_BIND_SERVICE can bind it. The proxy reads `net.ipv4.ip_unprivileged_port_start` at start-up rather than trusting the manifest, and refuses to serve unless it is above every port the sidecar binds below 1024. | `TestContainmentPortStart` |
| The resolver is reachable from outside the pod, so another peer reads the sandbox's allowlist by asking it. | The listener binds loopback addresses only. The proxy refuses a `listen.dns` host other than 127.0.0.1, ::1, an unspecified address or an empty host, both when it parses the configuration and when it binds. An empty or unspecified host binds 127.0.0.1 and ::1 and never a wildcard. | `TestListenBindsLoopbackOnly`, `TestListenRefusals`, `TestParseRefusesInvalidSettings`, `dns_allowlist.txtar` |
| A workload holds TCP connections to the resolver until the sidecar runs out of file descriptors. miekg/dns starts a goroutine per connection and holds it for the ten-second idle window, and the descriptors are the ones the frontends and the audit writer need. | `limits.max_dns_connections` caps the connections one resolver listener accepts, separately from `limits.max_connections`. Further accepts wait in the backlog. The resolver refuses to build without a cap. | `TestTheResolverCapsItsTCPConnections`, `TestNewRefusesAnUnusableResolver` |
| A resolver forwards to itself, so every allowed name spends the budget and fails. | The proxy refuses a `dns.forward_to` entry that names its own listen address, and one that is a name rather than an address. | `TestNewRefusesAnUnusableResolver` |

### Decision process

| Threat | Mitigation | Test |
|---|---|---|
| The workload opens a tunnel to an allowed host, then sends requests for another host. A future credential could reach that other host. | The SNI must match the CONNECT authority. The request `Host` must match the SNI and port. A mismatch produces `host_mismatch`. The upstream request uses the SNI. | `TestHandshakeRefusals`, `TestDeniedRequestsInsideAnAllowedTunnel` |
| A path falls outside an endpoint prefix, or dot segments send a request to another upstream path. | The path must be absolute and use its shortest form. If it does not, the proxy returns `malformed_request`. The longest matching prefix decides, and no match returns `no_matching_endpoint`. | `TestMatcherDecisions`, `TestDeniedRequestsInsideAnAllowedTunnel` |
| Escaping hides a path from the decision. The proxy judges one form and the upstream reads another, so `/api/%2e%2e/secret` passes a prefix check and reaches `/api/secret`, or `/a%2Fb` is judged as a child of `/a/` and arrives as one segment. | The decision reads the escaped path, the bytes the upstream receives, so the match and the forwarded request cannot disagree. Both that form and its decoded form must be in shortest form, which refuses escaped dot segments. A prefix must hold only characters a path holds unescaped. | `TestMatcherDecisions`, `TestAnEscapedPathReachesTheUpstreamUnchanged`, `TestDeniedRequestsInsideAnAllowedTunnel`, `connect_allow_deny.txtar` |
| A query that does not parse reaches the upstream shorter than the workload wrote it. `httputil.ReverseProxy` re-encodes an invalid query and drops pairs it cannot read. The upstream then receives a request the workload did not send. | The request decision parses the query and refuses it with `malformed_request`. The credential writer applies the same check, so it never writes to an invalid query. | `TestDeniedRequestsInsideAnAllowedTunnel`, `TestWriterReplacesWhatTheWorkloadSent`, `credential_injection.txtar` |
| DNS points an allowed name at a cluster or metadata address. | The dialer checks every resolved address against the deny list before it opens a socket. A match returns `deny_always` and opens no connection. | `TestANameResolvingIntoADeniedRangeIsRefusedAtTheDial` |
| A document widens the platform list by naming a covered host or excepting the metadata address. | The proxy rejects both cases at start-up. | `TestCompileRefusals`, `TestDenyListRefusesAnExceptionCoveringTheMetadataAddress` |
| An exception opens more of the platform deny list than the operator meant to open, such as `0.0.0.0/1`. | The proxy accepts it. The only range it refuses to except is the cloud metadata address. Each exception is a warning in the start-up log, `/info` lists the set in force, and `config.digest` covers it, so an audit record names the deny list the decision used. | `TestDenyListAddresses`, `TestConfigDigestCoversTheEffectiveSettings`, `connect_allow_deny.txtar` |
| An endpoint names an address in a spelling that is not an IP literal, such as `0177.0.0.1` or `2852039166`, which a resolver still reads as an address. | A host must be a DNS name of ASCII labels whose last label is not all digits. The endpoint list refuses the rest at start-up, and the dial guard refuses the address whatever the name. | `TestParseRefusesInvalidEndpoints`, `TestANameResolvingIntoADeniedRangeIsRefusedAtTheDial` |
| An endpoint names a path prefix that covers more than it means to, such as an empty prefix or one with dot segments. | Compile validates every prefix itself, so a list assembled outside the document parser gets the same refusal. | `TestCompileRefusals` |
| A listed host runs another service on another port, and the workload reaches it because the document named only the host. | An endpoint covers one port, 443 unless it names another. The connection decision matches the CONNECT port against the endpoint list, and a port no endpoint names is refused with `no_matching_endpoint` before any leaf is minted. | `TestDeniedConnections`, `TestMatcherDecisions`, `connect_allow_deny.txtar` |
| The proxy cannot supply the credential for an endpoint. The request reaches the upstream with the value the workload sent at the placement. | The proxy rejects the request with `credential_unavailable` when it has no source, when the source has no credential for the endpoint resource, or when no writer accepts the placement. Nothing is dialed. | `TestCredentialRefusals`, `TestDeniedRequestsInsideAnAllowedTunnel`, `git_basic_auth.txtar` |

### Credential injection

The proxy writes a credential only at the placement that the endpoint names.

| Threat | Mitigation | Test |
|---|---|---|
| A document names a resource on another host, so the credential the zone issues for that host goes to this endpoint. | An endpoint is one URL. The proxy reads the host it connects to and the resource it asks the zone for from that URL, so the resource always names the host the proxy connects to. | `TestParseReadsTheEndpointURL`, `TestParseRefusesInvalidEndpoints` |
| A workload sends its own value at the placement and reaches the upstream with it, or keeps a value the proxy must replace. | The placement wins. A header placement replaces every value under that header name. A query placement replaces every value under that parameter name. A basic placement replaces every value under `Authorization`. | `TestWriterReplacesWhatTheWorkloadSent`, `TestCredentialInjection`, `TestGitOverHTTPS`, `TestRequestPath`, `git_basic_auth.txtar` |
| A workload puts userinfo in a clone URL, so the upstream authenticates the workload's own user rather than the one the document names. | A basic placement writes the user the document names and removes the userinfo from the outbound request line. A clone URL with no userinfo, with a user, or with a user and a password reaches the upstream with the same `Authorization`. | `TestWriterReplacesWhatTheWorkloadSent`, `TestGitOverHTTPS`, `git_basic_auth.txtar` |
| Userinfo in the request line reaches the upstream, or a log line formatted from the outbound URL prints the password in it. | The outbound request line is origin form, which does not include userinfo. The rewrite clears `URL.User` on every outbound request, whatever the endpoint names. A basic placement also clears it at the writer. | `TestRewriteClearsTheUserinfo`, `TestWriterReplacesWhatTheWorkloadSent`, `TestUserinfoInTheRequestLineNeverReachesTheUpstream` |
| A basic placement names a user holding a colon, so the upstream reads a different user and password than the document meant. | `credential.NewWriter` and the document parser both refuse a user with a colon or a control character. RFC 7617 section 2 reads the user name up to the first colon of the decoded pair. | `TestNewWriterRefusals`, config `basic placement whose user holds a colon` |
| A workload names the placement header in `Connection`, so the proxy writes a credential that the reverse proxy then drops as hop-by-hop. | The proxy writes the credential after the reverse proxy removes the headers named by `Connection`. | `TestCredentialInjection` |
| A credential holding a carriage return or newline splits the outbound request head and injects a header. | The proxy refuses a credential with a control character when it loads the source and when the source returns one. It denies the request with `credential_unavailable`. | `TestValidate`, `TestLoadStaticFileRefusals` |
| A header placement names a header that the connection, the proxy, or the upstream trusts, such as `Host`. `net/http` writes `Host` from the request target, so the credential would not reach the wire. | `credential.NewWriter` refuses banned names. The document parser and endpoints built in code get the same refusal. The list includes the hop-by-hop headers in RFC 9110 section 7.6.1, `Content-Length`, `Host`, `Forwarded`, and the `x-forwarded-` and `sec-` families. `Authorization` is allowed. | `TestNewWriterRefusesABannedHeaderName`, `TestNewWriterAcceptsAHeaderName`, config `a header placement naming Host` |
| A header placement names a header that would split the request head. | The writer refuses a name that is not a valid header name, which denies the request. | `TestNewWriterRefusals` |
| The credential writer fails and the request reaches the upstream with whatever the workload sent at the placement. | The rewrite records the failure. The round trip rejects the request before it dials. The request is denied with `credential_unavailable` and nothing is opened. | `TestAFailedCredentialWriteDenies` |
| A credential reaches the audit stream or the log, where it outlives the request. | A record holds the method, the path without its query, and the host. `credential.Redact` processes request error text written by the proxy. It replaces the raw header form, the percent-encoded query form, and the base64 a basic placement writes. The raw credential does not appear in that base64. Raw ReverseProxy diagnostics are disabled because body-read errors can quote upstream response bytes. Incomplete responses still produce an audit record with an outcome error. | `TestRedact`, `TestEmitForwardedRedactsTheCredential`, `TestNoCredentialReachesARecordOrALogLine`, `credential_injection.txtar`, `git_basic_auth.txtar` |
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
| The proxy names a user it cannot act for. The substitute-user token is unsigned, so the proxy can put any user ID on the wire. | The zone gets authority from client authentication, not from the subject token. Workload identity sends a projected token signed by the API server. The zone reads the ServiceAccount from it, and its policy allows that ServiceAccount to impersonate one user. The API server signs the token, so the pod cannot forge one for another ServiceAccount. The zone checks the signature, issuer, audience and expiry of the token. `test/fakeas` checks them against the cluster's service account keys in the e2e tests and against a test key in the unit and acceptance tests. A token the API server did not sign does not authenticate a client. The zone answers `invalid_client`, and the proxy denies with `exchange_failed` and returns 502. The zone refuses another user with OAuth code `access_denied`. The proxy maps it to `exchange_denied` and returns 403. | `TestFailuresAreTwoClasses/the_ServiceAccount_is_not_the_one_the_impersonated_user_is_named_after`, `TestASourceFailureClassIsItsDenialReason`, `workload_identity_exchange.txtar`, `TestClientAssertionVerification`, `TestClientAuthenticationShape`, `TestRequestPath` |
| The kubelet rotates the projected token and the proxy keeps offering the expired one. | The token file is read again for every exchange. The kubelet rewrites the projected token once it passes 80% of its lifetime, which defaults to one hour, and does not restart the pod. It writes the new token to a timestamped directory and renames the `..data` symlink onto it, so a read never sees a partial write ([`AtomicWriter.Write`](https://github.com/kubernetes/kubernetes/blob/v1.34.5/pkg/volume/util/atomic_writer.go#L86-L140)). A writer that rewrites the path in place instead would make an exchange fail with `exchange_failed` until the write completes. A rotated client secret takes effect after the next start because the proxy reads it once. | `TestTheWorkloadTokenIsReadOnEveryExchange` |
| The token path is a FIFO or another non-regular file, and a read of it never returns. The proxy stops before it binds a listener, or an exchange outlives its budget, because the file read takes no context. | The proxy stats the path at start-up and refuses anything that is not a regular file no larger than 64 KiB. | `TestCheckTokenFileRefusals`, `TestNewRefusals/a_workload_token_file_that_is_not_a_regular_file` |
| The projected token becomes unreadable while the process runs. | Any failure to read the file denies. The proxy sends no exchange request without client authentication. | `TestFailuresAreTwoClasses/the_kubelet_removed_the_projected_token`, `TestFailuresAreTwoClasses/the_projected_token_is_empty`, `TestFailuresAreTwoClasses/the_projected_token_holds_only_whitespace` |
| The workload reads the projected ServiceAccount token or the client secret and mints credentials for itself, bypassing the endpoint list. | The proxy reads each file at the configured path and writes it nowhere else. Neither reaches a log line, an audit record, or an `/info` answer. The secret reaches no form parameter either, because the proxy sends it in HTTP basic credentials. Both paths must name a regular file: a client secret file no larger than a megabyte, a token file no larger than 64 KiB. A client secret file must in addition be readable by its owner alone. The pod controls whether the workload can read either path. The sandbox chart's lint is what refuses a manifest that departs from this. | `TestReadSecretFileRefusals`, `TestCheckTokenFileRefusals`, `TestDescribeNamesTheSourceAndNoSecret`, `TestTheWireForm`, `token_exchange.txtar`, `workload_identity_exchange.txtar` |
| `identity.zone_url` resolves into the cluster or onto the metadata address, so the client authentication is offered to something that is not the zone. | The exchange uses the platform deny list for the zone connection. It refuses a resolved address on that list before it opens a socket. | `TestADeniedZoneAddressIsNotDialed` |
| A server that is not the zone answers discovery, takes the client authentication, and issues credentials the proxy writes into requests. | The exchange verifies the zone with the system roots and `tls.upstream_ca_files`. It requires TLS 1.2 or later and uses no proxy. RFC 8414 section 3.3 requires the metadata to name the configured zone as its issuer. A mismatch fails the exchange before the proxy posts a secret. | `TestTheZoneIssuerMustMatchTheConfiguredZone` |
| Metadata that names the configured zone as its issuer points `token_endpoint` at another host or at cleartext, so the client secret goes somewhere else. RFC 8414 section 3.3 binds the issuer and says nothing about `token_endpoint`. | Every request the exchange makes must be https, discovery and the token request alike. A cleartext endpoint reaches no socket. The exchange also refuses to follow a redirect, so a 307 from the token endpoint cannot move the secret to another host or to another port on the same host. | `TestTheTokenEndpointMustBeHTTPS`, `TestTheExchangeRefusesAnUnsafeZone/the_token_endpoint_redirects` |
| A zone streams a large body inside the exchange budget, which spends the sidecar's memory. | The exchange reads at most 1 MiB from the zone and fails the exchange past that. | `TestTheExchangeRefusesAnUnsafeZone/the_token_response_is_larger_than_the_limit` |
| A request the endpoint list already denies still spends an exchange, so the zone sees traffic the policy refused. | The exchange runs only after the request decision allows and the endpoint names a credential. A denied request reaches no zone. | `TestTheSourceReachesTheZoneOnlyOnCredential`, `token_exchange.txtar`, `TestRequestPath` |
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
| A container sharing the socket volume connects to the admin socket, or unlinks it and binds its own. | The socket directory is set to mode 0700 on every start, because a restart finds the directory a previous start left behind. The proxy refuses to start when the directory does not end up at 0700. The directory mode also covers the window between the bind, which honors the process umask, and the chmod of the socket to 0600. The default puts that directory inside the volume rather than at the mount point, which belongs to root at mode 0777 and which the proxy's uid may not chmod. The mount point's own mode is outside this check, which Known limits states. | `TestNewSetsTheDirectoryMode`, `TestCheckDirMode` |
| A wrong socket path causes the proxy to delete a file at start-up. | The proxy unlinks only an existing socket. Any other object at the path stops the process. | `TestNewRefusals`, `TestNewReplacesAStaleSocket` |

### Readiness and the probe subcommand

The admin socket answers `/readyz` once every frontend is bound and `ca.crt`
is on `ca.out_dir`. `egress-proxy probe <healthz|readyz|info>` dials the
socket, prints the answer and exits non-zero on anything but a 200. Which
probe runs which route is set in the manifest, which the sandbox chart owns.

The pod contract this surface assumes: the proxy is a sidecar, an entry in
`initContainers` with `restartPolicy: Always`, listed after netsetup. The
kubelet starts the next container only once a sidecar's startup probe
passes (https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/).
A proxy under `containers` starts beside the workload, and its probes hold
nothing back. The probe reads the socket path from `--admin` or
`EGRESS_PROXY_ADMIN`, not from the document, so a pod that moves the socket
sets the variable.

| Threat | Mitigation | Test |
|---|---|---|
| The workload starts before the proxy has written `ca.crt`, so every TLS handshake fails on certificate verification and an operator reads a misconfiguration as a policy denial. | The startup probe reads `/readyz`, which answers only once the listeners are bound and the certificate is on disk. The kubelet starts the workload only once it passes, under the pod contract above. The base image entrypoint waits for the certificate as well, which covers a restart that outlives the probe. | `TestReadinessNeedsTheCertificate`, `TestReadyz`, `TestProbeReadsTheAdminSocket`, `TestProxyImageBindsAPrivilegedPort`, `TestSandboxBaseImage` |
| The kubelet releases the workload while the port the capture redirects to is unbound, so the workload's first captured connection is refused. | Readiness turns true only after every listener is bound, the transparent sockets included. A transparent socket that fails to bind leaves the process not ready and stops it. | `TestBindReportsReadyOnlyOnceEveryListenerIsBound` |
| The capture sockets cover fewer address families than the receipt names. The capture binds `127.0.0.1` and `::1`, and leaves IPv6 out when the kernel refuses the socket with EAFNOSUPPORT. A proxy that reported ready then refuses every captured connection of the missing family for the life of the pod. | The receipt names the address families the init container programmed. The bind compares them against the sockets it opened and stops the process when the receipt names a family no socket covers. The start-up log names the families bound. | `TestBindReportsReadyOnlyOnceEveryListenerIsBound`, `TestCaptureFamiliesFollowTheSocketsThatBound` |
| The kubelet reads a 200 from `/readyz` during the SIGTERM drain and keeps sending the workload at a proxy whose listeners are closing. | The admin socket stops accepting when the drain starts, so the probe fails from the signal on. The shutdown path also clears the readiness flag, so a `/readyz` request already in flight answers 503. | `TestServeIsNotReadyOnceItStops` |
| An admin server is built with no readiness gate, and `/readyz` answers 200 for a process that has decided nothing. | A nil `Options.Ready` answers 503 naming that no gate is configured. | `TestServerAnswersHealthAndInfo`, `TestServerWithNoAnswers` |
| A probe reaches the admin surface over a port the workload can also reach. | There is no port. The probe runs this binary against the Unix socket in the proxy's mount namespace, and the socket path must be absolute. | `TestProbeReadsTheAdminSocket`, `TestProbeWithNoSocket`, `TestNewRefusals` |
| The kubelet restarts a proxy that has not finished starting, because liveness reads readiness. | The two routes are separate. `/healthz` answers while the process is alive and `/readyz` answers when it serves, so a liveness probe on `/healthz` does not restart a starting proxy. | `TestReadyz`, `TestProbeReadsTheAdminSocket` |
| The 503 body tells the workload something it does not already have. | The body says either that the listeners are not bound or that `ca.crt` is not readable. The only path in it is `ca.out_dir`, which `/info` already publishes. | `TestReadyz`, `TestProbeReadsTheAdminSocket` |
| Something on the socket path answers a probe with an endless body, and the probe holds a process slot every period. | The request has a five-second context and the read is capped at one mebibyte, so the probe returns whatever happens on the socket. | `TestProbeBoundsTheAnswer`, `TestProbeWithNoSocket` |

### Images

The three images are defined under `images/`. `make images` builds them
locally and checks each one in a container. Nothing in this repository
pushes an image.

| Threat | Mitigation | Test |
|---|---|---|
| Code running in the proxy container finds a shell, a package manager or curl and uses the sidecar's uid, which the capture exempts, to leave the pod. | The proxy image is distroless static: the binary, the public roots, and nothing else. The probe is the binary itself rather than a shell command. | `TestProxyImage` |
| The agent starts with a trust store the proxy's authority is not in, so every allowed request fails on certificate verification. | The base image entrypoint installs the certificate and runs `update-ca-certificates` before it execs the agent, and refuses to start the agent without it. Every bundle variable the image sets names the rebuilt bundle, and the image does not set a variable for a client it does not install. | `TestSandboxBaseImage` (the trust store, the git handshake, the missing certificate, the trust variables), `base_image_trust.txtar` |
| Each tool in an agent image needs its own proxy and CA settings. A tool nobody configured fails to reach an endpoint. | The base image entrypoint rebuilds the trust store, and the capture sends every connection to the proxy. In the built image, curl, Python requests, Node fetch, a Go client and git each reach an endpoint without a proxy address or a CA path. | `base_image_trust.txtar` |
| The netsetup image resolves an iptables binary on the nf_tables backend, whose rules the sandbox runtimes this proxy targets never apply, so the init container programs rules that never take effect. | The image installs the legacy binaries and the xtables extension libraries they load for `-m owner`, `-m conntrack`, `-m multiport` and `-m icmp6`. `TestNetsetupImage` runs the image's `egress-netsetup` with the init container's capabilities in a network namespace of its own. It loads both families through the legacy restore binaries, reads every rule back and drops CAP_NET_ADMIN. | `TestNetsetupImage` |

### Configuration document

| Threat | Mitigation | Test |
|---|---|---|
| A misspelled, repeated, or case-variant key silently changes enforcement. | The parser rejects unknown keys, repeated keys, keys that differ only in case, and a second YAML document. | `TestParseRefusesMalformedDocuments` |
| An audit record cannot be tied to the document that made the decision. | Every record holds the document canonical digest. | `TestDigestIsOverTheDocumentAsWritten`, `TestJSONSinkWritesOneLinePerRecord`, `TestTruncatedResponseIsAudited` |
| An environment variable or flag changes enforcement without changing the digest. | Every record also holds `config.digest` over the settings after an override applies, so two sidecars that enforce differently never share it. The endpoints and policy still come from the document alone. The start-up log and `/info` name every overridden key, and `egress-proxy settings` publishes the whole `EGRESS_PROXY_` namespace, so a chart lint can refuse any other variable on the proxy container. | `TestConfigDigestCoversTheEffectiveSettings`, `TestCommandResolvesFlagsAndEnvironment`, `TestSettingsCoverEveryFlag` |
| A build that denies different destinations is indistinguishable in the records. | `config.digest` covers a digest of the ranges, host names and suffixes compiled into the binary, so two builds that deny differently never share it. | `TestConfigDigestCoversTheEffectiveSettings` |

## Known limits

- Traffic capture is not a security boundary. A workload that can reach the
  proxy uid escapes the redirect and the filter exclusion together. The
  workload securityContext closes that. See the netsetup ruleset surface.
- A name the allowlist refuses fails at the lookup rather than at the
  connection. The workload sees "could not resolve host", not a 403 with
  `X-Keycard-Deny-Reason`. The record holds the same reason code under
  scope `dns`.
- One lookup can write several records. A stub resolver with `ndots` set
  tries each search domain before the absolute name, and each attempt is a
  decision the resolver answers and records. In the e2e tests the pod's
  search list holds three domains and `ndots` is 5, so one `curl` to an
  allowed host writes four records: three refusals for the search-expanded
  names and one allow. One `curl` to a host that resolves nowhere writes
  eight, because a resolution that fails outright asks for both address
  families on each of the four candidates. The cluster resolver would
  also answer those attempts `NXDOMAIN`. The extra records do not change
  any answer.
- The name is the allowlist unit, not the query type. Any type resolves for
  a name an endpoint declares, a `TXT` lookup included, and the answer is
  whatever the zone's owner published. The endpoint is already reachable
  over HTTPS through the proxy, and a lookup for it is recorded.
- The resolver's connection cap is per listener. `limits.max_dns_connections`
  bounds each of the resolver's TCP listeners, so a resolver bound on both
  address families can hold twice that many. A connection answers at most
  64 queries and closes after ten seconds idle. UDP has no cap. The
  resolver, the frontends and the audit writer share the process's file
  descriptor limit, so this cap and `limits.max_connections` count against
  the same limit.
- Anything listening on the pod loopback is reachable by the workload. The
  filter chain accepts loopback, because that is where the redirect sends
  the captured connections and the queries. A pod runs the proxy and the
  workload and nothing else on that interface.
- `ESTABLISHED` in OUTPUT is an open channel to any peer that opens a
  connection into the pod. The accept matches the reply direction only, so
  it passes nothing on a flow the pod opened. INPUT is untouched and its
  policy is ACCEPT, so a peer that connects into the pod creates a conntrack
  entry. The workload then has an unrestricted two-way channel to that peer
  on that tuple, over TCP or UDP. A NetworkPolicy on ingress closes it.
- The sidecar's DNS forwards and the workload's queries share one conntrack
  zone and one source port range. A UDP entry lasts 30 seconds after its
  last packet (`nf_conntrack_udp_timeout`). A forward sent from a tuple a
  workload query used inside that window joins the workload's flow, and its
  redirect sends the forward back to the sidecar's resolver. The resolver
  writes another `endpoint_allowed` record and forwards again, so one
  lookup can write several records. A workload that sends from every port
  in the range makes its own allowed lookups fail with `SERVFAIL`. The
  reverse also happens: a workload query sent from a tuple a forward used
  reaches the DROP, and the send fails with EPERM. Neither case sends a
  name the allowlist refuses. The chance for one send is about the number
  of tuples the other side used in the last 30 seconds, divided by the
  28,232 ports of the default `net.ipv4.ip_local_port_range`, 32768 to
  60999. A separate conntrack zone for the proxy uid's DNS flows removes
  both.
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
  that fails for a reason the policy did not decide does not get an audit
  record in either case, because the connection-scoped allow is written only once the
  tunnel is established.
- An idle timeout does not limit a request in flight. A response that is still
  transferring is not idle. A stalled upstream keeps its connection until the
  workload or upstream closes it.
- The sidecar checks the mode of the admin socket directory and of no
  directory above it. It sets that directory to 0700 and reads the mode
  back. The volume mount point above it is owned by root at mode 0777
  (kubernetes `pkg/volume/emptydir/empty_dir.go`, `perm`), and the proxy's
  uid may not chmod it. Any uid that mounts the volume can create entries
  beside the socket directory, but not inside it.
- Readiness is a point in time. `/readyz` reads the listener flag and stats
  `ca.crt` on each request, so it reports the state then rather than a
  guarantee about the next request.
- The address family check reads the receipt, which the init container
  wrote. It says what was programmed at that moment, so a rule removed
  afterwards is outside what this check sees.
- This repository does not check pod specs. `egress-proxy settings`
  publishes the variables and the defaults a manifest has to match. The
  sandbox chart's lint reads them and refuses a manifest that differs.
- goproxy discards bytes buffered after the CONNECT head. A client that sends
  its ClientHello before it reads the 200 loses those bytes. The handshake then
  waits for a ClientHello that already went missing and spends the whole
  budget, which is the warning above. Clients wait for the 200, as RFC 9110
  section 9.3.6 describes.
