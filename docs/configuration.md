# Configuration

The proxy reads one YAML or JSON document from `--config` or
`EGRESS_PROXY_CONFIG` once at start-up and keeps it in memory. Restart the
process after a change. The repository root has a complete example in
`config.example.yaml`.

## Sources and precedence

Settings come from three sources. Later sources override earlier sources in
this order: the document, the environment, and flags.

Only settings for this instance and process support a flag and an environment
variable: `sandbox.*`, `identity.*`, `listen.*`, `ca.*`, `tls.*`,
`credentials.*`, and `limits.*`. A manifest renderer can set them from the pod
metadata. For example, `sandbox.id` from the pod name and
`identity.impersonate.user` from `spec.serviceAccountName` through the
Kubernetes Downward API.

The document alone defines the `endpoints` and `policy` sections. These values
decide what the proxy allows. Each audit record attributes that decision to the
document digest. An override can hide a decision-affecting value from that
attribution, so these values cannot come from another source.

Every record also holds `config.digest`, which covers the settings after an
override applies. Read it with `document.digest` to distinguish the mounted
file from the settings in force. See "What the digests identify" below.

Every environment variable starts with `EGRESS_PROXY_`. The tables below list
the variable for each setting that supports one. The start-up log and `/info`
list every setting that an override replaced in `overridden`. A flag or
environment variable follows the same rules as the document value that it
replaces.

The parser rejects these errors:

- Unknown config keys. A misspelled key must not silently use a default value.
- A repeated key within the same object.
- Two keys within the same object that differ only in case, such as `listen` and
  `Listen`. Field names ignore case, so both keys would name one setting and the
  later key would silently win.

### What the digests identify

Every audit record holds two digests. Each value contains `sha256:` followed
by the hexadecimal SHA-256 digest of a document in RFC 8785 canonical JSON.

`document.digest` identifies the mounted file. `config.digest` identifies what
the process enforces. The proxy computes it from the settings that decide an
answer, in the form they take after every override and default: the endpoints,
the cluster ranges, the deny list exceptions, the identity, the effective
credential source, the upstream root files, and the platform deny list built
into this binary.
Two sidecars that answer every request alike write the same value, whatever
document, flag or variable each one was given.

Reading the two together tells you what happened. The same `document.digest`
with different `config.digest` values means an override, a default, or a build
changed what the sidecars enforce. Settings that decide nothing stay out of
`config.digest`, so `sandbox.id`, the listen addresses, the CA paths and the
limits never move it. The digest is one way and this proxy publishes no
reader for its input, so hashing a file path leaks nothing.

The schema grows by adding keys. The proxy does not rename or repurpose keys.
Every earlier example document continues to parse from
`internal/config/testdata/compat`.

## Keys

### Top level

| Key | Required | Variable | Description |
|---|---|---|---|
| `version` | yes | | Must be `1`. |
| `sandbox.id` | yes | `EGRESS_PROXY_SANDBOX_ID` | Identifies the sandbox that this proxy serves. The proxy adds it to every audit record as `sandbox_id`. The value cannot contain whitespace. The document or the environment variable must provide it. |

### `identity`

The whole section is optional. When it exists, the proxy mints an upstream
credential for each allowed request with an RFC 8693 token exchange against
the zone. It impersonates `impersonate.user`. Both this section and
`credentials.static_file` name a credential source, so the proxy refuses a
document that contains both.

| Key | Variable | Description |
|---|---|---|
| `zone_url` | `EGRESS_PROXY_ZONE_URL` | The Keycard zone. Use an absolute `https` URL without user information. RFC 8414 discovery runs against this URL, and the metadata must name it as the issuer. The proxy verifies the zone with the system roots and `tls.upstream_ca_files`, then refuses to dial an address on the platform deny list. |
| `client_id` | `EGRESS_PROXY_CLIENT_ID` | The ID of the application credential that the proxy authenticates as. Find it among the application's credentials in the Keycard console. |
| `workload_token_file` | `EGRESS_PROXY_WORKLOAD_TOKEN_FILE` | The absolute path of the projected ServiceAccount token. The kubelet rewrites the token once it passes 80% of its lifetime, which defaults to one hour, or once it is older than 24 hours, and does not restart the pod. The application reloads the token itself, so the proxy reads the file again for every exchange. See [Launch a Pod using service account token projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#launch-a-pod-using-service-account-token-projection). A rewrite revokes nothing. The previous token stays valid until its own `exp`, which is the remaining 20% of its lifetime. The kubelet writes the new token to a timestamped directory and renames the `..data` symlink onto it, so a read never sees a partial write. See [`AtomicWriter.Write`](https://github.com/kubernetes/kubernetes/blob/v1.34.5/pkg/volume/util/atomic_writer.go#L86-L140). A read that fails or finds an empty file denies the request. The file must be a regular file no larger than 64 KiB. The proxy refuses any other kind of file at start-up, because a read of one can block past the exchange budget. |
| `client_secret_file` | `EGRESS_PROXY_CLIENT_SECRET_FILE` | The absolute path of a file that holds the application credential secret. The proxy reads it once at start-up, so restart the process after a rotation. The file must be readable by its owner alone. The proxy refuses a file with any group or other permission bit. |
| `impersonate.user` | `EGRESS_PROXY_IMPERSONATE_USER` | The IAM user public ID for each exchange. The ServiceAccount has the same name, so a manifest sets this value from `spec.serviceAccountName`. |

The document must set exactly one of `workload_token_file` and
`client_secret_file`. The two mechanisms use different forms of client
authentication. Workload identity sends the projected token as an RFC 7523
client assertion. The zone reads the ServiceAccount subject from that token,
so its policy can allow one user for one ServiceAccount. Use workload identity
in a cluster. Use a client secret outside Kubernetes, where no OIDC issuer
signs a ServiceAccount token.

The two keys are mutually exclusive, and an environment variable cannot swap
one for the other. Setting `EGRESS_PROXY_CLIENT_SECRET_FILE` against a
document that already names `workload_token_file` leaves both set, which
fails validation. To move a document onto the client secret, remove
`workload_token_file` from the document.

A client secret uses `client_secret_basic` and names no ServiceAccount. A zone
that accepts the secret permits impersonation based on that secret alone. Bind
the application credential to one user in the zone. Read the known limits in
`docs/security-model.md` before you use this mechanism outside a test.

Never write the secret into the document, which is a ConfigMap, a flag, or an
environment variable. Store only the path in the configuration.

An environment variable can provide one field for a document that contains
the other fields. It can provide every field for a document that contains
none. The proxy rejects a partial identity supplied only by the environment.

If the zone refuses an exchange on policy, the proxy denies the request with
`exchange_denied` and returns 403, because a retry gets the same answer. If
the exchange fails for another reason, the proxy denies the request with
`exchange_failed` and returns 502. The proxy makes no exchange for a request
that the endpoint list denies.

### `listen`

| Key | Default | Flag and variable | Description |
|---|---|---|---|
| `connect` | `127.0.0.1:3128` | `--connect`, `EGRESS_PROXY_CONNECT` | The CONNECT frontend in `host:port` form. A workload that honors `HTTPS_PROXY` reaches the proxy through this address. |
| `transparent_port` | unset | `--transparent-port`, `EGRESS_PROXY_TRANSPARENT_PORT` | The redirect target. The netsetup init container sends captured TCP here, so clients reach the proxy without a proxy variable. The frontend binds this port on 127.0.0.1 and ::1 and no other address, because REDIRECT sends every captured connection to loopback. Other pods cannot connect to it. Unset or 0 disables the transparent frontend. Keep the port below `net.ipv4.ip_unprivileged_port_start` so an unprivileged workload cannot bind it during a sidecar restart. The proxy reads that sysctl at start-up and refuses to start when it is at or below the higher of this port and `listen.dns`. containerd 2.0 and later sets the sysctl to 0, so set it to `1024` in the pod's `securityContext.sysctls`. The proxy binds the port with `NET_BIND_SERVICE` from a file capability. Add `NET_BIND_SERVICE` to the sidecar and run the binary as its entrypoint. Linux only. |
| `cleartext_ports` | `[80]` | | The captured ports the frontend reads as cleartext HTTP. It gets the destination from the `Host` header. It reads every other captured port as TLS and gets the destination from the ClientHello. Endpoints name HTTPS destinations, so the proxy reads a cleartext connection and then refuses it. `config.digest` includes this setting only when `transparent_port` is set. |
| `dns` | unset | `--dns`, `EGRESS_PROXY_DNS` | The allowlist resolver in `host:port` form. The netsetup init container redirects UDP and TCP port 53 here. A name the document does not declare answers `NXDOMAIN` and does not reach the cluster resolver. A host that is empty or unspecified binds 127.0.0.1 and ::1, which is where the redirect rewrites the destination. A host of 127.0.0.1 or ::1 binds that address. The proxy refuses any other address, because the redirect does not reach it or other pods can. It refuses a hostname, including `localhost`, because the proxy would have to look it up before its resolver runs. Unset disables the resolver, and the init container must then run with `--dns-port 0`. The proxy refuses to start when the two disagree. Keep the port below `net.ipv4.ip_unprivileged_port_start` for the reason `transparent_port` gives. Linux only. |
| `admin` | `/run/egress/admin/admin.sock` | `--admin`, `EGRESS_PROXY_ADMIN` | The admin socket as an absolute file system path. Its directory must belong to the proxy uid, which sets it to mode `0700`. The default uses a separate subdirectory of the receipt volume. Use a Unix socket, never a port. The proxy shares the pod network namespace with the workload, so a loopback port would be reachable by that workload. `egress-proxy probe` does not read the document, so set a socket path other than the default with the variable. |

The admin socket answers `GET /healthz` with `ok` while the process is
alive. It answers `GET /readyz` with `ok` once every frontend is bound
and `ca.crt` is written to `ca.out_dir`, and with 503 and the reason before
that and again for the whole shutdown drain. It answers `GET /info`
with a JSON object that contains the binary version, `sandbox_id`,
`document_digest`, `config_digest`, `overridden`, the listen and limit
settings, the CA output directory and expiry, the credential source, the
netsetup receipt path, a `dns` object, the endpoint hosts, the cluster
ranges, and the deny list exceptions. The `dns` object holds the resolver's
`listen` address, the names it answers for under `resolves`, and the
resolvers it forwards to under `forward_to`. A process that runs no
resolver reports an empty `listen` and nothing else. The socket
has mode 0600 in a directory with mode 0700. The proxy sets that directory
mode on every start and refuses to start when the directory does not end up
at mode 0700, so no other uid in the pod can reach the socket. Keep
`ca.out_dir` out of that directory: the workload cannot traverse it.

`egress-proxy probe <healthz|readyz|info>` dials that socket, prints the
answer and exits non-zero on anything but a 200. It reads the same `--admin`
and `EGRESS_PROXY_ADMIN` the serving process reads, because it runs in the
same container. The proxy image has no shell and no curl, so this subcommand
is how the kubelet's probes, an operator and the e2e tests reach the
admin surface.

`egress-proxy settings` prints the settings this binary accepts as JSON,
with no document and no socket: every variable in the table above, the flag
that fills the same setting, and the default the parser applies. It also
prints the probe routes and the netsetup defaults a pod has to match. A
duration default is a whole number of seconds, so `--leaf-ttl` publishes
`86400`. The sandbox chart's lint reads it. See `docs/containers.md`.

### `dns`

Where the allowlist resolver forwards a name it answers. **There is no
setting for which names resolve.** The resolver answers only the endpoint
hosts and the zone host, which are the hosts the proxy connects to.

The match is exact equality on the whole name, case-insensitive. A
subdomain of an endpoint host does not resolve. `data.upstream.example` is
refused where `upstream.example` resolves.

| Key | Default | Flag and variable | Description |
|---|---|---|---|
| `forward_to` | from the receipt | `--dns-forward-to` (repeatable), `EGRESS_PROXY_DNS_FORWARD_TO` (comma-separated) | The cluster resolvers an allowed name goes to, each an address with an optional port that defaults to 53. They are tried in order and the first answer wins. When unset, the proxy reads them from the netsetup receipt, which holds what the init container read from `/etc/resolv.conf`. Name each resolver by IP address. The proxy refuses a hostname, because looking it up would need a resolver. It refuses a target that names its own listen address, which would forward every allowed name to itself. It also refuses this setting without `listen.dns`, because nothing would read it. |

A query no resolver answered gets `SERVFAIL` and an `upstream_failed`
record. A message that is not one lookup gets `FORMERR` and a
`malformed_request` record. Neither forwards.

### `netsetup`

| Key | Default | Flag and variable | Description |
|---|---|---|---|
| `receipt` | `/run/egress/netsetup/netsetup.json` | `--netsetup-receipt`, `EGRESS_PROXY_NETSETUP_RECEIPT` | The file where the init container records the rules it programmed. The proxy reads it when `listen.transparent_port` or `listen.dns` is set, because the rules redirect traffic to both. Put it on an `emptyDir` with `medium: Memory` that the init container and sidecar share but the workload does not mount. Keep it out of the admin socket directory, which the proxy takes to mode 0700. |

The proxy reads the receipt before it serves requests. It refuses to start if
the active rules differ from the receipt: the rules were not verified, the
init container kept `CAP_NET_ADMIN`, the proxy uid, the redirect port or the DNS port differs,
the proxy uid is 0, the receipt names no address family, the receipt names
another network namespace or none, this process holds
`CAP_NET_ADMIN`, group or other can write the receipt, the receipt or its
directory belongs to a uid other than root or the proxy, or
`net.ipv4.ip_unprivileged_port_start` is at or below the higher of the redirect port and the DNS port. It
skips the last check when the receipt records `allow-unprotected` in
`redirect_port_protection`. The directory itself can be writable by every uid
because an `emptyDir` mount point is writable that way. Each refusal names both values and the setting to change.

The init container is `egress-netsetup`. Its settings are arguments, not
environment variables, so the pod spec shows the whole ruleset.
`--dry-run` prints the rules without applying them.

### `ca`

| Key | Default | Flag and variable | Description |
|---|---|---|---|
| `out_dir` | `/shared-ca/out` | `--ca-out-dir`, `EGRESS_PROXY_CA_OUT_DIR` | The directory where the proxy writes `ca.crt` before it listens. The file has mode 0644, and the directory has mode 0755. The proxy sets that mode at every start, so this must be a directory the proxy creates inside the shared volume rather than the mount point, which belongs to root. The workload mounts the volume read-only and installs the file. The directory holds only the certificate. |
| `state_dir` | unset | `--ca-state-dir`, `EGRESS_PROXY_CA_STATE_DIR` | The directory that stores the CA key and certificate across a restart. This keeps the same authority that a running workload already trusts. The path must use a memory-backed volume, such as `emptyDir` with `medium: Memory`. The process checks that the directory uses tmpfs, rejects other file systems, and rejects a path that overlaps `out_dir`. When unset, the proxy keeps the authority only in memory. A restart then creates a new authority. Linux only. |
| `leaf_ttl` | `24h` | `--leaf-ttl`, `EGRESS_PROXY_LEAF_TTL` | How long a minted leaf certificate stays valid. A leaf never outlives the authority, which lives for 30 days. |
| `cache_size` | `1024` | `--cache-size`, `EGRESS_PROXY_CACHE_SIZE` | The number of minted leaf certificates that the proxy keeps. The proxy uses an LRU keyed by server name. |

The proxy writes the key to `state_dir` and nowhere else. No flag, key, or
code path writes the key under `out_dir` or to another file system.

### `tls`

| Key | Default | Flag and variable | Description |
|---|---|---|---|
| `upstream_ca_files` | `[]` | `--upstream-ca-file` (repeatable), `EGRESS_PROXY_UPSTREAM_CA_FILES` (comma-separated) | PEM files whose certificates join the system roots when the proxy verifies an upstream. Use this for a destination behind a private CA or for test fixtures. Each entry must be an absolute path. A file that the proxy cannot read or that contains no certificate stops the process. |

The upstream leg verifies every certificate and refuses TLS versions below
1.2. It ignores `HTTP_PROXY` and `HTTPS_PROXY`. The proxy shares an
environment with the workload, and those variables would name the proxy
itself.

### `credentials`

This section names the source from which the proxy reads endpoint credentials.
If a document names no source, every endpoint that names a credential is
denied with `credential_unavailable`. The process reports its source at every
start, and `/info` reports it as `credential_source`.

| Key | Default | Flag and variable | Description |
|---|---|---|---|
| `static_file` | unset | `--credential-static-file`, `EGRESS_PROXY_CREDENTIAL_STATIC_FILE` | A plain-text file that maps resources to credentials for tests and development. Use an absolute path that only its owner can read. The proxy refuses any group or other permission bit and refuses this setting with `identity`. |

The other source is `identity`, which mints a credential per request against
the zone. `config.digest` covers the source in force, so two sidecars that
read different sources never share it.

The proxy reads the file once at start-up. Restart the process after a
change. The file uses this format:

```yaml
version: 1
credentials:
  - resource: "https://api.github.com"
    value: "<the credential>"
```

Each entry uses the same resource URL as an endpoint. A request to an endpoint
whose resource the file omits is denied with `credential_unavailable`. The
proxy refuses repeated resources, empty credentials, and credentials with a
control character. A control character would split the request head.

### `limits`

| Key | Default | Flag and variable | Description |
|---|---|---|---|
| `max_connections` | `1024` | `--max-connections`, `EGRESS_PROXY_MAX_CONNECTIONS` | The maximum number of simultaneous connections one frontend serves. Further accepts wait until a connection ends. Each frontend has its own limit, so a process configured for `1024` with both frontends can hold `2048`. The transparent frontend takes a slot after accept, so each socket also holds one accepted connection unread at the limit. |
| `max_dns_connections` | `128` | `--max-dns-connections`, `EGRESS_PROXY_MAX_DNS_CONNECTIONS` | The maximum number of simultaneous TCP connections one resolver listener accepts. Further accepts wait until a connection ends. It is separate from `max_connections` because a lookup is one short exchange and the frontends need the file descriptors the resolver would otherwise hold. The limit is per listener, so a resolver bound on both address families can hold twice that many. UDP has no cap. |
| `idle_timeout` | `5m` | `--idle-timeout`, `EGRESS_PROXY_IDLE_TIMEOUT` | The time before the proxy closes a connection that neither reads nor writes. The proxy applies this limit on the frontend, inside a tunnel, and on the upstream connection. It refuses a request head that has not arrived after 10 seconds. |
| `response_header_timeout` | `30s` | `--response-header-timeout`, `EGRESS_PROXY_RESPONSE_HEADER_TIMEOUT` | The time an upstream has to send a response head once the proxy writes the request. A slower upstream gets `upstream_failed`. This limit does not bound a body, so a server-sent event stream runs as long as it stays active. |
| `exchange_timeout` | `10s` | `--exchange-timeout`, `EGRESS_PROXY_EXCHANGE_TIMEOUT` | The upper bound for one token exchange, including discovery. The dial and TLS handshake to the zone each have five seconds inside this budget, and discovery has at most ten seconds whatever the budget, because the SDK caps its own metadata fetch there. A request that spends the budget gets `exchange_failed`. This setting limits a call but does not decide the answer, so `config.digest` excludes it. |

An absent setting takes the default, and so does a setting written as zero,
because this schema reads zero as unset. A negative value is refused. Nothing
bounds a whole request, because a long request that is still transferring is
working rather than stalled.

### `policy`

The document supplies this section. No flag or environment variable can
change it.

| Key | Default | Description |
|---|---|---|
| `cluster_cidrs` | `[]` | The pod and service ranges for this cluster in CIDR form. The proxy adds these ranges to the platform deny list. |
| `deny_list_exceptions` | `[]` | Ranges that the platform deny list no longer covers. This setting alone can shorten the list, and an entry can be as broad as `0.0.0.0/1`. The proxy rejects only an exception that covers `169.254.169.254`. It reports every exception as a warning at start-up and on `/info`, and `config.digest` covers the set. |

The binary contains the platform deny list. It includes loopback, RFC 1918,
link-local ranges that contain the cloud metadata address, shared address
space, IPv6 equivalents, cloud metadata host names, and the large public
DNS-over-HTTPS resolvers. The proxy rejects a document that names a covered
host at start-up. It also rejects an allowed name at dial time when the name
resolves into a covered range, with `deny_always`. Exceptions apply only to
addresses. A covered host name remains covered inside an excepted range.

The metadata address is the only range an exception cannot remove. Everything
else in the list is a default that the document can drop, in one entry or
several, so review `deny_list_exceptions` the way you review the endpoint
list. A sidecar announces the set it is running at start-up and reports it on
`/info`.

### `endpoints`

The document supplies this section. No flag or environment variable can
change it. The section lists the destinations that the sandbox can reach. The
proxy rejects every other connection or request. An empty list rejects all
connections and requests.

| Key | Default | Description |
|---|---|---|
| `url` | required | The endpoint, as `https://host[:port][/path]` or `http://host[:port][/path]`. The proxy reads the host, the port and the path prefix from it, and sends its canonical form to token exchange as the resource. It must not hold user information, a query or a fragment. |
| `credential` | unset | Defines where in a request the proxy puts a credential. See `endpoints[].credential`. |

**Host.** A DNS name without a wildcard. Labels hold ASCII letters, digits and hyphens, and the last label is not all digits. The proxy matches the name case-insensitively against the SNI. It rejects an IP literal, because a TLS client sends no SNI for one, and it rejects an address written another way, such as `0177.0.0.1` or `2852039166`, which a resolver still reads as an address. Write an internationalized name as its A-label, the `xn--` punycode form. RFC 6066 section 3 requires the SNI to be ASCII, so a host holding non-ASCII characters never matches what a client sends.

**Port.** The scheme's port, 443 for `https` and 80 for `http`, unless the URL names another. An endpoint covers one port. A host reachable on two ports is two endpoints, which also gives each one its own prefix and credential. A CONNECT to any other port on the host is rejected with `no_matching_endpoint`, the same reason an unlisted host gets.

**Path.** `/` when the URL has none, and `/` covers every path. A path that ends in `/` covers everything below it. Any other path covers itself and its child paths as segments. For example, `/api` covers `/api` and `/api/v1`, but not `/apis`. The longest matching path decides. Write the path as it appears on the wire: the proxy compares it against the escaped path, so a path holding a character a client always escapes, such as a space, is rejected because it could never match.

**Resource.** The canonical form of the URL: the scheme and host in lowercase, no trailing dot, no port when it is the scheme default, and sub-path as written.

The proxy decides on the escaped path, the bytes it forwards upstream. An
escaped character is not a separator, so `/a%2Fb` is one segment named `a/b`
and the prefix `/a/` does not cover it. The proxy refuses a path whose
escaped or decoded form holds dot segments, so `/api/%2e%2e/secret`, which
an upstream that decodes first reads as `/secret`, is rejected with
`malformed_request`.

Two endpoints whose URLs name the same host, port and path are rejected. The
same host and path on two ports are two endpoints, not a repeat.
The proxy forwards nothing cleartext. A cleartext `http://` request is
rejected with `cleartext_not_forwarded`, and an `http://` endpoint does not
change that. An `http://` endpoint lets the connection to port 80 through,
so the request is refused with `cleartext_not_forwarded` instead of
`no_matching_endpoint`. An `http://` endpoint cannot hold a credential.

#### `endpoints[].credential`

| Key | Description |
|---|---|
| `placement.kind` | `header`, `query`, or `basic`. |
| `placement.name` | For `header`, the header name. For `query`, the parameter name. |
| `placement.template` | For `header`, the value with `{credential}` where the proxy puts the credential, such as `Bearer {credential}`. |
| `placement.user` | For `basic`, the user name. The credential becomes the password. It must not contain a colon or a control character. |

A placement tells the proxy where to write the credential. The placement wins
over any value that the workload sent there. The proxy also writes the
credential when the workload sent nothing. A header placement replaces every
value under that header name. A query placement replaces every value under
that parameter name and re-encodes the query. The request then leaves with
its parameters sorted by name. A basic placement replaces every value under
`Authorization` with `Basic base64(user:credential)`, as RFC 7617 section 2
writes it.

A header placement cannot name these headers, whatever their case. The proxy
refuses the document at start-up, and the writer refuses the same names.

| Header | Why |
|---|---|
| `Connection`, `Proxy-Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Proxy-Authenticate`, `Proxy-Authorization` | These hop-by-hop headers govern the connection that the proxy owns. The proxy strips them, so the credential never leaves. See RFC 9110 section 7.6.1. |
| `Content-Length` | It frames a body the proxy does not write. |
| `Host` | The proxy writes the host from the request target, not from the header map. The credential would not reach the upstream. |
| `Forwarded` (RFC 7239), any name starting `X-Forwarded-`, any name starting `Sec-` | An upstream can read these as the client's identity or route, and the `Sec-` names belong to the user agent. |

The proxy allows `Authorization`, which most endpoints use.

A basic placement also removes any userinfo from the request line. The
document names the user and the credential is the password. A user or
password in a clone URL has no effect on what the proxy sends. Use a basic
placement for git over HTTPS. The sandbox does not need a credential
helper.

A request that the credential source cannot answer is denied with
`credential_unavailable`. If the writer cannot write a placement, the request
is denied with the same reason before the proxy dials. The proxy never
forwards the value the workload sent at the placement to a credentialed
endpoint.

The proxy writes the credential after it removes the hop-by-hop headers that
the workload named in `Connection`. A workload cannot name the placement
header there and have the credential dropped on the way out.

No credential reaches a log line or an audit record. A record holds the
method, the path without its query, and the host. The proxy redacts credentials
from request error text. It suppresses raw ReverseProxy diagnostics and reports
incomplete responses in the audit record. Static-file parse errors name the
file and failing stage without including raw parser diagnostics.

## Decisions and reason codes

The proxy writes one JSON line to stdout for every decision. `scope` is
`connection` for the decision made when a CONNECT arrives or when the
transparent frontend recovers a captured connection's destination. It is
`request` for each request inside the tunnel. `connection_id` joins the two
records. A captured connection also names `destination.original_address`,
the address the client opened before the redirect rewrote it. That field
identifies a captured connection in the audit stream.
`decision.reason` has one of these values:

| Reason | Verdict | Scope | Meaning |
|---|---|---|---|
| `endpoint_allowed` | allow | both | An endpoint matched. A request record names it in `decision.endpoint`, as `host:port` plus the URL path. The port is always written, so one shape parses every id. A connection record names none, because no path took part in that decision. A connection record is written once the tunnel is established, so it also names the SNI, and a connection the handshake refused never gets an allow. |
| `deny_always` | deny | both | The host is on the platform deny list, or it resolved into a covered range at dial time. |
| `no_matching_endpoint` | deny | both | No endpoint covers the destination: none names the host, one does and none names the port, or one does and none covers the path. Read `scope` to tell those apart. |
| `cleartext_not_forwarded` | deny | both | The connection or request sends cleartext HTTP. The proxy forwards nothing cleartext, so an endpoint that covers the host on that port does not make the destination reachable. Change the client to `https://`. A host on the deny list is refused with `deny_always` instead, and a host no endpoint covers with `no_matching_endpoint`. |
| `no_sni` | deny | connection | The TLS handshake named no server, either inside a tunnel or on a captured connection whose ClientHello had no `server_name`. RFC 6066 section 3 forbids an IP literal there, so a client connecting straight to an address sends none. |
| `not_redirected` | deny | connection | The destination recovered from a connection on the transparent listener is that listener's own address, so the connection was opened to the proxy rather than redirected into it. |
| `host_mismatch` | deny | both | The SNI differs from the CONNECT authority, the request `Host` header differs from the SNI and port, or a captured connection names a destination that differs from the address it used. |
| `malformed_request` | deny | both | The request uses an asterisk-form target, a path whose escaped or decoded form holds dot segments, a query that does not parse, or a CONNECT authority with a bad port. |
| `not_a_proxy_request` | deny | request | An origin-form request reached the CONNECT listener. The listener does not serve requests of its own. |
| `credential_unavailable` | deny | request | The proxy did not put a credential in the request. The process has no source, the source has none for the endpoint resource, or the writer reported an error. `decision.error` identifies the cause. |
| `exchange_denied` | deny | request | The zone read its policy and refused the token exchange. Its policy does not permit this proxy to act for `identity.impersonate.user` on the endpoint resource, it does not permit this client to impersonate at all, or it does not know that user. The zone answers `access_denied`, `unauthorized_client`, or `invalid_grant`. A retry gets the same answer. |
| `exchange_failed` | deny | request | The token exchange did not complete. Discovery failed, the zone was unreachable, it refused the exchange for a reason that is not its policy, or the exchange spent `limits.exchange_timeout`. The proxy does not know whether the credential would have been granted. |
| `upstream_failed` | deny | request | An allowed request produced no response from the upstream. |
| `certificate_unavailable` | deny | connection | The policy allowed the server name and the proxy could not mint a leaf for it. The handshake fails and no request crosses the tunnel. |

A refusal names its reason in the `X-Keycard-Deny-Reason` header. It holds
the connection or request ID in `X-Keycard-Request-Id`. The proxy uses status
403 for a policy refusal, 400 for a malformed or non-proxy request, and 502 when
a dependency fails. `upstream_failed` and `exchange_failed` both answer 502
because a retry can succeed. A refused handshake does not have a response to put
a header on. The client sees a TLS failure, and the record names the reason.

The proxy writes JSON logs to stderr. These logs contain no decision. The
audit stream on stdout contains the decision record.
