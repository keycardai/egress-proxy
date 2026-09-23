# Configuration

The proxy reads one YAML or JSON document from `--config` or
`EGRESS_PROXY_CONFIG` once at start-up and keeps it in memory. Restart the
process after a change. The repository root has a complete example in
`config.example.yaml`.

## Sources and precedence

Settings come from three sources. Latter sources override earlier sources in
this order: the document, the environment, and flags.

Only settings for this instance and process support a flag and an environment
variable: `sandbox.*`, `identity.*`, `listen.*`, `ca.*`, `tls.*`, and
`limits.*`. A manifest renderer may set them from the pod metadata. For example,
`sandbox.id` from the pod name and `identity.impersonate.user` from
`spec.serviceAccountName` through the Kubernetes Downward API.

The document alone defines the `endpoints` and `policy` sections. These values
decide what the proxy allows. Each audit record attributes that decision to the
document digest. An override could hide a decision-affecting value from that
attribution, so these values cannot come from another source.

Every record also carries `config.digest`, which covers the settings after an
override applies. The two digests answer different questions. See "What the
digests identify" below.

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

Every audit record carries two digests. Each value contains `sha256:` followed
by the hexadecimal SHA-256 digest of a document in RFC 8785 canonical JSON.

`document.digest` identifies the mounted file. `config.digest` identifies what
the process enforces. The proxy computes it from the settings that decide an
answer, in the form they take after every override and default: the endpoints,
the cluster ranges, the deny list exceptions, the identity, the upstream root
files, and the platform deny list this build carries. Two sidecars that answer
every request alike write the same value, whatever document, flag or variable
each one was given.

Reading the two together tells you what happened. The same `document.digest`
with different `config.digest` values means an override, a default or a build
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

The whole section is optional. When it exists, every key is required. The
proxy applies these requirements and uses the values during token exchange.
Without this section, every endpoint that names a credential is denied with
`credential_unavailable`, and the process reports the reason at every start.

| Key | Variable | Description |
|---|---|---|
| `zone_url` | `EGRESS_PROXY_ZONE_URL` | The Keycard zone. Use an absolute `https` URL without user information. |
| `client_id` | `EGRESS_PROXY_CLIENT_ID` | The application credential ID from the catalog output. |
| `workload_token_file` | `EGRESS_PROXY_WORKLOAD_TOKEN_FILE` | The absolute path of the projected ServiceAccount token. |
| `impersonate.user` | `EGRESS_PROXY_IMPERSONATE_USER` | The IAM user public ID for each exchange. The ServiceAccount has the same name, so a manifest sets this value from `spec.serviceAccountName`. |

An environment variable can provide one field for a document that contains
the other fields. It can also provide all four fields for a document that
contains none. The proxy rejects a partial identity supplied only by the
environment.

### `listen`

| Key | Default | Flag and variable | Description |
|---|---|---|---|
| `connect` | `127.0.0.1:3128` | `--connect`, `EGRESS_PROXY_CONNECT` | The CONNECT frontend in `host:port` form. A workload that honors `HTTPS_PROXY` reaches the proxy through this address. |
| `admin` | `/run/egress/admin.sock` | `--admin`, `EGRESS_PROXY_ADMIN` | The admin socket as an absolute file system path. Use a Unix socket, never a port. The proxy shares the pod network namespace with the workload, so a loopback port would be reachable by that workload. |

The admin socket answers `GET /healthz` with `ok`. It answers `GET /info`
with a JSON object that contains the binary version, `sandbox_id`,
`document_digest`, `overridden`, the listen and limit settings, the CA output
directory and expiry, the endpoint hosts, the cluster ranges, and the deny
list exceptions. The socket has mode 0600 in a directory with mode 0700.

### `ca`

| Key | Default | Flag and variable | Description |
|---|---|---|---|
| `out_dir` | `/shared-ca` | `--ca-out-dir`, `EGRESS_PROXY_CA_OUT_DIR` | The directory where the proxy writes `ca.crt` before it listens. The file has mode 0644, and the directory has mode 0755. The workload mounts the directory read-only and installs the file. The directory contains only the certificate. |
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

### `limits`

| Key | Default | Flag and variable | Description |
|---|---|---|---|
| `max_connections` | `1024` | `--max-connections`, `EGRESS_PROXY_MAX_CONNECTIONS` | The maximum number of simultaneous connections that the CONNECT listener accepts. Further accepts wait until a connection ends. |
| `idle_timeout` | `5m` | `--idle-timeout`, `EGRESS_PROXY_IDLE_TIMEOUT` | The time before the proxy closes a connection that neither reads nor writes. The proxy applies this limit on the frontend, inside a tunnel, and on the upstream connection. It refuses a request head that has not arrived after 10 seconds. |
| `response_header_timeout` | `30s` | `--response-header-timeout`, `EGRESS_PROXY_RESPONSE_HEADER_TIMEOUT` | The time an upstream has to send a response head once the proxy writes the request. A slower upstream gets `upstream_failed`. This limit does not bound a body, so a server-sent event stream runs as long as it stays active. |

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
| `deny_list_exceptions` | `[]` | Ranges that the platform deny list no longer covers. This setting alone can shorten the list. The proxy reports every exception as a warning at start-up. It rejects an exception that covers `169.254.169.254`. |

The binary contains the platform deny list. It includes loopback, RFC 1918,
link-local ranges that contain the cloud metadata address, shared address
space, IPv6 equivalents, cloud metadata host names, and the large public
DNS-over-HTTPS resolvers. The proxy rejects a document that names a covered
host at start-up. It also rejects an allowed name at dial time when the name
resolves into a covered range, with `deny_always`. Exceptions apply only to
addresses. A covered host name remains covered inside an excepted range.

### `endpoints`

The document supplies this section. No flag or environment variable can
change it. The section lists the destinations that the sandbox can reach. The
proxy rejects every other connection or request. An empty list rejects all
connections and requests.

| Key | Default | Description |
|---|---|---|
| `host` | required | A DNS name without a scheme, port, path, or wildcard. Labels hold ASCII letters, digits and hyphens, and the last label is not all digits. The proxy matches the name case-insensitively against the SNI. It rejects an IP literal, because a TLS client sends no SNI for one, and it rejects an address written another way, such as `0177.0.0.1` or `2852039166`, which a resolver still reads as an address. Write an internationalized name as its A-label, the `xn--` punycode form. RFC 6066 section 3 requires the SNI to be ASCII, so a host holding non-ASCII characters never matches what a client sends. |
| `port` | `443` | The one port this endpoint covers on that host. A host reachable on two ports is two endpoints, which also gives each one its own prefix and credential. A CONNECT to any other port on the host is rejected with `no_matching_endpoint`, the same reason an unlisted host gets, because a destination the document does not declare is absent whichever part of it differs. |
| `path_prefix` | `/` | An absolute path in its shortest form. `/` covers every path. A prefix that ends in `/` covers everything below it. Any other prefix covers itself and its child paths as segments. For example, `/api` covers `/api` and `/api/v1`, but not `/apis`. The longest matching prefix decides. Write the prefix as it appears on the wire: the proxy compares it against the escaped path, so a prefix holding a character a client always escapes, such as a space, is rejected because it could never match. |
| `resource` | `https://<host>/` | The resource identifier that the proxy sends to token exchange. Use an absolute `https` URL without user information, a query, or a fragment. Two endpoints can share one resource. |
| `credential` | unset | Defines where the proxy puts a credential and which placeholder the workload holds. See `endpoints[].credential`. |

The proxy decides on the escaped path, the bytes it forwards upstream. An
escaped character is not a separator, so `/a%2Fb` is one segment named `a/b`
and the prefix `/a/` does not cover it. The proxy refuses a path whose
escaped or decoded form carries dot segments, so `/api/%2e%2e/secret`, which
an upstream that decodes first reads as `/secret`, is rejected with
`malformed_request`.

Two endpoints with the same `host`, `port` and `path_prefix` are rejected.
The same host and prefix on two ports are two endpoints, not a repeat.
Endpoints name HTTPS destinations, so a cleartext `http://` request through
the proxy matches no endpoint and is rejected with `no_matching_endpoint`.

#### `endpoints[].credential`

| Key | Description |
|---|---|
| `env` | The environment variable that holds the workload placeholder. Use a valid variable name. |
| `placement.kind` | `header`, `query`, or `basic`. |
| `placement.name` | For `header`, the header name. For `query`, the parameter name. |
| `placement.template` | For `header`, the value with `{credential}` where the proxy puts the credential, such as `Bearer {credential}`. |
| `placement.user` | For `basic`, the user name. The credential becomes the password. |

Until this build has a credential source, the proxy rejects a request to an
endpoint with a credential with `credential_unavailable`. It does not forward
the workload placeholder.

## Decisions and reason codes

The proxy writes one JSON line to stdout for every decision. `scope` is
`connection` for the decision made when a CONNECT arrives. It is `request` for
each request inside the tunnel. `connection_id` joins the two records.
`decision.reason` has one of these values:

| Reason | Verdict | Scope | Meaning |
|---|---|---|---|
| `endpoint_allowed` | allow | both | An endpoint matched. A request record names it in `decision.endpoint`, as `host:port` plus `path_prefix`. The port is always written, so one shape parses every id. A connection record names none, because no path took part in that decision. A connection record is written once the tunnel is established, so it also names the SNI, and a connection the handshake refused never carries an allow. |
| `deny_always` | deny | both | The host is on the platform deny list, or it resolved into a covered range at dial time. |
| `no_matching_endpoint` | deny | both | No endpoint covers the destination: none names the host, one does and none names the port, or one does and none covers the path. Read `scope` to tell those apart. The proxy also uses this reason for every cleartext request. |
| `no_sni` | deny | connection | The TLS handshake inside the tunnel named no server. |
| `host_mismatch` | deny | both | The SNI differs from the CONNECT authority, or the request `Host` header differs from the SNI and port. |
| `malformed_request` | deny | both | The request uses an asterisk-form target, a path whose escaped or decoded form carries dot segments, or a CONNECT authority with a bad port. |
| `not_a_proxy_request` | deny | request | An origin-form request reached the CONNECT listener. The listener does not serve requests of its own. |
| `credential_unavailable` | deny | request | The endpoint names a credential, but this process has no credential source. |
| `upstream_failed` | deny | request | An allowed request produced no response from the upstream. |
| `certificate_unavailable` | deny | connection | The policy allowed the server name and the proxy could not mint a leaf for it. The handshake fails and the tunnel carries no request. |

A refusal carries its reason in the `X-Keycard-Deny-Reason` header. It carries
the connection or request ID in `X-Keycard-Request-Id`. The proxy uses status
403 for a policy refusal, 400 for a malformed or non-proxy request, and 502
when the upstream fails. A refused handshake has no response that can carry a
header. The client sees a TLS failure, and the record names the reason.

The proxy writes JSON logs to stderr. These logs contain no decision. The
audit stream on stdout contains the decision record.
