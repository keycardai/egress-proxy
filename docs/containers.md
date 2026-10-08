# Containers

What this repository ships and what each container needs. Use it to place
the proxy and the init container in a pod.

The pod spec is not defined here. The workload container, the volume
ownership settings and the pod-level namespace settings belong to the
sandbox composition, which lives with the charts and is checked by their
lint. Where a requirement below holds only because something outside this
repository enforces it, the text says so and names the enforcer.

`docs/configuration.md` defines every setting named here.
`docs/security-model.md` states what each surface defends against.

## The three images

| Image | Built by | What is in it |
|---|---|---|
| proxy | `make image-proxy`, ko from `images/proxy/.ko.yaml` and then `images/proxy/Dockerfile` | `gcr.io/distroless/static-debian13:nonroot`, the `egress-proxy` binary with `cap_net_bind_service=+ep` on it, and the public root certificates it verifies upstreams and the zone against. No shell and no package manager. |
| netsetup | `make image-netsetup`, `images/netsetup/Dockerfile` with the repository root as its build context | Debian trixie-slim, the `egress-netsetup` binary, the legacy `iptables` and `ip6tables` binaries with their xtables extension libraries, and a shell. |
| sandbox-base | `make image-sandbox-base`, `images/sandbox-base/Dockerfile` | Debian trixie-slim, `ca-certificates`, `openssl`, `curl`, `git`, `python3` with `python3-requests`, `nodejs`, the agent uid and `keycard-sandbox-entrypoint`. An agent image builds `FROM` this one. |

`make images` builds all three locally and checks each one in a container,
under `test/images`.

## Published images

Every push to main publishes the three images for linux/amd64 and
linux/arm64, from the same definitions:

| Image | Reference |
|---|---|
| proxy | `ghcr.io/keycardai/egress-proxy` |
| netsetup | `ghcr.io/keycardai/egress-netsetup` |
| sandbox-base | `ghcr.io/keycardai/sandbox-base` |

The `main` tag follows the latest push to main. A release adds its version
tag, `vX.Y.Z`, and attaches `digests.txt` to the GitHub release with the
digest of each image. Tags move, so a manifest names an image by digest.

Each image index carries an SPDX SBOM and a SLSA provenance attestation:

    docker buildx imagetools inspect ghcr.io/keycardai/egress-proxy@sha256:... --format '{{json .SBOM}}'

Each index, platform manifest and attestation is signed with cosign,
keylessly, by the release workflow. Verify a digest against that identity:

    cosign verify ghcr.io/keycardai/egress-proxy@sha256:... \
      --certificate-identity https://github.com/keycardai/egress-proxy/.github/workflows/release.yml@refs/heads/main \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com

## The proxy container

Runs `egress-proxy` with no subcommand, which reads the configuration
document and serves. The binary is the container's entrypoint.

The proxy is a sidecar: an entry in `initContainers` with
`restartPolicy: Always`, listed after the netsetup init container. The
kubelet starts the next container only once a sidecar's startup probe
passes (https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/),
so the workload waits for the proxy. A proxy under `containers` starts
beside the workload, and its probes hold nothing back.

**uid.** The proxy runs as a uid of its own, the same one
`egress-netsetup --proxy-uid` is given. `egress-proxy settings` publishes
the default, 1337. The capture leaves that uid's own traffic alone, so the
proxy can reach an upstream. That separation holds only while the workload
runs as a different uid, which this binary does not check and the chart
lint does.

The image's own user is the distroless nonroot uid, 65532, so a manifest
that wants the proxy on the uid the capture exempts sets `runAsUser`
itself.

**Capabilities.** `NET_BIND_SERVICE`, and nothing else. The proxy does not
program rules or read another process.

    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]

The capability lets the proxy bind `listen.transparent_port` and
`listen.dns`, both below 1024. The default redirect port is 1015 and the
resolver port is 53. An unprivileged workload cannot bind a port below
1024, so it cannot take over either port during a sidecar restart.

This needs both the image and the pod. The image has
`cap_net_bind_service=+ep` on `/ko-app/egress-proxy`, so the kernel puts the
capability in the permitted and effective sets of whatever uid execs the
binary. A permitted file capability is drawn from the bounding set, and the
pod fills that set.

Neither half works alone. Without the file capability a non-root container
holds an added capability in its bounding set and nothing else
(kubernetes/kubernetes#56374), so the bind is refused. Without the pod
grant, the capability is outside the bounding set and the kernel refuses
the exec itself with `operation not permitted`.

The file capability also holds under `allowPrivilegeEscalation: false`. The
runtime puts the added capability in the permitted set of the process that
execs the entrypoint, and `no_new_privs` keeps what that process held.
`docs/security-model.md` gives the sources, and `test/images` runs the image
under `no_new_privs`. **NEVER start the binary from a shell under
`allowPrivilegeEscalation: false`.** The shell does not hold the
capability to pass on, and the bind is refused.

**NEVER give the proxy container `drop: ["ALL"]` without
`add: ["NET_BIND_SERVICE"]`**, whatever `listen.transparent_port` is set
to. The capability is on the binary, so a bounding set without it stops the
container before `main` runs, even when `listen.transparent_port` is unset.

**Volumes and paths.**

| Path | Setting | What it is |
|---|---|---|
| the document | `--config`, `EGRESS_PROXY_CONFIG` | The configuration document, read once at start-up, read-only. |
| `/shared-ca/out` | `ca.out_dir` | Where the proxy writes `ca.crt`. The workload reads the same volume and trusts that file. It holds the certificate and nothing else. |
| the CA state directory | `ca.state_dir` | Where the CA key is held across restarts. It must be memory-backed, and the proxy refuses to start when it is not. NEVER mount it into another container, and NEVER place it under `ca.out_dir`. |
| `/run/egress/admin/admin.sock` | `listen.admin` | The admin socket. The proxy sets its directory to mode 0700 on every start and refuses to start when the directory does not end up at that mode. |
| `/run/egress/netsetup/netsetup.json` | `netsetup.receipt` | What the init container recorded: the ruleset, the ports it redirects and the cluster resolvers. The proxy reads it and refuses to serve a transparent frontend without it. |
| the projected token | `identity.workload_token_file` | The ServiceAccount token the exchange authenticates with, when the document names workload identity. |
| the client secret | `identity.client_secret_file` | The application credential secret, when the document names one. It must be readable by its owner alone. |

Every path the proxy sets a mode on is a directory inside a volume, never
the mount point. The kubelet creates a mount point owned by root at mode
0777, and the proxy runs as a uid of its own, so a chmod of the mount point
fails with EPERM and the sidecar never starts. Mount the volume and let the
proxy create `out` and `admin` under it. The receipt directory is separate
from the admin socket directory: the proxy takes the admin socket directory
to 0700, and the init container writes the receipt as root into a directory
the proxy has to traverse.

Whether the workload can also read the token, the secret or the CA key
depends on the pod spec. The chart lint checks it.

**Probes.** All three run the binary, because the admin surface is a Unix
socket in this container's mount namespace. An `httpGet` probe has nothing
to dial, and the image has no shell and no curl to dial it with. ko puts
the binary at `/ko-app/egress-proxy`, which is the path an `exec` probe
names.

| Probe | Command | What it says |
|---|---|---|
| startup | `/ko-app/egress-proxy probe readyz` | Every frontend is bound and `ca.crt` is written. The workload starts once this passes. |
| readiness | `/ko-app/egress-proxy probe readyz` | The same answer while the process runs. |
| liveness | `/ko-app/egress-proxy probe healthz` | The process is alive. Liveness NEVER reads `readyz`: a proxy that is still starting would be restarted for it. |

`egress-proxy probe <healthz|readyz|info>` connects to the admin socket,
prints the response, and exits non-zero unless the status is 200. It gets
the socket path from `--admin` or `EGRESS_PROXY_ADMIN`, or uses the
default. It does not read the configuration document.

To move the socket, set `EGRESS_PROXY_ADMIN` on the proxy container. If you
set `listen.admin` in the document instead, the proxy listens on the new
path but the probe still connects to the default. The startup probe fails
and the workload never starts.

## The netsetup init container

Runs `egress-netsetup`, which programs the capture rules, reads them back,
gives up `CAP_NET_ADMIN` and writes the receipt. It exits. It is an
ordinary init container that runs to completion, not a sidecar, and it is
listed before the proxy.

**uid and capabilities.** Root, with `NET_ADMIN`, `NET_RAW` and `SETPCAP`.
`NET_ADMIN` programs the rules. The `iptables` binaries need `NET_RAW` to
open their raw socket. `SETPCAP` lets the process drop `NET_ADMIN` from its
own bounding set before it writes the receipt.

**Volumes.** The receipt directory, shared with the proxy container and
memory-backed. The proxy refuses a receipt that group or other can write,
and a receipt or directory owned by a uid other than root and its own.

**Settings.** `egress-netsetup` reads only flags, not environment
variables. The defaults a pod has to agree with are in
`egress-proxy settings` under `netsetup`: the proxy uid, the redirect port,
the captured ports, the DNS port and the receipt path. `--proxy-uid` and
the proxy container's `runAsUser` name the same uid, `--redirect-port` and
`listen.transparent_port` name the same port, and `--dns-port` and `listen.dns`
name the same port. The proxy refuses to start when any of the three
disagree.

## Name resolution

The init container redirects UDP and TCP port 53 to `listen.dns`. The
filter chain does not accept DNS to any resolver. Every lookup the workload
makes reaches the sidecar's resolver, whatever resolver the client named.
A query the redirect missed reaches the terminal DROP.
The resolver answers `NXDOMAIN` for a name that is not an endpoint host or
the zone host and forwards the rest to the cluster resolvers.

**Leave the pod's resolver configuration alone.** Use the default
`dnsPolicy: ClusterFirst`. The redirect already sends every query to the
resolver. A pod that sets `dnsPolicy: None` with
`nameservers: [127.0.0.1]` points every container at the loopback
listener, the init container included. The init container then records
the loopback address as the cluster resolver, and the proxy refuses to
start, because it would forward every allowed name to itself.

**The resolvers the sidecar forwards to** come from the receipt, which
holds what the init container read from `/etc/resolv.conf`. To name them
another way, set `dns.forward_to` on the proxy. To run without a resolver,
leave `listen.dns` unset and run the init container with `--dns-port 0`.

A name in `/etc/hosts` does not need a resolver. Debian
resolves `files` before `dns`, so a `hostAliases` entry still works.

## The sandbox-base image

An agent image builds `FROM` this one, and every client in it trusts the
proxy without any setting in the pod manifest. Three parts of the image
set this up:

1. `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`
   and `GIT_SSL_CAINFO` all name one bundle. `NODE_EXTRA_CA_CERTS` names
   the sidecar's certificate directly, because Node bundles its own
   OpenSSL.
2. `keycard-sandbox-entrypoint` waits for the file `KEYCARD_CA_FILE`
   names, parses it, installs it as a system anchor and runs
   `update-ca-certificates`. It refuses to start the agent without it. The
   wait covers a restart that outlives the sidecar's startup probe.
3. The agent uid owns `/usr/local/share/ca-certificates` and
   `/etc/ssl/certs`, so `update-ca-certificates` runs unprivileged. A pod
   with `readOnlyRootFilesystem: true` mounts a writable volume owned by
   the agent uid at each of the two directories. It does not need a
   writable `/tmp`.

A variable is set only for a client the image installs. The image does not
install an AWS client, so it does not set `AWS_CA_BUNDLE`. An image built
on this one that adds a client sets that client's variable itself.
`test/images` reads `Config.Env` from the built image and checks that
every variable naming a trust store belongs to a client the image installs.

`KEYCARD_CA_FILE` and `NODE_EXTRA_CA_CERTS` default to
`/shared-ca/out/ca.crt`, which is `ca.out_dir` above with `ca.crt` under
it. A pod that takes both defaults does not need to set either variable.
If one moves, the agent waits for a file the sidecar never writes and exits
69, so a pod that sets `ca.out_dir` sets `KEYCARD_CA_FILE` to match.
`test/images` pins the two paths together by mounting the certificate at
the published default with no variable set.

The pod mounts `/shared-ca` read-only, and the image does not need any
capability. `AGENT_UID` is a build argument, and an image that changes it
is built for a pod that runs the workload as that uid.

## The settings the binary accepts

`egress-proxy settings` prints them as JSON, with no document and no socket,
so a chart lint can read them out of the image it is about to deploy:

    docker run --rm <proxy image> settings

The file capability applies to every run of the binary, this subcommand
included. If `NET_BIND_SERVICE` is outside the bounding set, the kernel
refuses the exec. Docker's default set has `NET_BIND_SERVICE`, so the
command above works as written. A lint that runs the image under
`drop: ["ALL"]` must add `NET_BIND_SERVICE` back, or the container does not
start.

Each entry names the `EGRESS_PROXY_` variable, the flag that fills the same
setting, what it sets, and the value the document parser applies when
neither is set. A duration default is a JSON number of whole seconds, so
`--leaf-ttl` publishes `86400` rather than a string a consumer has to
parse. Every other default is a string, and `null` says the parser leaves
the setting empty. The report also names the probe subcommand and its
routes, and the netsetup defaults above. `schema` is the report's format
version. Adding a field does not change it. Changing a field's meaning or
removing a field raises it.

A flag wins over its variable, and both win over the document. The
endpoints and the `policy` section come from the document alone and have no
variable, because an audit record has to name every rule that was in force.
`config.digest` covers the settings after an override applies, and the
process announces every overridden key on every start.

## What the proxy checks for itself

The proxy refuses to start when one of these checks fails. They do not
replace a correct pod spec. Each one says what the proxy can see from
inside the container.

- **The netsetup receipt.** With `listen.transparent_port` set, the proxy reads
  the receipt before it serves. It refuses a receipt that says the rules
  were not read back, one whose proxy uid, redirect port or DNS port
  disagrees with its own, one that does not name an address family, one
  that says `CAP_NET_ADMIN` was kept, and one that any other uid can write. It also
  refuses to serve while this process holds `CAP_NET_ADMIN`.
- **The resolver's forward targets.** The proxy refuses a `dns.forward_to`
  entry that names its own listen address, which would forward every
  allowed name to itself, and one that is a name rather than an address.
  With `listen.dns` set and no resolver named anywhere, it refuses to
  start.
- **`net.ipv4.ip_unprivileged_port_start`.** The redirect target and the
  resolver port are below 1024 so the workload cannot bind either. That
  rests on the sysctl, so the proxy reads it at start-up rather than
  trusting the manifest and refuses to start when it is at or below the
  higher of the two. containerd sets the
  sysctl to 0 in a pod sandbox, and Docker sets it to 0 too, so the refusal
  fires on every pod that has not set it. A pod that wants this mitigation
  sets it itself:

      securityContext:
        sysctls:
          - name: net.ipv4.ip_unprivileged_port_start
            value: "1024"

  It is on the kubelet's safe sysctl list, so no node configuration and no
  `--allowed-unsafe-sysctls` is needed. Under Docker, run the container
  with `--sysctl net.ipv4.ip_unprivileged_port_start=1024`.
- **The CA state directory.** The proxy checks the file system type and
  refuses a `ca.state_dir` that is not memory-backed, and refuses one that
  overlaps `ca.out_dir`, before any key exists.
- **The admin socket directory.** The proxy sets it to mode 0700 on
  every start, reads the mode back, and stops if it is not 0700.
