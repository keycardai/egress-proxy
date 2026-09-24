# Containers

What this repository ships and what each container it ships needs. Whoever
composes a pod reads this to place the proxy and the init container
correctly.

This repository does not decide the pod. The workload container, the volume
ownership settings and the pod-level namespace settings belong to the
sandbox composition, which lives with the charts and is checked by their
lint. Where a requirement below holds only because something outside this
repository enforces it, the text says so and names the enforcer.

`docs/configuration.md` defines every setting named here.
`docs/security-model.md` states what each surface defends against.

## The three images

| Image | Built by | What is in it |
|---|---|---|
| proxy | `make image-proxy`, ko from `images/proxy/.ko.yaml` and then `images/proxy/Dockerfile` | `gcr.io/distroless/static-debian12:nonroot`, the `egress-proxy` binary with `cap_net_bind_service=+ep` on it, and the public root certificates it verifies upstreams and the zone against. No shell and no package manager. |
| netsetup | `make image-netsetup`, `images/netsetup/Dockerfile` with the repository root as its build context | Alpine, the `egress-netsetup` binary, the legacy `iptables` and `ip6tables` binaries with their xtables extension libraries, and a shell. |
| sandbox-base | `make image-sandbox-base`, `images/sandbox-base/Dockerfile` | Debian bookworm-slim, `ca-certificates`, `openssl`, `curl`, `git`, `python3`, `nodejs`, the agent uid and `keycard-sandbox-entrypoint`. An agent image builds `FROM` this one. |

`make images` builds all three locally and drives what each one does, under
`test/images`. Nothing in this repository pushes an image. Publishing is a
release step.

## The proxy container

Runs `egress-proxy` with no subcommand, which reads the configuration
document and serves.

**uid.** The proxy runs as a uid of its own, the same one
`egress-netsetup --proxy-uid` is given. `egress-proxy settings` publishes
the default, 1337. The capture leaves that uid's own traffic alone, so the
proxy can reach an upstream. That separation holds only while the workload
runs as a different uid, which this binary does not check and the chart
lint does.

The image's own user is the distroless nonroot uid, 65532, so a manifest
that wants the proxy on the uid the capture exempts sets `runAsUser`
itself.

**Capabilities.** `NET_BIND_SERVICE`, and nothing else. The proxy programs
no rule and reads no other process.

    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]

The capability is what lets the proxy bind `listen.transparent` below 1024.
The redirect port the init container programs is 1015, and a port below
1024 is one an unprivileged workload cannot bind during a sidecar restart
to stand in for the proxy.

It takes both the image and the pod. The image holds
`cap_net_bind_service=+ep` on `/ko-app/egress-proxy`, so the kernel puts the
capability in the permitted and effective sets of whatever uid execs the
binary. A permitted file capability is drawn from the bounding set, and the
pod is what fills that set.

Neither half works alone. Without the file capability a non-root container
holds an added capability in its bounding set and nothing else
(kubernetes/kubernetes#56374), so the bind is refused. Without the pod
grant, the capability is outside the bounding set and the kernel refuses
the exec itself with `operation not permitted`. The file capability still
applies under `allowPrivilegeEscalation: false`, which is what sets
`no_new_privs`, and `test/images` proves that.

**NEVER give the proxy container `drop: ["ALL"]` without
`add: ["NET_BIND_SERVICE"]`**, whatever `listen.transparent` is set to. The
capability is a property of the binary, so a bounding set without it stops
the container before `main` runs, with `listen.transparent` unset as much
as with it set.

**Volumes and paths.**

| Path | Setting | What it is |
|---|---|---|
| the document | `--config`, `EGRESS_PROXY_CONFIG` | The configuration document, read once at start-up, read-only. |
| `/shared-ca/out` | `ca.out_dir` | Where the proxy writes `ca.crt`. The workload reads the same volume and trusts that file. It holds the certificate and nothing else. |
| the CA state directory | `ca.state_dir` | Where the CA key is held across restarts. It must be memory-backed, and the proxy refuses to start when it is not. NEVER mount it into another container, and NEVER place it under `ca.out_dir`. |
| `/run/egress/admin/admin.sock` | `listen.admin` | The admin socket. The proxy sets its directory to mode 0700 on every start and refuses to start when the directory does not end up at that mode. |
| `/run/egress/netsetup/netsetup.json` | `netsetup.receipt` | What the init container recorded. The proxy reads it and refuses to serve a transparent frontend without it. |
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

Whether the workload can also read the token, the secret or the CA key is a
property of the pod. The chart lint decides it.

**Probes.** All three run the binary, because the admin surface is a Unix
socket in this container's mount namespace. An `httpGet` probe has nothing
to dial, and the image has no shell and no curl to dial it with. ko puts
the binary at `/ko-app/egress-proxy`, which is the path an `exec` probe
names.

| Probe | Command | What it says |
|---|---|---|
| startup | `/ko-app/egress-proxy probe readyz` | Every frontend is bound and `ca.crt` is written. The kubelet holds the workload until this passes. |
| readiness | `/ko-app/egress-proxy probe readyz` | The same answer while the process runs. |
| liveness | `/ko-app/egress-proxy probe healthz` | The process is alive. Liveness NEVER reads `readyz`: a proxy that is still starting would be restarted for it. |

`egress-proxy probe <healthz|readyz|info>` dials the socket named by
`--admin` or `EGRESS_PROXY_ADMIN`, prints the answer and exits non-zero on
anything but a 200.

## The netsetup init container

Runs `egress-netsetup`, which programs the capture rules, reads them back,
gives up `CAP_NET_ADMIN` and writes the receipt. It exits. It is an
ordinary init container that runs to completion, not a sidecar.

**uid and capabilities.** Root, with `NET_ADMIN`, `NET_RAW` and `SETPCAP`.
`NET_ADMIN` programs the rules, `NET_RAW` is what the `iptables` binaries
open their raw socket with, and `SETPCAP` is what lets the process drop
`NET_ADMIN` from its own bounding set before it writes the receipt.

**Volumes.** The receipt directory, shared with the proxy container and
memory-backed. The proxy refuses a receipt any other uid can write, and
refuses one whose directory any other uid can write.

**Settings.** `egress-netsetup` reads flags only and no environment
variable. The defaults a pod has to agree with are in
`egress-proxy settings` under `netsetup`: the proxy uid, the redirect port,
the captured ports and the receipt path. `--proxy-uid` and the proxy
container's `runAsUser` name the same uid, and `--redirect-port` and
`listen.transparent` name the same port.

## The sandbox-base image

An agent image builds `FROM` this one, and every client it runs then trusts
the proxy with nothing in the pod manifest. Three parts of the image do
that:

1. `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`
   and `GIT_SSL_CAINFO` all name one bundle. `NODE_EXTRA_CA_CERTS` names
   the sidecar's certificate directly, because Node bundles its own
   OpenSSL.
2. `keycard-sandbox-entrypoint` waits for `/shared-ca/ca.crt`, parses it,
   installs it as a system anchor and runs `update-ca-certificates`. It
   refuses to start the agent without it. The wait covers a restart that
   outlives the sidecar's startup probe.
3. The agent uid owns `/usr/local/share/ca-certificates` and
   `/etc/ssl/certs`, so `update-ca-certificates` runs unprivileged.

A variable is set only for a client the image installs. The image installs
no AWS client, so it sets no `AWS_CA_BUNDLE`. An image built on this one
that adds a client sets that client's variable itself.

The pod mounts `/shared-ca` read-only and the image needs no capability.
`AGENT_UID`
is a build argument, and an image that changes it is built for a pod that
runs the workload as that uid.

## The settings the binary accepts

`egress-proxy settings` prints them as JSON, with no document and no socket,
so a chart lint can read them out of the image it is about to deploy:

    docker run --rm <proxy image> settings

Each entry names the `EGRESS_PROXY_` variable, the flag that fills the same
setting, what it sets, and the value the document parser applies when
neither is set. A duration default is a JSON number of whole seconds, so
`--leaf-ttl` publishes `86400` rather than a string a consumer has to
parse. Every other default is a string, and `null` says the parser leaves
the setting empty. The report also names the probe subcommand and its
routes, and the netsetup defaults above. `schema` is the version of the
shape: a field is added without changing it, and a field that changes
meaning or goes away raises it.

A flag wins over its variable, and both win over the document. The
endpoints and the `policy` section come from the document alone and have no
variable, because an audit record has to name every rule that was in force.
`config.digest` covers the settings after an override applies, and the
process announces every overridden key on every start.

## What the proxy checks for itself

These are the checks that refuse to serve. They are not a substitute for
the pod being composed correctly, and each says what it can see from inside
the container.

- **The netsetup receipt.** With `listen.transparent` set, the proxy reads
  the receipt before it serves. It refuses a receipt that says the rules
  were not read back, one whose proxy uid or redirect port disagrees with
  its own, one that names no address family, one that says
  `CAP_NET_ADMIN` was kept, and one that any other uid can write. It also
  refuses to serve while this process holds `CAP_NET_ADMIN`.
- **`net.ipv4.ip_unprivileged_port_start`.** The redirect target is below
  1024 so the workload cannot bind it. That rests on the sysctl, so the
  proxy reads it at start-up rather than trusting the manifest and refuses
  to start when it is at or below the redirect port. containerd sets the
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
- **The admin socket directory.** Set to mode 0700 on every start, read
  back, and a directory that does not end up at that mode stops the
  process.
