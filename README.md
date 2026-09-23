# egress-proxy

The Keycard egress proxy intercepts outbound network requests from an untrusted workload controlled by an agent.

It is a forward "man-in-the-middle" (MITM) proxy which terminates TLS and governs outbound connections with Keycard policy, which allows or denies target destinations and replaces placeholder credentials with actual bearer tokens, API keys or other real credentials transparently to the untrusted agent workload.

It proxies HTTP and HTTPS.

This project does not provide workload isolation "sandboxing" or the network configuration necessary for traffic to be forced through the proxy, or for the untrusted workload to trust the proxy's self-signed root CA. This service is designed to be deployed as a component into such a configuration, as a means by which trust can be removed from untrustworthy workloads. See [https://github.com/keycardai/agent-sandbox-poc] for a reference example of such a deployment.

## Run

    go build ./cmd/egress-proxy
    ./egress-proxy --config config.example.yaml --ca-out-dir ./shared-ca --admin /tmp/egress-admin.sock

Every flag also reads an `EGRESS_PROXY_*` variable, so a manifest can set the
per-instance values from the pod's own metadata and share one document.

The proxy listens for `CONNECT` on `127.0.0.1:3128` by default and writes its
CA certificate to the output directory. A client that trusts that certificate
and sets `HTTPS_PROXY=http://127.0.0.1:3128` reaches the endpoints the
document lists and nothing else:

    HTTPS_PROXY=http://127.0.0.1:3128 curl --cacert ./shared-ca/ca.crt https://pypi.org/simple/

Every decision is one JSON line on stdout. Logs are JSON on stderr. The admin
socket answers `/healthz`, `/readyz` and `/info`, and the binary itself dials
it, so a pod needs no shell and no curl to probe the proxy:

    ./egress-proxy --admin /tmp/egress-admin.sock probe info

`docs/configuration.md` describes every key of the document and every reason
code in the audit stream. `docs/security-model.md` states what the proxy
enforces and what it does not.

## Build

    make build      # the binaries
    make all        # build, test, lint, checks, acceptance
    make images     # the three images under images/, built locally

Go 1.27.1 or newer. The build-time tools are `tool` directives in `go.mod`,
built by the `go` command on first use. Nothing else needs installing.

## License

Apache-2.0. See `LICENSE` and, for third-party attributions, `NOTICE`.
