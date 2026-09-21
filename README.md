# egress-proxy

The Keycard egress proxy intercepts outbound network requests from an untrusted workload controlled by an agent.

It is a forward "man-in-the-middle" (MITM) proxy which terminates TLS and governs outbound connections with Keycard policy, which allows or denies target destinations and replaces placeholder credentials with actual bearer tokens, API keys or other real credentials transparently to the untrusted agent workload.

Currently only HTTP/HTTPS is supported.

This project does not provide workload isolation "sandboxing" or the network configuration necessary for traffic to be forced through the proxy, or for the untrusted workload to trust the proxy's self-signed root CA. This service is designed to be deployed as a component into such a configuration, as a means by which trust can be removed from untrustworthy workloads. See [https://github.com/keycardai/agent-sandbox-poc] for a reference example of such a deployment.

## Build

    make build      # the binaries
    make all        # build, test, lint, checks, acceptance

Go 1.27.1 or newer. The build-time tools are `tool` directives in `go.mod`,
built by the `go` command on first use; nothing else needs installing.

## License

Apache-2.0. See `LICENSE` and, for third-party attributions, `NOTICE`.
