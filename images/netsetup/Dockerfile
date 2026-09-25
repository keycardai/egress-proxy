# The init container that programs the capture. Build it from the
# repository root, which is the build context:
#
#   make image-netsetup
#
# It has a shell, unlike the proxy image. The init container runs as root
# with NET_ADMIN, NET_RAW and SETPCAP, and an operator debugging a ruleset
# needs the iptables binaries and a shell to drive them with.
# Base images are pinned by tag and digest in literal FROM lines, which is
# the form Dependabot reads and updates.
FROM golang:1.27-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off, so the binary runs on any base image.
RUN CGO_ENABLED=0 go build -trimpath -o /out/egress-netsetup ./cmd/egress-netsetup

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
# egress-netsetup refuses any iptables binary that reports the nf_tables
# backend, so it resolves the legacy binaries. The iptables package holds
# the xtables extension libraries those binaries load for -m owner, -m
# conntrack, -m multiport and -m icmp6. The iptables-legacy package holds
# the binaries themselves.
RUN apk add --no-cache iptables iptables-legacy
COPY --from=build /out/egress-netsetup /usr/local/bin/egress-netsetup
ENTRYPOINT ["/usr/local/bin/egress-netsetup"]
