# The init container that programs the capture. Build it from the
# repository root, which is the build context:
#
#   make image-netsetup
#
# It has a shell, unlike the proxy image. The init container runs as root
# with NET_ADMIN, NET_RAW and SETPCAP, and an operator debugging a ruleset
# needs the iptables binaries and a shell to drive them with.
ARG GO_IMAGE=golang:1.27-bookworm
ARG RUNTIME_IMAGE=alpine:3.22

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off, so the binary runs on any base image.
RUN CGO_ENABLED=0 go build -trimpath -o /out/egress-netsetup ./cmd/egress-netsetup

FROM ${RUNTIME_IMAGE}
# egress-netsetup refuses any iptables binary that reports the nf_tables
# backend, so it resolves the legacy binaries. The iptables package holds
# the xtables extension libraries those binaries load for -m owner, -m
# conntrack, -m multiport and -m icmp6. The iptables-legacy package holds
# the binaries themselves.
RUN apk add --no-cache iptables iptables-legacy
COPY --from=build /out/egress-netsetup /usr/local/bin/egress-netsetup
ENTRYPOINT ["/usr/local/bin/egress-netsetup"]
