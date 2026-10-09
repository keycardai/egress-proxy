# The init container that programs the capture. Build it from the
# repository root, which is the build context:
#
#   make image-netsetup
#
# It has a shell, unlike the proxy image. The init container runs as root
# with NET_ADMIN, NET_RAW and SETPCAP, and an operator debugging a ruleset
# needs the iptables binaries and a shell to drive them with.
# Base images are pinned by tag and digest. Dependabot updates them.
#
# The build stage runs on the build platform and cross-compiles for the
# target, so a multi-platform build emulates only the apt step.
FROM --platform=$BUILDPLATFORM golang:1.27-trixie@sha256:2f84bc93ecfb2689f782b153fdcd368b5a7ab96c1386c65cdaccf35e726d6a44 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off, so the binary runs on any base image.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/egress-netsetup ./cmd/egress-netsetup

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
# egress-netsetup refuses any iptables binary that reports the nf_tables
# backend, so it resolves the legacy binaries. The iptables package holds
# iptables-legacy, ip6tables-legacy and their restore binaries, and the
# xtables extension libraries they load for -m owner, -m conntrack,
# -m multiport and -m icmp6.
RUN apt-get update \
	&& apt-get install --yes --no-install-recommends iptables \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=build /out/egress-netsetup /usr/local/bin/egress-netsetup
ENTRYPOINT ["/usr/local/bin/egress-netsetup"]
