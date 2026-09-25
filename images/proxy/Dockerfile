# The setcap step on top of the image ko built. ko has no setcap step and
# the distroless base has no shell, so the capability goes on in a stage
# that has libcap2-bin and the binary is copied back. COPY between stages
# keeps the security.capability extended attribute.
#
# Build both steps with:
#   make image-proxy
#
# KO_IMAGE is the reference ko loaded. `make image-proxy` builds it first
# and passes it here, so ko still chooses the base image, compiles the
# binary and places it at /ko-app/egress-proxy.
#
# cap_net_bind_service is what lets the proxy bind listen.transparent below
# 1024. The +ep form puts it in the permitted and effective sets of
# whatever uid execs the binary, drawn from the bounding set. The pod fills
# that set with capabilities.add NET_BIND_SERVICE. docs/containers.md
# states why both halves are needed.
#
# The setcap base is pinned by tag and digest in a literal FROM line, which
# is the form Dependabot reads and updates.
ARG KO_IMAGE

FROM ${KO_IMAGE} AS ko

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS setcap
RUN apt-get update \
	&& apt-get install --yes --no-install-recommends libcap2-bin \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=ko /ko-app/egress-proxy /ko-app/egress-proxy
RUN setcap cap_net_bind_service=+ep /ko-app/egress-proxy \
	&& getcap /ko-app/egress-proxy | grep -q cap_net_bind_service

FROM ${KO_IMAGE}
COPY --from=setcap /ko-app/egress-proxy /ko-app/egress-proxy
