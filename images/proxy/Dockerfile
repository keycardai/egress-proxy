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
ARG KO_IMAGE
ARG SETCAP_IMAGE=debian:bookworm-slim

FROM ${KO_IMAGE} AS ko

FROM ${SETCAP_IMAGE} AS setcap
RUN apt-get update \
	&& apt-get install --yes --no-install-recommends libcap2-bin \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=ko /ko-app/egress-proxy /ko-app/egress-proxy
RUN setcap cap_net_bind_service=+ep /ko-app/egress-proxy \
	&& getcap /ko-app/egress-proxy | grep -q cap_net_bind_service

FROM ${KO_IMAGE}
COPY --from=setcap /ko-app/egress-proxy /ko-app/egress-proxy
