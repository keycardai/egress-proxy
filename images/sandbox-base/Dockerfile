# The sandbox base image. An agent image builds FROM this one, and every
# client it runs then trusts the proxy with nothing in the pod manifest.
#
# Build it with:
#   make image-sandbox-base
#   docker build --build-arg AGENT_UID=1000 images/sandbox-base
#
# Three parts of the image do the trusting, so the manifest carries none of
# it:
#
#   1. The environment variables below name one bundle, and every client in
#      the image reads one of them.
#   2. The entrypoint waits for the sidecar's certificate, installs it as a
#      system anchor and runs update-ca-certificates, which covers the
#      clients that read the system store rather than a variable.
#   3. The agent uid owns the trust store. The workload container runs with
#      runAsNonRoot, allowPrivilegeEscalation false and every capability
#      dropped, so update-ca-certificates cannot become root and the
#      directories it writes must already belong to the uid it runs as.
ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}

# AGENT_UID must equal the pod's workload securityContext.runAsUser. The
# build hands the trust store to it, and the netsetup owner match tells this
# uid apart from the sidecar's.
ARG AGENT_UID=1000
ARG AGENT_GID=1000
ARG AGENT_USER=agent
# The volume the sidecar writes its certificate to, mounted read-only here.
ARG SHARED_CA_FILE=/shared-ca/ca.crt

ENV DEBIAN_FRONTEND=noninteractive

# openssl provides the x509 parse the entrypoint validates the certificate
# with, and ca-certificates provides update-ca-certificates. curl, python3
# and nodejs are the clients a sandbox reaches an endpoint with.
RUN apt-get update \
	&& apt-get install --yes --no-install-recommends \
		ca-certificates \
		openssl \
		curl \
		python3 \
		nodejs \
	&& rm -rf /var/lib/apt/lists/*

RUN groupadd --gid "${AGENT_GID}" "${AGENT_USER}" \
	&& useradd --uid "${AGENT_UID}" --gid "${AGENT_GID}" --create-home --shell /bin/sh "${AGENT_USER}"

# update-ca-certificates rewrites the bundle and the hash links in place.
# The agent uid owns both directories so it can run unprivileged. A workload
# that edits its own trust store gains nothing: the proxy decides egress,
# and removing the proxy's certificate only breaks the workload's own TLS.
RUN chown -R "${AGENT_UID}:${AGENT_GID}" /usr/local/share/ca-certificates /etc/ssl/certs

COPY keycard-sandbox-entrypoint /usr/local/bin/keycard-sandbox-entrypoint
RUN chmod 0755 /usr/local/bin/keycard-sandbox-entrypoint

# One bundle, named for every client that reads a variable rather than the
# system store. SSL_CERT_FILE and SSL_CERT_DIR cover OpenSSL and everything
# linked against it, REQUESTS_CA_BUNDLE covers Python requests,
# CURL_CA_BUNDLE covers libcurl, AWS_CA_BUNDLE covers botocore and the AWS
# CLI, and GIT_SSL_CAINFO covers git.
#
# Node bundles its own OpenSSL and ignores the system store unless
# --use-openssl-ca tells it to read it. NODE_EXTRA_CA_CERTS names the
# sidecar's certificate directly, so Node trusts the proxy under either
# setting.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
	SSL_CERT_DIR=/etc/ssl/certs \
	REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
	CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
	AWS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
	GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt \
	NODE_EXTRA_CA_CERTS=${SHARED_CA_FILE} \
	NODE_OPTIONS=--use-openssl-ca \
	KEYCARD_CA_FILE=${SHARED_CA_FILE}

USER ${AGENT_UID}:${AGENT_GID}
WORKDIR /home/${AGENT_USER}

ENTRYPOINT ["/usr/local/bin/keycard-sandbox-entrypoint"]
CMD ["/bin/sh", "-c", "echo 'sandbox base image: pass the agent command as the container args' >&2; exit 64"]
