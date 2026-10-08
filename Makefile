# Every target here is also a CI step. Keep the two the same gate.

GO ?= go
export GOTOOLCHAIN ?= auto

.PHONY: help
help:
	@echo "build           go build ./..."
	@echo "test            go vet and go test -race ./..., including the gate self-tests"
	@echo "lint            golangci-lint (with the depguard import gate), the version go.mod pins"
	@echo "checks          license allow-list, NOTICE freshness and govulncheck"
	@echo "acceptance      the acceptance tests under test/acceptance, which drive the built binary"
	@echo "e2e             the e2e tests under test/e2e, on a k3d cluster"
	@echo "images          build the three images locally and check each one"
	@echo "publish         build the three images for every platform and push them, PUBLISH_TAGS required"
	@echo "sign            sign the images publish pushed with cosign, by digest"
	@echo "notice          regenerate NOTICE from the build list"
	@echo "tidy            go mod tidy"
	@echo "all             build, test, lint, checks, acceptance, in gate order"

.PHONY: build
build:
	$(GO) build ./...

# The test suites behind a build tag are named here, so vet covers them too.
.PHONY: vet
vet:
	$(GO) vet -tags acceptance,e2e,images ./...

# The gate self-tests under test/gates run the gate scripts against their
# negative fixtures, so this target builds the tools. -short skips them.
.PHONY: test
test: vet
	$(GO) test -race ./...

.PHONY: lint
lint:
	./scripts/lint.sh

.PHONY: fmt
fmt:
	$(GO) tool golangci-lint fmt ./...

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: checks
checks: check-licenses check-notice vuln

.PHONY: check-licenses
check-licenses:
	./scripts/check-licenses.sh

.PHONY: check-notice
check-notice:
	./scripts/notice.sh --check

.PHONY: vuln
vuln:
	./scripts/vuln.sh

.PHONY: notice
notice:
	./scripts/notice.sh

# The acceptance tests build the binary and drive it from Go, one testscript
# per scenario under test/acceptance/testdata, named for what it proves. They
# are behind the acceptance build tag so `go test ./...` never runs binaries.
# Every scenario runs on every commit, so a later change cannot silently
# regress an earlier one.
.PHONY: acceptance
acceptance:
	$(GO) test -tags acceptance -count=1 ./test/acceptance/...

# The e2e tests, on sigs.k8s.io/e2e-framework with support/k3d. It builds
# the images, creates a k3d cluster, imports them, applies a sandbox pod and
# drives requests from inside the agent container. It is behind the e2e
# build tag so `go test ./...` never starts a cluster, and it skips with a
# message when Docker or k3d is missing.
.PHONY: e2e
e2e:
	$(GO) test -tags e2e -count=1 ./test/e2e/...

# The three images, built locally. ko builds the proxy straight from the
# module. The other two are Dockerfiles, and the netsetup one takes the
# repository root as its build context. Nothing here pushes: `publish`
# below is the release step.
IMAGE_TAG ?= dev

# The reference the proxy image ends up under.
PROXY_IMAGE ?= egress-proxy:$(IMAGE_TAG)

# The intermediate image ko builds and the setcap step reads. ko also tags
# it with its digest. The recipe removes both tags when it finishes. Do not
# override this: the binary in that image does not have the capability, so
# nothing outside this recipe may run it.
PROXY_KO_IMAGE = ko.local:$(IMAGE_TAG)-ko

# Two steps. ko compiles the binary and builds the distroless image, then
# images/proxy/Dockerfile puts cap_net_bind_service=+ep on the binary,
# which ko has no step for. test/images runs this target, so the image
# tests check the image the release builds.
#
# SOURCE_DATE_EPOCH keeps the created timestamp of the final image at the
# epoch, which is the timestamp ko gives the image it loads. The file
# timestamps inside the layers keep the values the setcap stage wrote.
#
# Both ko references are removed whether or not the setcap build succeeds.
# The recipe exits with the build's status, then with the removal's.
.PHONY: image-proxy
image-proxy:
	ko_ref=$$(KO_CONFIG_PATH=images/proxy KO_DOCKER_REPO=ko.local $(GO) tool ko build --local --bare \
		--tags $(IMAGE_TAG)-ko --platform linux/$(shell $(GO) env GOARCH) ./cmd/egress-proxy) || exit $$?; \
	build_status=0; \
	SOURCE_DATE_EPOCH=0 docker build -f images/proxy/Dockerfile --build-arg KO_IMAGE=$(PROXY_KO_IMAGE) \
		-t $(PROXY_IMAGE) images/proxy || build_status=$$?; \
	rm_status=0; \
	docker image rm $(PROXY_KO_IMAGE) "$$ko_ref" || rm_status=$$?; \
	[ $$build_status -eq 0 ] || exit $$build_status; \
	exit $$rm_status

.PHONY: image-netsetup
image-netsetup:
	docker build -f images/netsetup/Dockerfile -t egress-netsetup:$(IMAGE_TAG) .

.PHONY: image-sandbox-base
image-sandbox-base:
	docker build -t sandbox-base:$(IMAGE_TAG) images/sandbox-base

# The image tests build all three and checks each one in a container: the
# proxy image answers `probe`, the netsetup image resolves the legacy
# iptables binaries, and the base image entrypoint installs a certificate
# from a fake /shared-ca. It skips when no Docker daemon answers.
.PHONY: images
images:
	$(GO) test -tags images -count=1 -timeout 30m ./test/images/...

# Publishing. The release workflow runs `publish` and then `sign`. publish
# builds the same three definitions for every platform in PLATFORMS and
# pushes them under each tag in PUBLISH_TAGS, with an SBOM and a provenance
# attestation in each image index. It needs a docker-container buildx
# builder, and emulation for every platform that is not the host's.
# It records each digest under PUBLISH_DIR, and sign reads them back, so
# a signature names the digest that was pushed and never a tag.
REGISTRY ?= ghcr.io/keycardai
PUBLISH_TAGS ?=
PLATFORMS ?= linux/amd64,linux/arm64
PUBLISH_DIR ?= dist/publish
IMAGE_SOURCE ?= https://github.com/keycardai/egress-proxy
IMAGE_REVISION ?= $(shell git rev-parse HEAD)
PUBLISHED_IMAGES = egress-proxy egress-netsetup sandbox-base

# The buildx flags every published image takes. $(1) is the image name.
# The annotations name the source repository, which links the package to
# it on ghcr.io.
publish_args = --platform $(PLATFORMS) --sbom=true --provenance=mode=max --push \
	$(foreach t,$(PUBLISH_TAGS),--tag $(REGISTRY)/$(1):$(t)) \
	--annotation "index,manifest:org.opencontainers.image.source=$(IMAGE_SOURCE)" \
	--annotation "index,manifest:org.opencontainers.image.revision=$(IMAGE_REVISION)" \
	--annotation "index,manifest:org.opencontainers.image.licenses=Apache-2.0" \
	--metadata-file $(PUBLISH_DIR)/$(1).json

.PHONY: publish
publish: publish-proxy publish-netsetup publish-sandbox-base

.PHONY: publish-dir
publish-dir:
	@[ -n "$(strip $(PUBLISH_TAGS))" ] || { echo "PUBLISH_TAGS must name at least one tag" >&2; exit 2; }
	mkdir -p $(PUBLISH_DIR)

# The same two steps as image-proxy. ko writes the multi-platform image to
# an OCI layout instead of the daemon, and buildx reads it as the named
# context egress-proxy-ko, so the intermediate image is never pushed.
.PHONY: publish-proxy
publish-proxy: publish-dir
	rm -rf $(PUBLISH_DIR)/ko-layout
	ko_ref=$$(KO_CONFIG_PATH=images/proxy KO_DOCKER_REPO=egress-proxy-ko $(GO) tool ko build --push=false --bare \
		--sbom=none --oci-layout-path $(PUBLISH_DIR)/ko-layout --platform $(PLATFORMS) ./cmd/egress-proxy) || exit $$?; \
	SOURCE_DATE_EPOCH=0 docker buildx build -f images/proxy/Dockerfile --build-arg KO_IMAGE=egress-proxy-ko \
		--build-context egress-proxy-ko=oci-layout://$(abspath $(PUBLISH_DIR))/ko-layout@$${ko_ref##*@} \
		$(call publish_args,egress-proxy) images/proxy

.PHONY: publish-netsetup
publish-netsetup: publish-dir
	docker buildx build -f images/netsetup/Dockerfile $(call publish_args,egress-netsetup) .

.PHONY: publish-sandbox-base
publish-sandbox-base: publish-dir
	docker buildx build $(call publish_args,sandbox-base) images/sandbox-base

# Keyless signing: in the release workflow cosign takes the job's OIDC
# token, so the certificate names the workflow that pushed the image.
# --recursive also signs each platform manifest and attestation in the
# index. The references signed go to $(PUBLISH_DIR)/digests.txt.
.PHONY: sign
sign:
	: > $(PUBLISH_DIR)/digests.txt
	for image in $(PUBLISHED_IMAGES); do \
		digest=$$(jq -er '."containerimage.digest"' $(PUBLISH_DIR)/$$image.json) || exit $$?; \
		$(GO) tool cosign sign --yes --recursive $(REGISTRY)/$$image@$$digest || exit $$?; \
		echo "$(REGISTRY)/$$image@$$digest" >> $(PUBLISH_DIR)/digests.txt; \
	done

.PHONY: all
all: build test lint checks acceptance
