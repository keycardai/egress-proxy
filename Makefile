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
	@echo "e2e             the cluster lanes under test/e2e"
	@echo "images          build the three images locally and drive what each one has to do"
	@echo "notice          regenerate NOTICE from the build list"
	@echo "tidy            go mod tidy"
	@echo "all             build, test, lint, checks, acceptance, in gate order"

.PHONY: build
build:
	$(GO) build ./...

# The acceptance tests are behind a build tag, so vet names it to cover them.
.PHONY: vet
vet:
	$(GO) vet -tags acceptance ./...

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

# The k3d lanes on sigs.k8s.io/e2e-framework. The lanes are behind the e2e
# build tag so `go test ./...` never starts a cluster.
.PHONY: e2e
e2e:
	@if [ -d test/e2e ]; then \
		$(GO) test -tags e2e -count=1 -timeout 30m ./test/e2e/...; \
	else \
		echo "e2e: no lanes under test/e2e yet"; \
	fi

# The three images, built locally. ko builds the proxy straight from the
# module. The other two are Dockerfiles, and the netsetup one takes the
# repository root as its build context. Nothing here pushes: publishing is
# a release step.
IMAGE_TAG ?= dev

.PHONY: image-proxy
image-proxy:
	KO_CONFIG_PATH=images/proxy KO_DOCKER_REPO=ko.local $(GO) tool ko build --local --bare \
		--tags $(IMAGE_TAG) --platform linux/$(shell $(GO) env GOARCH) ./cmd/egress-proxy

.PHONY: image-netsetup
image-netsetup:
	docker build -f images/netsetup/Dockerfile -t egress-netsetup:$(IMAGE_TAG) .

.PHONY: image-sandbox-base
image-sandbox-base:
	docker build -t sandbox-base:$(IMAGE_TAG) images/sandbox-base

# The image lane builds all three and drives what each one has to do: the
# proxy image answers `probe`, the netsetup image resolves the legacy
# iptables binaries, and the base image entrypoint installs a certificate
# from a fake /shared-ca. It skips when no Docker daemon answers.
.PHONY: images
images:
	$(GO) test -tags images -count=1 -timeout 30m ./test/images/...

.PHONY: all
all: build test lint checks acceptance
