# Every target here is also a CI step. Keep the two the same gate.

GO ?= go
export GOTOOLCHAIN ?= auto

.PHONY: help
help:
	@echo "build           go build ./..."
	@echo "test            go vet and go test -race ./..., including the gate self-tests"
	@echo "lint            golangci-lint (with the depguard import gate), the version go.mod pins"
	@echo "checks          license allow-list, NOTICE freshness and govulncheck"
	@echo "acceptance      every acceptance script under test/acceptance"
	@echo "e2e             the cluster lanes under test/e2e"
	@echo "notice          regenerate NOTICE from the build list"
	@echo "tidy            go mod tidy"
	@echo "all             build, test, lint, checks, acceptance, in gate order"

.PHONY: build
build:
	$(GO) build ./...

.PHONY: vet
vet:
	$(GO) vet ./...

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

# Every acceptance script runs on every commit, so a later change cannot
# silently regress an earlier one. Directories are named for what the script
# proves, not for a task or milestone id.
.PHONY: acceptance
acceptance:
	@set -e; found=0; \
	for script in test/acceptance/*/run.sh; do \
		[ -e "$$script" ] || continue; found=1; \
		echo "acceptance: $$script"; "$$script"; \
	done; \
	[ "$$found" = 1 ] || echo "acceptance: no scripts under test/acceptance yet"

# The k3d lanes on sigs.k8s.io/e2e-framework. The lanes are behind the e2e
# build tag so `go test ./...` never starts a cluster.
.PHONY: e2e
e2e:
	@if [ -d test/e2e ]; then \
		$(GO) test -tags e2e -count=1 -timeout 30m ./test/e2e/...; \
	else \
		echo "e2e: no lanes under test/e2e yet"; \
	fi

.PHONY: all
all: build test lint checks acceptance
