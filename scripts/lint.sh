#!/usr/bin/env bash
# The lint gate: golangci-lint at the version go.mod pins, reading the
# repository's .golangci.yml. The depguard rule in that file is the import
# gate, so this script is also what rejects a github.com/keycardlabs/ import.
#
# Usage: lint.sh [DIR] [golangci-lint args...]
#
# DIR is the module to lint and defaults to the repository root. The gate
# self-test points it at the fixture modules under test/gates/testdata; the
# tool is still resolved from the root go.mod, which is what -modfile does.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dir=$repo_root
if [[ $# -gt 0 && -d $1 ]]; then
	dir=$(cd "$1" && pwd)
	shift
fi

# golangci-lint analyzes one GOOS at a time, and a file its build
# constraints exclude is never loaded. Linting the host alone leaves every
# //go:build linux file unlinted on a macOS workstation. Both platforms run
# here, so the local gate and the CI gate are one gate.
platforms=(linux darwin)

# The tool is built once, for the host. Setting GOOS for `go tool` would
# cross-build the tool itself instead of changing what it analyzes.
tool_dir=$(mktemp -d)
trap 'rm -rf "$tool_dir"' EXIT
go build -modfile="$repo_root/go.mod" -o "$tool_dir/golangci-lint" \
	github.com/golangci/golangci-lint/v2/cmd/golangci-lint

cd "$dir"
# Some test suites use build tags. Naming every tag here keeps those packages
# under the same lint as everything else.
for goos in "${platforms[@]}"; do
	echo "lint: GOOS=$goos ($dir)"
	GOOS=$goos "$tool_dir/golangci-lint" run --config "$repo_root/.golangci.yml" \
		--build-tags acceptance,e2e,images ./... "$@"
done
echo "lint: OK ($dir)"
