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

cd "$dir"
go tool -modfile="$repo_root/go.mod" golangci-lint run --config "$repo_root/.golangci.yml" ./... "$@"
echo "lint: OK ($dir)"
