#!/usr/bin/env bash
# The license gate: every third-party module in the build list of the module
# under DIR must carry a license on the allow-list below, identified by SPDX
# id. go-licenses walks the packages' resolved imports, so a transitive
# dependency is checked like a direct one.
#
# It walks one GOOS at a time, and a file its build constraints exclude is
# never loaded. Both platforms run here, so a module that only a
# //go:build linux file imports is checked on a macOS workstation too.
#
# Usage: check-licenses.sh [DIR]
#        check-licenses.sh --allowed     print the allow-list, one id per line
#
# DIR defaults to the repository root. The gate self-test points it at a
# fixture module that depends on a GPL-3.0 module.
#
# The allow-list is the set of licenses the shipped binaries may redistribute.
# MPL-2.0 is on it because its obligations attach to the MPL-licensed files
# themselves, which a Go module dependency leaves unmodified and unvendored.
# GPL, LGPL and AGPL are off it. A build-time tool is not on this list's
# terms: it is a tool directive in go.mod, imported by no package, so it is
# outside the packages this gate walks and in no binary.
set -euo pipefail

allowed_licenses=(
	Apache-2.0
	MIT
	BSD-2-Clause
	BSD-3-Clause
	ISC
	MPL-2.0
)

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if [[ ${1-} == --allowed ]]; then
	printf '%s\n' "${allowed_licenses[@]}"
	exit 0
fi

dir=${1:-$repo_root}
[[ -d $dir ]] || { echo "check-licenses: not a directory: $dir" >&2; exit 2; }
cd "$dir"

# The tool is built once, for the host. Setting GOOS for `go tool` would
# cross-build the tool itself instead of changing what it walks.
tool_dir=$(mktemp -d)
trap 'rm -rf "$tool_dir"' EXIT
go build -modfile="$repo_root/go.mod" -o "$tool_dir/go-licenses" github.com/google/go-licenses/v2

# Packages of this repository are not third-party and are skipped by path
# prefix; their dependencies are still checked.
allowed=$(IFS=,; echo "${allowed_licenses[*]}")
for goos in linux darwin; do
	echo "check-licenses: GOOS=$goos ($dir)"
	GOOS=$goos "$tool_dir/go-licenses" check ./... \
		--allowed_licenses="$allowed" \
		--ignore github.com/keycardai/egress-proxy
done
echo "check-licenses: OK ($dir): every module in the build list is licensed under one of: $allowed"
