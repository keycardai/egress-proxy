#!/usr/bin/env bash
# Generates NOTICE from the build list with go-licenses report and the
# template in scripts/notice.tpl. NOTICE is committed; --check fails when the
# committed file differs from what the build list produces, so a dependency
# change lands with its attribution.
#
# The build list is read for GOOS=linux, which is what the images ship. A
# file its build constraints exclude is never loaded, so reading the host
# instead would drop every module that only a //go:build linux file imports
# and leave NOTICE stale on a macOS workstation.
#
# Usage: notice.sh          rewrite NOTICE
#        notice.sh --check  fail if NOTICE is stale
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

# The tool is built once, for the host. Setting GOOS for `go tool` would
# cross-build the tool itself instead of changing what it reads.
tool_dir=$(mktemp -d)
trap 'rm -rf "$tool_dir"' EXIT
go build -modfile="$repo_root/go.mod" -o "$tool_dir/go-licenses" github.com/google/go-licenses/v2

# Packages of this repository are not third-party and are skipped by path
# prefix; their dependencies are still reported.
generate() {
	GOOS=linux "$tool_dir/go-licenses" report ./... \
		--template scripts/notice.tpl \
		--ignore github.com/keycardai/egress-proxy
}

case ${1-} in
"")
	generate >NOTICE
	echo "notice: wrote NOTICE"
	;;
--check)
	if ! diff -u NOTICE <(generate); then
		echo "notice: FAIL. NOTICE is stale; run 'make notice' and commit the result." >&2
		exit 1
	fi
	echo "notice: OK. NOTICE matches the build list."
	;;
*)
	echo "notice: unknown argument: $1" >&2
	exit 2
	;;
esac
