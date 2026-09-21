#!/usr/bin/env bash
# Generates NOTICE from the build list with go-licenses report and the
# template in scripts/notice.tpl. NOTICE is committed; --check fails when the
# committed file differs from what the build list produces, so a dependency
# change lands with its attribution.
#
# Usage: notice.sh          rewrite NOTICE
#        notice.sh --check  fail if NOTICE is stale
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

# Packages of this repository are not third-party and are skipped by path
# prefix; their dependencies are still reported.
generate() {
	go tool go-licenses report ./... \
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
