#!/usr/bin/env bash
# The vulnerability gate: govulncheck at the version go.mod pins, over the
# module under DIR. It reports only vulnerabilities in symbols the code
# reaches, and exits 3 when it finds one.
#
# Usage: vuln.sh [DIR]
#
# DIR defaults to the repository root. The gate self-test points it at a
# fixture module that calls a function with a published vulnerability.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dir=${1:-$repo_root}
[[ -d $dir ]] || { echo "vuln: not a directory: $dir" >&2; exit 2; }
cd "$dir"

go tool -modfile="$repo_root/go.mod" govulncheck ./...
echo "vuln: OK ($dir)"
