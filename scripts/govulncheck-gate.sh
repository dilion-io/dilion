#!/usr/bin/env bash
# govulncheck with an allowlist.
#
# Fails, like plain `govulncheck ./...`, on every vulnerability the code calls,
# except those listed in scripts/govulncheck-allow.txt with the module at or
# above the listed version. govulncheck itself has no way to accept a
# finding: a record that names no fixed version (or names it late) would
# otherwise hold CI red with no remedy but to drop the dependency.
#
# Usage: scripts/govulncheck-gate.sh [packages...]   (default ./...)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
allow="$here/govulncheck-allow.txt"
govulncheck=${GOVULNCHECK:-govulncheck}
[ $# -gt 0 ] || set -- ./...

json=$(mktemp)
trap 'rm -f "$json"' EXIT
# -format json exits 0 whatever it finds; a non-zero exit is a scan error.
"$govulncheck" -format json "$@" >"$json"

# One line per called vulnerability: "<osv> <module> <version>". A finding is
# called when its innermost trace frame names a function. The others are
# package- or module-level, which plain govulncheck does not fail on either.
called=$(jq -r 'select(.finding) | .finding
	| select(.trace[0].function != null)
	| "\(.osv) \(.trace[0].module) \(.trace[0].version)"' "$json" | sort -u)

# version_ge A B: A >= B in semver order. Both are vX.Y.Z[-pre]; sort -V
# orders those correctly except a prerelease against its own release, which
# a minimum version never is.
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

declare -A min_version=()
while read -r id module min _; do
	case "$id" in '' | '#'*) continue ;; esac
	min_version["$id $module"]=$min
done <"$allow"

failed=0
declare -A seen=()
while read -r id module version; do
	[ -n "$id" ] || continue
	key="$id $module"
	seen["$key"]=1
	min=${min_version[$key]:-}
	if [ -n "$min" ] && version_ge "$version" "$min"; then
		echo "allowed: $id in $module@$version (listed for >= $min in scripts/govulncheck-allow.txt)"
	else
		echo "::error::$id is called in $module@$version — https://pkg.go.dev/vuln/$id${min:+ (allowlisted only for >= $min)}"
		failed=1
	fi
done <<<"$called"

for key in "${!min_version[@]}"; do
	if [ -z "${seen[$key]:-}" ]; then
		echo "::warning::govulncheck no longer reports ${key% *} in ${key#* }; delete its entry from scripts/govulncheck-allow.txt"
	fi
done

if [ "$failed" -ne 0 ]; then
	echo "Details: $govulncheck $*"
	exit 1
fi
echo "govulncheck-gate: OK"
