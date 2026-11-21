#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The corecbor Authors
#
# API stability gate (proposal 034): compare every module's exported API
# against the v0.2.2 release with apidiff and fail on any incompatible
# change that isn't listed in engineering-docs/api-allowlist.txt.
#
# Requires the v0.2.2 tag locally (CI checks out with fetch-depth: 0).
set -euo pipefail

TAG=${APICHECK_BASE:-v0.2.2}
MODULES=(. cose cwt eat edhoc)

root=$(git rev-parse --show-toplevel)
allowlist="$root/engineering-docs/api-allowlist.txt"
apidiff=(go tool -modfile="$root/tools/go.mod" apidiff)

if ! git -C "$root" rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
	echo "apicheck: tag $TAG not found; fetch tags (git fetch --tags)" >&2
	exit 1
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/corecbor-apicheck.XXXXXX")
old="$tmp/$TAG"
cleanup() {
	git -C "$root" worktree remove --force "$old" >/dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT

git -C "$root" worktree add --quiet --detach "$old" "$TAG"

# Allowlist entries are "<module path>: <apidiff line>"; comments and
# blank lines are ignored.
allowed="$tmp/allowed.txt"
grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$allowlist" >"$allowed" || true

status=0
for mod in "${MODULES[@]}"; do
	modpath=$(cd "$root/$mod" && go list -m)
	exp="$tmp/$(echo "$modpath" | tr '/' '_').export"
	(cd "$old/$mod" && "${apidiff[@]}" -m -w "$exp" "$modpath")
	report="$tmp/report.txt"
	(cd "$root/$mod" && "${apidiff[@]}" -m -incompatible "$exp" "$modpath") >"$report"

	unexpected=0
	while IFS= read -r line; do
		[ -z "$line" ] && continue
		case "$line" in
		"Incompatible changes:" | "Compatible changes:") continue ;;
		esac
		entry="$modpath: $(echo "$line" | sed -e 's/^[[:space:]]*-[[:space:]]*//')"
		if grep -qxF -- "$entry" "$allowed"; then
			echo "apicheck: allowlisted: $entry"
		else
			echo "apicheck: INCOMPATIBLE: $entry" >&2
			unexpected=1
		fi
	done <"$report"

	if [ "$unexpected" -ne 0 ]; then
		status=1
	else
		echo "apicheck: $modpath: no unlisted incompatible changes vs $TAG"
	fi
done

if [ "$status" -ne 0 ]; then
	cat >&2 <<EOF

apicheck: exported API changed incompatibly vs $TAG. Proposal 034 forbids
removing, renaming or retyping exported identifiers. The only accepted
break is an appended variadic ...Option parameter whose no-option
behavior is unchanged; list each one in engineering-docs/api-allowlist.txt
(and the migration guide) as "<module path>: <apidiff line>".
EOF
fi
exit "$status"
