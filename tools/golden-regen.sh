#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The corecbor Authors
#
# Regenerate the v0.2.2 golden vectors (proposal 034).
#
# The expected results must come from the v0.2.2 release, never from the
# working tree, so this script checks out v0.2.2 into a temporary git
# worktree, copies the current golden harness (cases + allowlists +
# internal/goldentest) into it, runs each module's TestGoldenV022 with
# -golden.update there, and copies the generated JSON back.
#
# Run it after adding or changing golden *cases*. Never edit the JSON by
# hand to match new behavior; allowlist the vector ID instead.
set -euo pipefail

TAG=v0.2.2
MODULES=(. cose cwt eat edhoc)
HARNESS_FILES=(golden_v022_test.go golden_changes_test.go)

root=$(git rev-parse --show-toplevel)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/corecbor-golden.XXXXXX")
old="$tmp/$TAG"

cleanup() {
	git -C "$root" worktree remove --force "$old" >/dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT

git -C "$root" worktree add --quiet --detach "$old" "$TAG"

mkdir -p "$old/internal"
cp -R "$root/internal/goldentest" "$old/internal/"

for mod in "${MODULES[@]}"; do
	for f in "${HARNESS_FILES[@]}"; do
		if [ -f "$root/$mod/$f" ]; then
			cp "$root/$mod/$f" "$old/$mod/$f"
		fi
	done
	echo ">>> generating $TAG vectors in $mod"
	(cd "$old/$mod" && CORECBOR_GOLDEN_FROM="$TAG" go test -count=1 -run '^TestGoldenV022$' . -args -golden.update)
	mkdir -p "$root/$mod/testdata/golden/$TAG"
	cp "$old/$mod/testdata/golden/$TAG/"*.json "$root/$mod/testdata/golden/$TAG/"
done

echo "golden vectors regenerated from $TAG"
