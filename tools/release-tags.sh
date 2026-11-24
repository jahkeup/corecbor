#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The corecbor Authors
#
# Create the annotated release tags for every module at HEAD:
#   <version>, cose/<version>, cwt/<version>, eat/<version>,
#   edhoc/<version>, scitt/<version>
#
# It checks first that the tree is clean, that every sub-module requires
# the in-repo modules at <version>, that none of the tags exist, and that
# `make check` passes. It never pushes; afterwards:
#   git push origin <version> cose/<version> cwt/<version> \
#     eat/<version> edhoc/<version> scitt/<version>
#
# Usage: tools/release-tags.sh v0.3.0 [--skip-check]
set -euo pipefail

version=${1:?usage: tools/release-tags.sh vX.Y.Z [--skip-check]}
skip_check=${2:-}
[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a release version: $version" >&2; exit 1; }

cd "$(dirname "$0")/.."
modules=(cose cwt eat edhoc scitt)

if [ -n "$(git status --porcelain)" ]; then
	echo "working tree is not clean" >&2
	exit 1
fi

bad=0
for m in "${modules[@]}"; do
	while read -r path ver; do
		if [ "$ver" != "$version" ]; then
			echo "$m/go.mod requires $path $ver, want $version" >&2
			bad=1
		fi
	done < <(awk '$1 ~ /^github\.com\/jahkeup\/corecbor(\/[a-z]+)?$/ && $2 ~ /^v/ {print $1, $2}' "$m/go.mod")
done
[ "$bad" = 0 ] || exit 1

tags=("$version")
for m in "${modules[@]}"; do tags+=("$m/$version"); done
for t in "${tags[@]}"; do
	if git rev-parse -q --verify "refs/tags/$t" >/dev/null; then
		echo "tag $t already exists" >&2
		exit 1
	fi
done

if [ "$skip_check" != "--skip-check" ]; then
	make check
fi

head=$(git rev-parse --short HEAD)
for t in "${tags[@]}"; do
	git tag -a "$t" -m "${t%/*}: corecbor $version" HEAD
	echo "tagged $t at $head"
done
echo
echo "Not pushed. To publish:"
echo "  git push origin ${tags[*]}"
