#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The corecbor Authors
#
# Consumer check: is this corecbor working tree a drop-in for a
# downstream module that depends on a released corecbor?
#
# Clones the consumer into a temp dir (its checkout is never modified)
# and, against both BASE (a corecbor tag) and this working tree:
#   1. runs a consumer-supplied probe test that writes one line per
#      encoded item to $BYTECOMPAT_OUT, and diffs the two outputs
#      (for consumers that persist or authenticate encoded bytes, they
#      must be identical); lines containing re=false, encerr or decerr
#      fail the check;
#   2. runs RACE_PKGS under -race against this tree;
#   3. runs BENCH in BENCH_PKG, interleaved, and prints benchstat.
#
# Required:
#   CONSUMER_DIR  path to the consumer module checkout
#   PROBE         path to the probe _test.go file (kept with the consumer,
#                 not in this repo)
#   PROBE_PKG     consumer-relative package dir to copy PROBE into
#   PROBE_RUN     test name regexp for the probe
# Optional:
#   BASE=v0.2.2  RACE_PKGS=./...  BENCH_PKG=  BENCH=.  FULL=0 (1 = run ./...)
set -euo pipefail

: "${CONSUMER_DIR:?set CONSUMER_DIR}" "${PROBE:?set PROBE}" "${PROBE_PKG:?set PROBE_PKG}" "${PROBE_RUN:?set PROBE_RUN}"
base=${BASE:-v0.2.2}
here=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'git -C "$here" worktree remove --force "$work/corecbor-base" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

git clone -q --local "$CONSUMER_DIR" "$work/consumer"
git -C "$here" worktree add -q --detach "$work/corecbor-base" "$base"
cp "$PROBE" "$work/consumer/$PROBE_PKG/zz_corecbor_probe_test.go"

use() { # use <corecbor dir>
	(
		cd "$work/consumer"
		go mod edit -replace "github.com/jahkeup/corecbor=$1"
		if [ -d vendor ]; then go mod vendor; fi
	)
}
side_dir() { if [ "$1" = base ]; then echo "$work/corecbor-base"; else echo "$here"; fi; }

for side in base head; do
	use "$(side_dir "$side")"
	echo ">>> [$side] probe"
	(cd "$work/consumer" && BYTECOMPAT_OUT="$work/bytes-$side.txt" \
		go test -count=1 -run "$PROBE_RUN" "./$PROBE_PKG/" >/dev/null)
done

if cmp -s "$work/bytes-base.txt" "$work/bytes-head.txt"; then
	echo "bytes: IDENTICAL to $base ($(wc -l <"$work/bytes-head.txt" | tr -d ' ') lines)"
else
	echo "bytes: DIFFER from $base" >&2
	diff "$work/bytes-base.txt" "$work/bytes-head.txt" | head -20 >&2
	exit 1
fi
if grep -qE 're=false|encerr|decerr' "$work/bytes-head.txt"; then
	echo "round-trip: FAILURES" >&2
	grep -E 're=false|encerr|decerr' "$work/bytes-head.txt" | head >&2
	exit 1
fi
echo "round-trip: ok"

use "$here"
echo ">>> -race ${RACE_PKGS:-./...}"
(cd "$work/consumer" && go test -race -count=1 ${RACE_PKGS:-./...})

if [ "${FULL:-0}" = 1 ]; then
	echo ">>> full consumer suite"
	(cd "$work/consumer" && go test -count=1 ./...)
fi

if [ -n "${BENCH_PKG:-}" ]; then
	echo ">>> benchmarks (interleaved)"
	for _ in 1 2 3; do
		for side in base head; do
			use "$(side_dir "$side")"
			(cd "$work/consumer" && go test -run NONE -bench "${BENCH:-.}" -benchmem -count 2 "$BENCH_PKG" >>"$work/perf-$side.txt")
		done
	done
	if command -v benchstat >/dev/null 2>&1; then
		benchstat "$work/perf-base.txt" "$work/perf-head.txt"
	else
		echo "(install golang.org/x/perf/cmd/benchstat for a comparison)"
	fi
fi
