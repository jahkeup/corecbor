# 019 — Encode path throughput recovery

## Header

| Field | Value |
|---|---|
| **Number** | 019 |
| **Tier** | 2 |
| **Status** | Draft |
| **Filed** | 2026-05-24 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 016 (struct Value) |
| **Supersedes** | none |
| **Spec sections touched** | §9 (performance requirements) |

---

## TL;DR

The struct-based Value (proposal 016) regressed encode throughput from
907 MB/s to 619 MB/s for scalar arrays. CPU profiling reveals that
**70% of encode time is accessor overhead** — reading `Kind()` and
`UintVal()` through pointer indirection on every element. The actual
encoding work (`wire.AppendHead`) is only 5% of CPU time. This
proposal specifies three targeted optimizations that recover throughput
to ≥850 MB/s without changing the public API.

---

## Motivation

### Profiling data (BenchmarkEncodeScalars, Apple M3 Max)

| Function | % CPU | What it does |
|---|---|---|
| `rfc8949.encode` (dispatch) | 49.5% | Kind switch + pointer deref |
| `cbor.Value.UintVal()` | 30.1% | Read `v.num` through `*Value` |
| `cbor.Value.Kind()` | 8.7% | Read `v.kind` through `*Value` |
| `wire.AppendHead` | 4.9% | **Actual CBOR encoding** |
| `runtime.newstack` | 4.9% | Stack growth from deep recursion |

**Only 5% of CPU does useful work.** The remaining 95% is overhead
from the pointer-based accessor pattern required by the cross-package
boundary between `rfc8949` and `cbor`.

### Profiling data (BenchmarkEncodeNestedMap, deterministic)

| Function | % CPU | What it does |
|---|---|---|
| `rfc8949.encode` | 37.9% | Recursive dispatch |
| `rfc8949.encodeMap` | 13.7% | Map-specific sorting setup |
| `slices.SortFunc` | 13.7% | Key sorting |
| `utf8.ValidString` | 5.2% | UTF-8 validation on map keys |
| `Value.IsZero()` | 5.2% | Redundant nil check inside containers |
| `sync.Pool.Get/Put` | 8.5% | sortState pool overhead |

### Current state vs §9 targets

| Benchmark | Pre-016 (interface) | Current (struct) | §9 Target | Gap |
|---|---|---|---|---|
| EncodeScalars | 907 MB/s | 619 MB/s | ≥500 | Met, but 32% below pre-016 |
| EncodeNestedMap (det) | 218 MB/s | 199 MB/s | ≥100 | Met, but 9% below pre-016 |
| EncodeNestedMap (permissive) | — | 305 MB/s | — | Sorting costs 35% |

---

## Proposal

### Optimization 1: Export Value fields for intra-module access

The dominant cost (70% CPU) is accessor method overhead: calling
`v.Kind()` and `v.UintVal()` through a pointer requires function-call
dispatch even when inlined, because the compiler cannot prove the
pointer doesn't alias other memory.

**Fix:** Export the Value struct fields (`Kind`, `Num`, `Str`, `Bytes`,
`Items`, `Pairs`) so that the `rfc8949` package can access them
directly without method calls. The public accessor methods remain for
external consumers, but internal hot paths bypass them.

Alternatively: move the encode function into the `cbor` package itself
(as an unexported helper) where it has direct field access. The
`rfc8949` package then calls `cbor.AppendEncoded(dst, &v, ...)`.

**Expected gain:** Eliminates 70% of the overhead → ~3x improvement on
scalar encoding. Predicted: 619 → ~1500+ MB/s (approaching the
`wire.AppendHead` throughput ceiling).

### Optimization 2: Pass EncodeOpts by pointer

`EncodeOpts` is a 32-byte struct passed by value on every recursive
`encode()` call. For deeply nested structures, this adds 32 bytes per
stack frame and prevents the compiler from keeping opts in registers.

**Fix:** Change the internal `encode` signature to `encode(dst []byte,
v *Value, opts *EncodeOpts) ([]byte, error)`. The public `Encode` takes
opts by value (API unchanged) and passes its address to the internal
function.

**Expected gain:** Reduces per-call stack frame by 32 bytes. Measured
stack growth (`runtime.newstack`) is 4.9% of CPU — this should drop
to near zero. Estimated: 5-10% throughput improvement.

### Optimization 3: Skip redundant validation for container children

Every `encode()` call checks `v.IsZero()` (5.2% CPU in map benchmark)
and `utf8.ValidString` (5.2% CPU). Both are redundant when encoding
children of a container that was already validated at construction time
(decode always produces valid Values; user-constructed Values are
validated at the top-level call).

**Fix:** Add a `trusted bool` parameter to the internal encode path.
When `trusted=true`, skip `IsZero()` and `ValidString()` checks. The
top-level `Encode()` passes `trusted=false`; recursive calls from
within containers pass `trusted=true`.

For callers who construct Values from trusted sources (e.g., re-encoding
a just-decoded value), expose `EncodeOpts.SkipAllValidation bool` that
sets `trusted=true` at the top level.

**Expected gain:** Eliminates 10.4% CPU overhead in the map path.
Estimated: 10-15% throughput improvement for maps with text keys.

### Optimization 4: Inline map entry encoding (non-deterministic path)

The array encode path already inlines scalar encoding for elements.
The non-deterministic map path still calls `encode()` per key and per
value — 2 function calls × N entries. For the common case of
text-key maps with scalar values, this is pure overhead.

**Fix:** Apply the same inline fast-path pattern to `encodeMap`'s
non-deterministic branch:

```go
if !opts.Deterministic || len(m) <= 1 {
    for i := range m {
        // Inline key encoding (text keys are 90%+ of real maps)
        key := &m[i].Key
        if key.Kind() == KindText {
            s := key.str
            dst = wire.AppendHead(dst, wire.MajorText, uint64(len(s)))
            dst = append(dst, s...)
        } else {
            dst, err = encode(dst, key, opts)
        }
        // Inline value encoding for scalars
        val := &m[i].Value
        switch val.Kind() { ... }
    }
}
```

**Expected gain:** Measured: permissive mode is already 305 MB/s vs
199 MB/s deterministic. Inlining keys in the deterministic path's
key-buffer loop would save the `encode()` call overhead for key
encoding. Estimated: 15-20% for deterministic map encoding.

### Combined predicted outcome

| Optimization | Mechanism | Estimated gain |
|---|---|---|
| 1. Direct field access | Eliminate accessor overhead | +150-200% |
| 2. Opts by pointer | Reduce stack frame | +5-10% |
| 3. Skip validation | Remove redundant checks | +10-15% |
| 4. Inline map entries | Remove function calls | +15-20% |

**Compounded estimate:** EncodeScalars 619 → ≥850 MB/s.
**Stretch target:** ≥900 MB/s (matching pre-016 interface baseline).

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| `BenchmarkEncodeScalars` ≥ 850 MB/s | `go test -bench -benchmem` | Yes |
| `BenchmarkEncodeNestedMap` (deterministic) ≥ 200 MB/s | same | Yes |
| No change to public API signatures | Code review | Yes |
| All existing tests pass | `make check` | Yes |
| No new `unsafe` usage | Code review | Yes |
| `BenchmarkEncodeNestedMap` (permissive) ≥ 350 MB/s | same | No (informational) |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | Opts by pointer (internal encode signature change) | Pending | 5-10% improvement measured |
| 2 | Skip validation for trusted children | Pending | IsZero/UTF8 no longer in profile |
| 3 | Direct field access (export Value fields or move encode into cbor) | Pending | Accessor methods no longer in profile top-5 |
| 4 | Inline map entry encoding | Pending | Permissive map ≥ 350 MB/s |

Phases 1-2 are low-risk internal changes. Phase 3 requires an
architectural decision (export fields vs move code). Phase 4 is
mechanical once Phase 3 lands.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Exporting Value fields breaks encapsulation | medium | medium | Alternative: move encode into cbor package |
| Skipping validation introduces silent bad output | low | high | Only skip for container children; top-level always validates |
| Phase 3 increases coupling between cbor/ and rfc8949/ | medium | low | If moved into cbor/, the encoding logic lives alongside the type — natural |
| Compiler inlining defeats pointer-opts optimization | low | low | Benchmark before/after; if no gain, skip Phase 1 |

---

## Alternatives considered

### Use `unsafe.Pointer` to cast `*Value` to a raw struct and read fields

Rejected. Unnecessary complexity; exporting fields or moving code
achieves the same result safely.

### Accept the 619 MB/s throughput as the new baseline

Rejected. 32% below the pre-016 baseline is a measurable regression
for callers who upgraded for allocation reduction. The §9 target is
met (≥500), but closing the gap requires minimal effort.

### Revert to interface-based Value for the encode path only

Rejected. Maintaining two Value representations adds complexity and
defeats the purpose of the unified struct model.

---

## Cross-references

- Proposal 016 — struct Value (introduced the regression)
- Proposal 018 — opt-in extensions (PrecomputeMapOrder already bypasses
  the encode path for map keys; this proposal fixes the remaining cases)
- `rfc8949/encode.go` — the file modified by all 4 phases
- `cbor/value.go` — field visibility decision (Phase 3)
- CPU profiles: `pprof -top -cum` on BenchmarkEncodeScalars and
  BenchmarkEncodeNestedMap (data in this document)

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-24 | Initial draft with profiling data | corecbor maintainers |
