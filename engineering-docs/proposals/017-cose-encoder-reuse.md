# 017 — COSE encoder reuse strategy

## Header

| Field | Value |
|---|---|
| **Number** | 017 |
| **Tier** | 2 |
| **Status** | Draft |
| **Filed** | 2026-05-22 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001, 016 (if struct migration changes Encoder API) |
| **Supersedes** | none |
| **Spec sections touched** | none (internal optimization) |

---

## TL;DR

The COSE marshal functions (`MarshalSign1`, `MarshalEncrypt0`, etc.)
allocate a fresh `*Encoder` on every call, accounting for 12% of
`MarshalSign1` allocations. This proposal evaluates three encoder reuse
strategies — package-level singleton, `sync.Pool`, and caller-provided
encoder — and selects one that is safe across runtime environments
(standard Go, TinyGo/WASM, concurrent callers).

Acceptance: `MarshalSign1` eliminates the per-call encoder allocation
without introducing concurrency hazards or environment-specific
behavior.

---

## Motivation

Profiling (`pprof -alloc_objects`, 2026-05-22) shows `corecbor.New()`
contributes ~10% of `BenchmarkMarshalSign1` allocations. The `Encoder`
struct is 80+ bytes (includes `SortStateCache`) and is allocated on the
heap because it escapes through the pointer return of `New()`.

Every COSE marshal function does:
```go
enc := corecbor.New(corecbor.ModeCoreDeterministic)
return enc.Encode(buf, tagged)
```

The encoder is stateless between calls — its only mutable state is the
`SortStateCache` which is reset on each use. This makes it a candidate
for reuse.

---

## Proposal

### Options under consideration

**Option A: Package-level `var` (singleton)**

```go
var deterministicEncoder = corecbor.New(corecbor.ModeCoreDeterministic)
```

- Pro: Zero allocation, zero overhead.
- Con: `SortStateCache` is not goroutine-safe. Concurrent calls to
  `MarshalSign1` from different goroutines would race on the cache.
  The `Encoder.Encode` method itself is safe (it only reads config),
  but the `SortStateCache` embedded in the encoder is mutated.
- Con: TinyGo on single-threaded WASM would work, but the API doesn't
  prevent misuse.
- Verdict: **Unsafe without additional synchronization.** Would require
  either making `SortStateCache` concurrency-safe (adds a mutex — worse
  than `sync.Pool`) or removing the cache from the singleton.

**Option B: `sync.Pool` of `*Encoder`**

```go
var encoderPool = sync.Pool{
    New: func() any {
        return corecbor.New(corecbor.ModeCoreDeterministic)
    },
}
```

- Pro: Goroutine-safe, amortizes allocation.
- Con: `sync.Pool` has non-trivial Get/Put overhead (~8-10% of encode
  time per profiling of the `sortStatePool`). This exactly trades one
  allocation for pool overhead.
- Con: TinyGo's `sync.Pool` is a simple slice with no GC integration.
  On memory-constrained targets, pooled encoders never get collected.
- Verdict: **Marginal.** May not improve over the current allocation.

**Option C: Caller-provided encoder (API change)**

```go
func MarshalSign1With(enc *corecbor.Encoder, msg *Sign1) ([]byte, error)
```

- Pro: Zero overhead — caller controls lifetime and concurrency.
- Con: Breaks the simple `MarshalSign1(msg)` API or requires a `With`
  variant.
- Con: Pushes responsibility to the caller. Most callers won't bother
  and will call `MarshalSign1` which internally still allocates.
- Verdict: **Good for hot paths, but doesn't help the common case.**

**Option D: Encoder without cache (lightweight singleton)**

```go
var deterministicEncoder = &corecbor.Encoder{
    mode: corecbor.ModeCoreDeterministic,
    // no SortStateCache — nested maps fall back to sync.Pool
}
```

Expose a `NewLite()` or make `Encode` not use the cache when called
on a shared encoder (detected by nil cache pointer).

- Pro: Zero allocation, goroutine-safe (encoder is read-only, sort
  state comes from pool).
- Con: Nested map encoding still uses `sync.Pool` for sort state.
- Verdict: **Best compromise.** Eliminates the encoder allocation
  without introducing concurrency issues. The sort cache optimization
  applies only to long-lived, caller-owned encoders.

### Recommended approach: Option D

Split the encoder into a lightweight configuration struct (mode +
flags, immutable after construction) that can be safely shared, and
the mutable `SortStateCache` that lives on caller-owned instances.

The COSE module uses a package-level shared encoder:

```go
var coseEncoder = corecbor.NewShared(corecbor.ModeCoreDeterministic)
```

`NewShared` returns an `*Encoder` with `SortCache` set to nil,
making `Encode` fall through to `sync.Pool` for sort state. This is
goroutine-safe and costs zero allocations for the encoder itself.

Callers who need maximum throughput on a dedicated goroutine still
use `corecbor.New()` which includes the local cache.

### Behavior

- `corecbor.New()` — returns `*Encoder` with local `SortStateCache` (current behavior, not goroutine-safe for concurrent Encode)
- `corecbor.NewShared()` — returns `*Encoder` with nil cache (goroutine-safe, sort state from pool)
- COSE/CWT/EAT/EDHOC internal marshal functions use `NewShared()` singleton
- No change to public `MarshalSign1` API

### Failure modes

None — this is a pure optimization. If `NewShared` is misused (caller
mutates it), the only consequence is incorrect encoding mode, same as
today if someone mutates an encoder's fields.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| `MarshalSign1` encoder allocation eliminated | `-benchmem` shows reduction from 10 to 9 allocs/op | Yes |
| No data race under concurrent `MarshalSign1` calls | `go test -race -count=100` with parallel benchmark | Yes |
| TinyGo compilation unaffected | `tinygo build` (when 015 lands) | No |
| No regression in `BenchmarkEncodeNestedMap` | `-bench` unchanged | Yes |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Future Encoder fields become mutable (breaking shared safety) | Low | Med | Document `NewShared` contract; add a test that races on it |
| `sync.Pool` sort state is slower than cache on constrained targets | Med | Low | Profile on WASM if 015 lands; TinyGo pool is a simple slice |
| Proposal 016 (Value struct) changes Encoder internals | High | Low | This proposal is compatible — struct Values don't change encode config |

---

## Alternatives considered

See Options A-C above. Each rejected for the stated reasons.

---

## Open questions

1. **Naming:** `NewShared` vs `NewConcurrent` vs `NewImmutable`?
   Recommendation: `NewShared` — communicates intent without
   overpromising implementation details.

2. **Should `New()` document non-concurrency?** Today it's implicit.
   If we add `NewShared`, we should document that `New()` encoders
   are not safe for concurrent `Encode` calls (due to the sort cache).

---

## Cross-references

- Profiling data: 2026-05-22 session, `BenchmarkMarshalSign1` alloc profile
- Proposal 015 — TinyGo support (sync.Pool behavior differs)
- Proposal 016 — Value struct (may change Encoder internals)

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-22 | Initial draft | corecbor maintainers |
