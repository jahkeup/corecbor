# 020 — Default-path decode recovery and residual throughput fixes

## Header

| Field | Value |
|---|---|
| **Number** | 020 |
| **Tier** | 1 |
| **Status** | Draft |
| **Filed** | 2026-05-24 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 016 (struct Value), 018 (arena), 019 (encode recovery) |
| **Supersedes** | none |
| **Spec sections touched** | §9 (performance requirements) |

---

## TL;DR

The default decode path (no opt-in flags) misses §9 targets by 23-31%
because the struct-based Value (proposal 016) increased per-element
memory from 16 bytes (interface) to 104 bytes (struct). The opt-in
arena (proposal 018 Phase B) exceeds all targets — but requiring
callers to learn about arenas, lifecycle management, and Reset()
semantics to achieve the library's own baseline targets is a contract
failure.

This proposal makes the decoder internally arena-backed by default
(auto-reset per Decode call), brings all §9 benchmarks back into
compliance on the default path, and addresses four residual throughput
issues that surfaced during the full-picture analysis.

---

## Motivation

### The §9 contract is a tier-1 artifact

From `encoder-decoder-spec.md` §9:

> Performance is a tier-1 acceptance criterion — the library is "core"
> CBOR; inefficiency propagates everywhere.

The targets are:

| Metric | §9 Target | Current default | Status |
|---|---|---|---|
| Encode scalars | ≥500 MB/s | 1793 MB/s | ✓ (3.6x) |
| Encode nested map | ≥100 MB/s | 233 MB/s | ✓ (2.3x) |
| Decode scalars | ≥400 MB/s | 276 MB/s | **✗ (-31%)** |
| Decode nested map (strict) | ≥80 MB/s | 62 MB/s | **✗ (-23%)** |
| Decode scalar allocs | 1 | 1 | ✓ |
| Encode scalar allocs | 0 | 0 | ✓ |

Two of four throughput targets fail on the default path. The library
ships with callers experiencing the regression unless they opt into
arena — an expert-mode feature that requires understanding Value
lifetime semantics.

### Why "just opt into arena" is insufficient

1. **Discovery barrier.** A caller running `go test -bench` and seeing
   276 MB/s doesn't know that `WithArena` exists or that it triples
   their throughput. The default must be competitive.

2. **§9 says "the library is core CBOR."** Core means: works well out
   of the box. Requiring configuration to meet stated targets is a
   contradiction in the spec.

3. **The pre-016 baseline was met without opts.** v0.1 hit all targets
   with zero configuration. v0.2 should not regress the zero-config
   experience.

4. **Postel's Law extends to defaults.** Be conservative in what you
   require of callers. The default decoder should produce correct,
   performant results without asking callers to manage lifetimes.

### Why the thresholds are what they are

The §9 targets were set based on the competitive landscape and the
"core" positioning:

| Target | Rationale |
|---|---|
| Encode ≥500 MB/s (scalars) | Must outperform `encoding/json` (~300 MB/s) by a meaningful margin. CBOR is a binary format; falling below JSON throughput would question the format choice. |
| Encode ≥100 MB/s (nested) | Must handle COSE/CWT header encoding at wire speed for TLS-class request rates (~100K req/s × 1KB payload = 100 MB/s). |
| Decode ≥400 MB/s (scalars) | Must keep up with NVMe read bandwidth for storage-codec use cases (local SSD random read ~500 MB/s). The codec must not be the bottleneck between disk and application. |
| Decode ≥80 MB/s (strict) | Must handle 10 Gbps wire ingestion with strict validation for security-sensitive paths (COSE signature verification reads ~1KB messages at ~80K/s = 80 MB/s). |

These are not aspirational — they are the minimum for the stated use
cases (storage AAD, wire protocol, cryptographic signing). Failing them
means the library cannot serve its documented callers without forcing
them into expert-mode optimization paths.

---

## Proposal

### Change 1: Decoder-internal arena (default-on, auto-reset)

The `Decoder` struct gains an internal arena that is automatically used
for container allocation and reset on each `Decode()` call:

```go
type Decoder struct {
    cfg   decodeConfig
    arena *rfc8949.Arena  // internal, auto-managed
}

func NewDecoder(opts ...DecoderOption) *Decoder {
    d := &Decoder{cfg: cfg}
    d.arena = rfc8949.NewArena(256, 64)
    // ...
    return d
}

func (d *Decoder) Decode(src []byte) (Value, error) {
    d.arena.Reset()
    d.cfg.opts.Arena = d.arena
    v, n, err := rfc8949.Decode(src, d.cfg.opts)
    // ...
}
```

**Lifecycle contract:** Values decoded from one `Decode()` call are
valid until the NEXT `Decode()` call on the same decoder. This matches
the universal usage pattern:

```go
for msg := range stream {
    v, _ := dec.Decode(msg)
    process(v)  // valid here
}
// v is invalid after the next iteration — but nobody holds it
```

Callers who need Values to outlive the decode call (accumulating into
a slice, passing to another goroutine) use `WithoutInternalArena()`:

```go
dec := corecbor.NewDecoder(corecbor.WithoutInternalArena())
```

Or clone individual Values before the next decode:

```go
v, _ := dec.Decode(msg)
persistent := v.Clone()  // deep copy, independent of arena
```

### Change 2: Inline text-key decode fast-path

In `decodeMap`, the map key decode is inlined for the common case
(short definite-length text string, <24 bytes — covers >90% of real
map keys):

```go
if pos < len(src) && src[pos]&0xe0 == 0x60 && src[pos]&0x1f < 24 {
    length := int(src[pos] & 0x1f)
    end := pos + 1 + length
    if end <= len(src) {
        k = cbor.Value{Kind: cbor.KindText, Str: string(src[pos+1 : end])}
        pos = end
        // skip full decodeValue call
    }
}
```

This eliminates function-call overhead, Kind switch, and validation
checks for the most common map-key pattern.

### Change 3: WriteValue scalar fast-path

`StreamEncoder.WriteValue(v)` currently buffers the entire encoded
value via `Encode(nil, v, opts)` then writes. For scalar Values, it
should dispatch to the existing zero-alloc direct-write methods:

```go
func (s *StreamEncoder) WriteValue(v Value) error {
    if err := s.trackWrite(); err != nil {
        return err
    }
    switch v.Kind {
    case KindUint:
        return s.writeHead(wire.MajorUint, v.Num)
    case KindNegInt:
        return s.writeHead(wire.MajorNegInt, v.Num)
    case KindBool:
        if v.Num != 0 {
            s.scratch[0] = wire.SimpleTrue
        } else {
            s.scratch[0] = wire.SimpleFalse
        }
        _, err := s.w.Write(s.scratch[:1])
        return err
    case KindNull:
        s.scratch[0] = wire.SimpleNull
        _, err := s.w.Write(s.scratch[:1])
        return err
    case KindText:
        if err := s.writeHead(wire.MajorText, uint64(len(v.Str))); err != nil {
            return err
        }
        _, err := io.WriteString(s.w, v.Str)
        return err
    case KindBytes:
        if err := s.writeHead(wire.MajorBytes, uint64(len(v.Bstr))); err != nil {
            return err
        }
        _, err := s.w.Write(v.Bstr)
        return err
    default:
        return rfc8949.EncodeTo(s.w, v, s.enc.encodeOpts())
    }
}
```

### Change 4: Extend decode array inline fast-path

The current `decodeArray` inlines uint/negint. Extend to also inline
text, bytes, bool, and null — the same pattern that already proved
effective in the encode path (proposal 019).

### Change 5: Value.Clone() method

Required by Change 1's lifecycle contract. Deep-copies a Value and all
its children, producing a Value independent of any arena:

```go
func (v Value) Clone() Value {
    switch v.Kind {
    case KindBytes:
        b := make([]byte, len(v.Bstr))
        copy(b, v.Bstr)
        return Value{Kind: KindBytes, Bstr: b}
    case KindText:
        return Value{Kind: KindText, Str: strings.Clone(v.Str)}
    case KindArray:
        items := make([]Value, len(v.Items))
        for i := range v.Items {
            items[i] = v.Items[i].Clone()
        }
        return Value{Kind: KindArray, Items: items}
    case KindMap:
        pairs := make([]MapEntry, len(v.Pairs))
        for i := range v.Pairs {
            pairs[i] = MapEntry{Key: v.Pairs[i].Key.Clone(), Value: v.Pairs[i].Value.Clone()}
        }
        return Value{Kind: KindMap, Pairs: pairs}
    case KindTag:
        return MakeTag(v.Num, v.Items[0].Clone())
    default:
        return v  // scalars have no shared backing
    }
}
```

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| `BenchmarkDecodeScalars` ≥ 400 MB/s (default, no opts) | `go test -bench` | Yes |
| `BenchmarkDecodeNestedMapStrict` ≥ 80 MB/s (default) | same | Yes |
| `BenchmarkEncodeScalars` unchanged (≥1700 MB/s) | same | Yes |
| `WriteValue(Uint(42))` ≤ 5ns, 0 allocs | same | Yes |
| `Value.Clone()` produces deep-independent copy | unit test | Yes |
| `WithoutInternalArena()` disables auto-arena | unit test | Yes |
| All existing tests pass | `make check` + sub-modules | Yes |
| Fuzz targets pass 30s each | `make fuzz` | Yes |
| Values valid until next Decode() call | documented + tested | Yes |
| Values INVALID after next Decode() call (arena reuse) | documented | Yes (docs only) |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | Decoder-internal arena + auto-reset + WithoutInternalArena | Pending | Default DecodeScalars ≥ 400 MB/s |
| 2 | Value.Clone() method | Pending | Clone produces independent copy |
| 3 | Inline text-key decode in map loop | Pending | DecodeNestedMapStrict ≥ 80 MB/s |
| 4 | WriteValue scalar fast-path | Pending | WriteValue(Uint) ≤ 5ns, 0 allocs |
| 5 | Extend decode array inline (text/bytes/bool/null) | Pending | Measurable improvement on mixed arrays |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Callers hold Values across Decode() calls | medium | high (silent corruption) | Document prominently; provide Clone(); WithoutInternalArena() opt-out |
| Internal arena grows unboundedly for large messages | low | medium (memory) | Cap arena growth; Reset releases only the offset, not the backing |
| Clone() performance for large trees | low | low | Clone is explicit opt-in; callers who call it accept the cost |
| Text-key inline misses edge cases (indefinite, non-shortest) | low | low | Inline only the common path; fallback to full decode for edge cases |

---

## Alternatives considered

### Keep arena as opt-in only, accept §9 failure

Rejected. The spec explicitly states performance is tier-1. Failing
stated targets on the default path without caller action contradicts
the library's contract. Every caller who benchmarks will see a
regression from the documented targets and question the library's
fitness.

### Compact the struct instead of using arena by default

Reduces the gap but doesn't close it. Even at 88 bytes (merged
Str+Bstr with unsafe), `make([]Value, 1000)` = 88KB vs the 8KB needed
to hit 400 MB/s. The 10x gap requires either fundamentally smaller
Values (back to interfaces — rejected) or arena-style batch allocation.

### Use sync.Pool for decoded Value slices

Pools amortize allocation but don't eliminate it. Each `Decode()` call
still pays Pool.Get/Put overhead (~8-10% of decode time per profiling).
Arena with auto-reset is strictly better: zero overhead on reuse, zero
allocs in steady state.

### Make Values immutable (copy-on-write)

Over-engineering. The common case is decode → process → discard. Making
Values immutable adds complexity for a pattern that almost never occurs
in practice (modifying a decoded Value in-place). Arena + Clone covers
the rare case cleanly.

---

## Cross-references

- `encoder-decoder-spec.md` §9 — performance targets and rationale
- Proposal 016 — struct Value (introduced the regression)
- Proposal 018 Phase B — arena allocator (the mechanism reused here)
- Proposal 019 — encode throughput recovery (proven pattern for inline
  fast-paths)
- v0.1.0-alpha.1 benchmarks — the pre-016 baseline that defined §9
  targets

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-24 | Initial draft | corecbor maintainers |
