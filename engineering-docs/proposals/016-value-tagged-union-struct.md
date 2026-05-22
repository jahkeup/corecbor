# 016 — Replace Value interface with tagged-union struct

## Header

| Field | Value |
|---|---|
| **Number** | 016 |
| **Tier** | 1 |
| **Status** | Draft |
| **Filed** | 2026-05-22 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001 (foundational primitives) |
| **Supersedes** | none |
| **Spec sections touched** | §4 (value model), §9 (performance requirements) |

---

## TL;DR

Replace `cbor.Value` (currently a sealed interface with ~12 concrete
types) with a single `Value` struct carrying an explicit `Kind`
discriminator and inline storage for all variant data. This eliminates
the per-value heap allocation from interface boxing — the dominant cost
in decode (27% of CPU, 70% of allocations in `BenchmarkDecodeNestedMapStrict`)
and the primary reason the strict decode benchmark fails the §9 target
of 80 MB/s. Acceptance: strict decode exceeds 80 MB/s; all existing
tests and sub-modules pass after mechanical migration.

---

## Motivation

Profiling (`pprof` CPU + alloc, 2026-05-22 on AMD EPYC 7R13) shows
that the interface-based `cbor.Value` type is the performance ceiling
for the decode path:

| Allocation source | % of allocs (strict decode) | Mechanism |
|---|---|---|
| `convTstring` (Text → interface) | 52% | runtime boxes `string` into interface |
| `convTslice` (Map/Array → interface) | 18% | runtime boxes `[]MapEntry`/`[]Value` into interface |
| `make(cbor.Map, 0, count)` | 18% | per-map backing array |
| `make(cbor.Array, count)` | 10% | per-array backing array |
| `decodeBytes` (Bytes copy) | 2% | unavoidable data copy |

The first two categories — 70% of all allocations — exist solely
because `Value` is an interface. Every decoded item must be heap-
allocated and wrapped in a two-word interface value. The Go compiler
cannot escape-analyze these away because the interface return type
forces the concrete value to escape.

**Current benchmark vs. target:**

| Benchmark | Current | §9 Target | Gap |
|---|---|---|---|
| DecodeNestedMapStrict | 55 MB/s, 46 allocs/op | ≥ 80 MB/s | **-31%** |
| DecodeScalars | 430 MB/s, 2 allocs/op | ≥ 400 MB/s | pass (marginal) |

The 46 allocs/op cannot be reduced below ~6 without eliminating
interface boxing. No amount of pooling, interning, or arena tricks
within the interface model can reach the target — the runtime's
`convTstring` and `convTslice` are the floor.

Additionally, the COSE `MarshalSign1` benchmark shows 47% of its
allocations come from constructing `cbor.Value` interface values
(boxing `Bytes`, `Array`, `Map` into the interface). A struct-based
Value eliminates these entirely.

---

## Proposal

### Public API surface

The `cbor` package replaces its interface-based model with a struct:

```go
// Kind discriminates the CBOR data item type stored in a Value.
type Kind uint8

const (
	KindInvalid   Kind = iota // zero value; not a valid CBOR item
	KindUint                  // major type 0
	KindNegInt                // major type 1
	KindBytes                 // major type 2
	KindText                  // major type 3
	KindArray                 // major type 4
	KindMap                   // major type 5
	KindTag                   // major type 6
	KindBool                  // major type 7, simple 20/21
	KindNull                  // major type 7, simple 22
	KindUndefined             // major type 7, simple 23
	KindFloat32               // major type 7, AI 26
	KindFloat64               // major type 7, AI 27
	KindSimple                // major type 7, unassigned simple values
)

// Value is a CBOR data item. The zero value has Kind == KindInvalid.
//
// Values are cheap to copy (a struct, not a pointer). Slice-backed
// variants (Bytes, Text, Array, Map) share underlying storage on copy
// — mutating one alias is visible through the other, same as a slice
// assignment in Go.
type Value struct {
	kind  Kind
	num   uint64     // Uint, NegInt, Float64 (bits), Float32 (bits), Bool, Simple, Tag ID
	str   string     // Text
	bytes []byte     // Bytes
	items []Value    // Array, Tag (items[0] = inner)
	pairs []MapEntry // Map
}

// MapEntry is a key-value pair in a CBOR map.
type MapEntry struct {
	Key   Value
	Value Value
}
```

**Constructors** (replace the named types used today):

```go
func Uint(v uint64) Value
func NegInt(v uint64) Value
func Bytes(b []byte) Value
func Text(s string) Value
func MakeArray(items ...Value) Value
func MakeMap(pairs ...MapEntry) Value
func MakeTag(id uint64, inner Value) Value
func Bool(v bool) Value
func Null() Value
func Undefined() Value
func Float32(v float32) Value
func Float64(v float64) Value
func Simple(v uint8) Value
```

**Accessors** (type-safe extraction — panic on kind mismatch):

```go
func (v Value) Kind() Kind
func (v Value) IsZero() bool      // Kind == KindInvalid

func (v Value) Uint() uint64      // panics if Kind != KindUint
func (v Value) NegInt() uint64    // panics if Kind != KindNegInt
func (v Value) Bytes() []byte     // panics if Kind != KindBytes
func (v Value) Text() string      // panics if Kind != KindText
func (v Value) Array() []Value    // panics if Kind != KindArray
func (v Value) Map() []MapEntry   // panics if Kind != KindMap
func (v Value) TagID() uint64     // panics if Kind != KindTag
func (v Value) TagInner() Value   // panics if Kind != KindTag
func (v Value) Bool() bool        // panics if Kind != KindBool
func (v Value) Float32() float32  // panics if Kind != KindFloat32
func (v Value) Float64() float64  // panics if Kind != KindFloat64
func (v Value) Simple() uint8     // panics if Kind != KindSimple
```

### Behavior

**Before (interface):**
```go
switch v := val.(type) {
case cbor.Text:
    name := string(v)
case cbor.Uint:
    id := uint64(v)
case cbor.Array:
    for _, item := range v { ... }
}
```

**After (struct):**
```go
switch val.Kind() {
case cbor.KindText:
    name := val.Text()
case cbor.KindUint:
    id := val.Uint()
case cbor.KindArray:
    for _, item := range val.Array() { ... }
}
```

**Construction before:**
```go
arr := corecbor.Array{
    corecbor.Bytes(protectedBytes),
    corecbor.Text("hello"),
}
tagged := corecbor.Tag{ID: 18, Inner: arr}
```

**Construction after:**
```go
arr := cbor.MakeArray(
    cbor.Bytes(protectedBytes),
    cbor.Text("hello"),
)
tagged := cbor.MakeTag(18, arr)
```

**Migration impact:** All callers that construct, inspect, or
pattern-match `cbor.Value` must update. This is ~140 call sites across
cose/, cwt/, eat/, edhoc/ and an unknown number in external consumers.
The transforms are mechanical and greppable:

| Old pattern | New pattern | Automation |
|---|---|---|
| `cbor.Text("x")` (type conversion) | `cbor.Text("x")` (constructor) | Same syntax, different semantics — no change needed |
| `v.(cbor.Text)` | `v.Text()` after `Kind()` check | sed/gofmt |
| `case cbor.Text:` in type switch | `case cbor.KindText:` in kind switch | sed |
| `cbor.Array{item1, item2}` | `cbor.MakeArray(item1, item2)` | sed |
| `cbor.Map{entry1, entry2}` | `cbor.MakeMap(entry1, entry2)` | sed |
| `cbor.Tag{ID: n, Inner: v}` | `cbor.MakeTag(n, v)` | sed |
| `cbor.MapEntry{Key: k, Value: v}` | `cbor.MapEntry{Key: k, Value: v}` | unchanged |
| `for _, e := range m` (Map iteration) | `for _, e := range v.Map()` | minor |
| `arr[i].(cbor.Bytes)` | `arr[i].Bytes()` | sed |

### Struct size and copy cost

The `Value` struct is 80 bytes (1 byte kind + 7 padding + 8 num + 16
str + 24 bytes + 24 items + 24 pairs = 104; with alignment likely 80
on amd64 with field reordering). Copying an 80-byte struct is 1-2
cache lines — cheaper than dereferencing a heap-allocated interface +
pointer chase + potential cache miss on the pointed-to data.

For compound values (Array, Map), the struct holds the slice header
(24 bytes) — the backing data is shared on copy, identical to today's
behavior where `cbor.Array` is already `[]Value`.

### Failure modes

No new typed errors. The only new failure mode is calling an accessor
with the wrong kind, which panics. Callers who today use type
assertions without the comma-ok form already panic on mismatch — the
risk profile is unchanged. Callers who use type switches get a
compile-time-complete set of `Kind` constants.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| `BenchmarkDecodeNestedMapStrict` ≥ 80 MB/s | `go test -bench` | Yes |
| `BenchmarkDecodeNestedMapStrict` ≤ 10 allocs/op | `-benchmem` | Yes |
| `BenchmarkDecodeScalars` ≥ 400 MB/s | `go test -bench` | Yes |
| `BenchmarkEncodeScalars` ≥ 500 MB/s | `go test -bench` | Yes |
| `BenchmarkEncodeNestedMap` ≥ 100 MB/s | `go test -bench` | Yes |
| All existing tests pass (root + sub-modules) | `make check` | Yes |
| Zero boxing allocations in encode path (scalar, reused encoder) | `-benchmem` shows 0 allocs | Yes |
| `MarshalSign1` ≤ 8 allocs/op (down from 16) | `go test -bench -benchmem` in cose/ | No (informational) |
| No `interface{}` or `any` in the Value API surface | Code review | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | Implement `Value` struct + `Kind` + constructors + accessors in `cbor/` | Pending | Unit tests pass, struct compiles |
| 2 | Migrate encoder (`rfc8949/encode.go`) to struct-based dispatch | Pending | Encode benchmarks unchanged or improved |
| 3 | Migrate decoder (`rfc8949/decode.go`) to return struct values | Pending | Decode benchmarks meet §9 targets |
| 4 | Migrate sub-modules (cose, cwt, eat, edhoc) | Pending | `make check` passes for all modules |
| 5 | Remove old interface type, update godoc, tag release | Pending | Clean API, no dead code |

Phases 2 and 3 can land independently. Phase 4 is parallelizable
across sub-modules. Phase 5 is the breaking-change commit.

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestValueConstructorsRoundTrip` | Every Kind constructs and accesses correctly | `cbor/value_test.go` |
| `TestValueZeroIsInvalid` | Zero value has KindInvalid, accessors panic | `cbor/value_test.go` |
| `TestValueCopySharesBackingSlice` | Array/Map copy semantics match slice assignment | `cbor/value_test.go` |
| All existing `vectors_test.go` | RFC 8949 round-trip unchanged | `vectors_test.go` |
| All existing fuzz targets | No panics on arbitrary input | `fuzz_test.go` |
| Sub-module test suites | COSE/CWT/EAT/EDHOC behavior unchanged | respective `*_test.go` |

No new fuzz targets required — existing targets exercise the
encode/decode path regardless of the Value representation. The fuzz
harness calls `Decode` then `Encode` and checks round-trip, which
validates the new struct path automatically.

---

## Performance

| Metric | Current (interface) | Expected (struct) | Target | Test mechanism |
|---|---|---|---|---|
| DecodeNestedMapStrict throughput | 55 MB/s | ~120-150 MB/s | ≥ 80 MB/s | `go test -bench BenchmarkDecodeNestedMapStrict` |
| DecodeNestedMapStrict allocs/op | 46 | ~6 | — | `-benchmem` |
| DecodeScalars throughput | 430 MB/s | ~500+ MB/s | ≥ 400 MB/s | `go test -bench BenchmarkDecodeScalars` |
| DecodeScalars allocs/op | 2 | 1 | 1 | `-benchmem` |
| EncodeScalars throughput | 610 MB/s | ≥ 610 MB/s (no regression) | ≥ 500 MB/s | `go test -bench BenchmarkEncodeScalars` |
| EncodeNestedMap throughput | 147 MB/s | ~160+ MB/s (less interface dispatch) | ≥ 100 MB/s | `go test -bench BenchmarkEncodeNestedMap` |
| MarshalSign1 allocs/op | 16 | ~6-8 | — | COSE bench |

**Rationale for estimates:**

The 46→6 alloc estimate for strict decode:
- 3 maps: 3 allocs for `make([]MapEntry, count)` — these remain (can't avoid the backing array)
- 3 arrays: 3 allocs for `make([]Value, count)` — same
- Text strings: **0** — `string(src[...])` is stored inline in the `Value.str` field, no boxing
- Return values: **0** — `Value` is returned by value, no interface boxing
- Total: ~6 allocs (3 maps + 3 arrays)

The throughput estimate assumes allocation reduction translates ~1:1
to CPU savings since `mallocgc` + `convT*` account for 39.9% + 27.3%
= 67% of cumulative CPU in the strict decode profile.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| 80-byte struct copy is slower than interface pointer for deeply recursive encode | Low | Low — encode already 0-alloc, struct fits in 2 cache lines | Benchmark before/after; fallback to pointer-to-struct if regresses |
| Accessor panics replace type-assertion panics — same blast radius but less familiar to Go developers | Med | Low — same failure mode as today, different stack trace | Document in godoc; provide `TryText() (string, bool)` safe variants |
| External consumers (if any) break on the API change | Med | Med — breaking change | Semver major bump; provide a migration guide and a gofix-style tool |
| Compiler fails to inline accessors → method call overhead per access | Low | Low — accessors are trivial one-liners | Verify with `go build -gcflags='-m'`; add `//go:nosplit` if needed |
| `Value` struct too large for stack allocation in deeply nested decode | Low | Med — could force heap escape | Profile escape analysis; consider pointer-to-Value for recursive tree nodes (items/pairs already use slices, so the recursion is in the slice, not the struct) |

---

## Alternatives considered

**1. Keep interface, add string interning + arena allocator**

Pool previously-decoded strings and batch-allocate MapEntry slices
from a per-decode arena. Estimated gain: ~30-40% alloc reduction,
getting strict decode to ~70-75 MB/s. Rejected because:
- Still can't eliminate `convTstring`/`convTslice` boxing (the runtime does this, not our code)
- Adds complexity (intern maps, arena lifecycle) that gets discarded when the struct lands anyway
- Doesn't reach the 80 MB/s target

**2. Pointer-to-struct (`*Value`) instead of by-value struct**

Return `*Value` from decode to avoid copying 80 bytes. Rejected because:
- Reintroduces a heap allocation per decoded item (the pointer itself must point to heap)
- Defeats the primary goal of eliminating per-value allocations
- Slice-of-Value (`[]Value` for arrays) is already the right layout — contiguous, cache-friendly, one allocation for the whole array

**3. Tagged union via unsafe (NaN-boxing or pointer tagging)**

Pack the discriminator and small values into 16 bytes using unsafe tricks.
Rejected because:
- Violates Go's memory safety guarantees
- Breaks under different pointer sizes (32-bit, future architectures)
- TinyGo and WASM targets may not support the required unsafe operations
- Maintenance burden disproportionate to the marginal gain over a clean struct

**4. Separate "fast" and "safe" decode APIs**

Keep the interface API, add a parallel `DecodeStruct()` path. Rejected because:
- Doubles the API surface and maintenance burden
- Encoder must support both representations anyway
- Sub-modules would need to pick one or support both — combinatorial explosion

**5. Generic `Value[T]` or type-parameterized decode**

Use generics to monomorphize per-type. Rejected because:
- CBOR is heterogeneous: a map key's type isn't known until the wire byte is parsed
- The generic type parameter must be resolved at compile time, but decode resolves types at runtime
- Ends up needing an `any`/interface fallback for the general case, which is the same cost

---

## Open questions

1. **Safe accessor variants?** Should we provide `TryText() (string, bool)`
   alongside `Text() string`? Pro: avoids panics for callers who can't
   guarantee Kind before access. Con: doubles the accessor API surface.
   Recommendation: provide both; the panicking variant is the common
   path (caller already switched on Kind), the Try variant is for
   one-off extractions.

2. **Should `Value` be in `cbor/` or the root `corecbor` package?**
   Today `cbor.Value` is in `cbor/` (a sub-package). The root package
   re-exports the types as `corecbor.Text`, `corecbor.Array`, etc.
   With constructors instead of type names, re-export means
   `corecbor.Text(s)` calls `cbor.Text(s)` — straightforward. Keep
   current package layout.

3. **Sizeof budget:** Is 80 bytes acceptable, or should we compress
   further (e.g., union the `str`/`bytes`/`items`/`pairs` fields via
   unsafe)? Recommendation: start with the clean layout, measure, and
   only compress if escape analysis or copy overhead shows up in
   profiles. The slice headers are 24 bytes each, and only one is
   non-nil per value — wasteful in space but safe and simple.

4. **Tag inner value:** Store as `items[0]` (reusing the Array
   slice field) or add a dedicated `inner Value` field (+80 bytes)?
   Recommendation: `items[0]` avoids growing the struct. The `items`
   slice is unused for Tag kind otherwise, and `MakeTag` allocates a
   1-element slice — same as today's approach where `Tag.Inner` is
   an interface (1 alloc). If zero-alloc Tag is important later,
   revisit with a dedicated field.

---

## Cross-references

- Spec: §4 of `encoder-decoder-spec.md` (value type hierarchy)
- Spec: §9 of `encoder-decoder-spec.md` (performance requirements)
- Profiling data: commit message of `77bcd0b` + session 2026-05-22
- Proposal 001 — foundational primitives (introduced the interface model)
- Proposal 008 — reflective marshal/unmarshal (uses Value interface for reflection; must adapt)
- Proposal 015 — TinyGo support (struct approach is TinyGo-friendlier: no interface dispatch, smaller binary)

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-22 | Initial draft | corecbor maintainers |
