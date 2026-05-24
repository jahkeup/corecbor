# 018 — Opt-in performance extensions for complex use cases

## Header

| Field | Value |
|---|---|
| **Number** | 018 |
| **Tier** | 2 |
| **Status** | Draft |
| **Filed** | 2026-05-23 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001, 016 (tagged-union struct) |
| **Supersedes** | none |
| **Spec sections touched** | §9 (performance requirements — extends opt-in surface) |

---

## TL;DR

After proposal 016 eliminates interface boxing (the single largest
allocation source), the remaining performance headroom lives in
**caller-scenario-specific optimizations** — things that require the
caller to assert something about their usage pattern in exchange for
reduced allocations or throughput gains.  This proposal defines ten
opt-in performance extensions as a coherent system of `DecoderOption`,
`EncodeOpts` fields, and standalone APIs.  Each extension is safe to
ignore (the default path is unchanged), dangerous to misuse (documented
sharp edges), and independently shippable.

Acceptance: each extension demonstrates measurable improvement on its
target benchmark without regressing the default (no-opt-in) path.

---

## Motivation

The Phase 4 performance pass (proposal 001) met §9 targets.  Proposal
016 pushes decode throughput well past the 80 MB/s floor.  But callers
with extreme requirements — multi-tenant CBOR gateways, IoT ingestion
pipelines processing millions of messages/sec, COSE signing hot loops,
constrained embedded targets — need more.

The remaining allocation sources after 016 are:

| Source | % of remaining allocs (post-016 estimate) | Elimination mechanism |
|---|---|---|
| `make([]byte, n)` for byte strings | ~35% | Zero-copy decode |
| `string(src[start:end])` for text strings | ~25% | Zero-copy decode or string interning |
| `make([]Value, n)` / `make([]MapEntry, n)` per container | ~30% | Arena allocator |
| `mapInsert` linear scan (O(n²) for strict dedup) | CPU, not allocs | Hash-based dedup |
| Slice growth in encode (`append` to dst) | ~5% | Pre-sizing hints |
| Full tree decode when only one field is needed | CPU + allocs | Lazy/cursor decode |

None of these can be eliminated transparently — each requires the caller
to trade generality for performance by making a guarantee:

- "I will keep the source buffer alive" (zero-copy)
- "I accept shared mutable state in my intern table" (interning)
- "I will release the arena when done" (arena)
- "I know my approximate output size" (pre-sizing)
- "I only need one field" (cursor)

These are **expert-mode knobs** for callers who have profiled and know
their bottleneck.  The default path remains safe, allocation-conscious,
and correct without any of these enabled.

---

## Proposal

### Extension 1: Zero-copy decode

#### Problem

Every byte string and text string decode allocates a fresh buffer and
copies from `src`.  For forwarding proxies, re-encode pipelines, and
read-only inspection, the copy is pure waste — the caller never mutates
the decoded value and the source buffer outlives the decoded tree.

#### API

```go
// WithZeroCopy configures the decoder to return byte strings and text
// strings as views into the source buffer rather than independent copies.
//
// SAFETY CONTRACT: The caller MUST NOT mutate src after calling Decode,
// and MUST NOT use any decoded Value (or its sub-values) after src is
// freed or reused. Violating this contract produces undefined behavior
// (data corruption, not panics — the library cannot detect misuse at
// runtime without negating the performance benefit).
//
// Zero-copy values are indistinguishable from copied values at the API
// level. The only observable difference is allocation count and the
// lifetime coupling to src.
func WithZeroCopy() DecoderOption
```

#### Implementation

In `decodeBytes`:
```go
if opts.ZeroCopy {
    return cbor.BytesView(src[start:end]), end, nil  // no copy
}
buf := make([]byte, length)
copy(buf, src[start:end])
return cbor.Bytes(buf), end, nil
```

In `decodeText` (requires Go 1.20+ `unsafe.String` or a build-tagged path):
```go
if opts.ZeroCopy {
    s := unsafe.String(&src[start], length)
    return cbor.Text(s), end, nil  // no copy
}
s := string(src[start:end])
return cbor.Text(s), end, nil
```

`BytesView` is a constructor variant that sets a flag (or is simply
`Bytes` with documented semantics under zero-copy mode) indicating the
backing array is shared.

#### Sharp edges

- **Mutation of src corrupts decoded values silently.**
- **Use-after-free of src leaves dangling references in the Value tree.**
- Not compatible with streaming decode from `io.Reader` (no stable buffer).
- Must be documented as `unsafe`-grade — appropriate for performance-
  critical paths that have been profiled, not for general use.

---

### Extension 2: Per-decode arena allocator

#### Problem

After 016, container backing arrays (`[]Value` for arrays, `[]MapEntry`
for maps) are the dominant remaining allocations.  A document with 50
containers makes 50 separate `make()` calls.  Each call pays `mallocgc`
overhead, and the resulting objects are scattered in the heap (cache-
unfriendly).

#### API

```go
// Arena provides batch allocation for decode operations. A single Arena
// pre-allocates backing storage for Value slices and MapEntry slices,
// eliminating per-container heap allocations.
//
// Arenas are NOT goroutine-safe. One arena per decode call (or per
// goroutine with explicit reuse via Reset).
//
// LIFECYCLE: All Values decoded into an Arena share the arena's backing
// storage. When the Arena is Reset or garbage-collected, those Values
// become invalid. Callers who need Values to outlive the arena must
// copy them via Value.Clone().
type Arena struct {
    values []Value      // backing slab for arrays and tag inners
    pairs  []MapEntry   // backing slab for maps
    vOff   int
    pOff   int
}

// NewArena creates an arena pre-sized for approximately n values and
// m map entries. The arena grows if needed but pre-sizing avoids
// growth for known workloads.
func NewArena(values, pairs int) *Arena

// Reset resets the arena for reuse without freeing the backing storage.
// All Values previously decoded into this arena become invalid.
func (a *Arena) Reset()

// WithArena configures the decoder to allocate container backing from
// the provided arena instead of the heap.
func WithArena(a *Arena) DecoderOption
```

#### Usage pattern

```go
arena := rfc8949.NewArena(256, 64)  // pre-size for typical message
dec := rfc8949.NewDecoder(rfc8949.WithArena(arena))

for msg := range inbound {
    arena.Reset()
    val, _, err := dec.Decode(msg)
    if err != nil { continue }
    process(val)  // must complete before next Reset()
}
```

#### Implementation

The decoder calls `arena.AllocValues(n)` instead of `make([]Value, n)`,
which returns a subslice of the pre-allocated slab:

```go
func (a *Arena) AllocValues(n int) []Value {
    if a.vOff+n > len(a.values) {
        a.grow(n)
    }
    s := a.values[a.vOff : a.vOff+n]
    a.vOff += n
    return s
}
```

For a 50-container document, this reduces 50 allocations to 1 (the
initial arena slab) or 0 (on reuse after Reset).

---

### Extension 3: String interning for repetitive map keys

#### Problem

Stream-decode scenarios (telemetry, logging, event buses) process
thousands of messages with identical map key sets ("type", "timestamp",
"id", "value", "source", etc.).  Each decode allocates a fresh `string`
for every key, even though the same ~5-10 strings appear in every
message.

#### API

```go
// StringInterner deduplicates decoded text strings. When the decoder
// encounters a text string that matches an existing entry, it returns
// the interned copy (zero allocation) instead of allocating a new string.
//
// StringInterner is NOT goroutine-safe by default. Use a synchronized
// variant (or per-goroutine instances) for concurrent decode.
type StringInterner struct {
    table map[string]string  // or a more efficient structure
    max   int                // cap to prevent unbounded growth
}

// NewStringInterner creates an interner with a maximum capacity.
// When capacity is reached, new strings are allocated normally
// (graceful degradation, not failure).
func NewStringInterner(maxEntries int) *StringInterner

// Prefill seeds the interner with known-frequent strings. These entries
// are never evicted.
func (si *StringInterner) Prefill(keys ...string)

// WithStringIntern configures the decoder to intern decoded text strings
// through the provided interner.
func WithStringIntern(si *StringInterner) DecoderOption
```

#### Usage pattern

```go
interner := rfc8949.NewStringInterner(1024)
interner.Prefill("type", "id", "timestamp", "value", "source")

dec := rfc8949.NewDecoder(rfc8949.WithStringIntern(interner))
// interner is reused across all decode calls on this decoder
```

#### Implementation

In `decodeText`, after extracting the raw bytes:
```go
if opts.Interner != nil {
    s := opts.Interner.Intern(src[start:end])
    return cbor.Text(s), end, nil
}
```

Where `Intern` does a map lookup on the byte slice (avoiding a string
allocation for the lookup via `unsafe` conversion or Go 1.20+
`string([]byte)` map optimization):

```go
func (si *StringInterner) Intern(raw []byte) string {
    // Go 1.20+: map lookup with []byte key avoids allocation
    if existing, ok := si.table[string(raw)]; ok {
        return existing  // zero alloc — reuse existing string
    }
    if len(si.table) >= si.max {
        return string(raw)  // at capacity, allocate normally
    }
    s := string(raw)
    si.table[s] = s
    return s
}
```

---

### Extension 4: Hash-based duplicate map key detection

#### Problem

`mapInsert` with `RejectDuplicateMapKeys` performs a linear scan on
every insertion — O(n²) for a map with n keys.  For large maps (100+
keys) in strict mode, this dominates CPU time.

#### API

No new public API — this is an internal optimization triggered
automatically when `RejectDuplicateMapKeys` is set and the map exceeds
a size threshold (e.g., 16 keys).  Optionally exposed for tuning:

```go
// WithDuplicateKeyStrategy selects the algorithm for duplicate key
// detection. The default is automatic (linear for small maps, hash for
// large maps).
func WithDuplicateKeyStrategy(s DuplicateKeyStrategy) DecoderOption

type DuplicateKeyStrategy int

const (
    DuplicateKeyAuto   DuplicateKeyStrategy = iota  // linear ≤16, hash >16
    DuplicateKeyLinear                              // always O(n²), lowest overhead for small maps
    DuplicateKeyHash                                // always hash, O(n) amortized
)
```

#### Implementation

For the hash path, compute a hash of the encoded key bytes (which are
already available during decode) and maintain a `map[uint64][]int`
(hash → list of indices with that hash) for collision handling:

```go
type keyDedup struct {
    seen map[uint64][]int  // hash → indices into the map slice
}

func (kd *keyDedup) check(m cbor.Map, key cbor.Value, encodedKey []byte) error {
    h := fnv1a(encodedKey)
    for _, idx := range kd.seen[h] {
        if valuesEqual(m[idx].Key, key) {
            return cbor.ErrDuplicateMapKey
        }
    }
    kd.seen[h] = append(kd.seen[h], len(m))
    return nil
}
```

The dedup state is pooled (via arena or sync.Pool) to avoid allocating
the hash map per-decode.

---

### Extension 5: Encode buffer pre-sizing

#### Problem

`Encode(nil, v, opts)` starts with a nil slice and grows it via
`append`.  For large values, this triggers multiple reallocation +
copy cycles (1→2→4→8→... growth).  Callers who know their approximate
output size (common for fixed schemas like COSE Sign1, CWT, EAT) pay
this cost unnecessarily.

#### API

```go
// EstimateSize returns a conservative estimate of the encoded size of v
// in bytes. The estimate is O(tree-size) in CPU but zero-allocation.
// It may overestimate by up to 9 bytes per container (maximum header
// size) but never underestimates.
//
// Use this to pre-allocate the destination buffer:
//   dst := make([]byte, 0, rfc8949.EstimateSize(v))
//   dst, err = rfc8949.Encode(dst, v, opts)
func EstimateSize(v cbor.Value) int

// EncodeWithHint is like Encode but pre-grows dst to at least hint bytes
// of capacity before encoding. If dst already has sufficient capacity,
// no reallocation occurs.
func EncodeWithHint(dst []byte, v cbor.Value, opts EncodeOpts, hint int) ([]byte, error)
```

#### Implementation

`EstimateSize` walks the Value tree summing:
- Scalars: 9 bytes (maximum head size)
- Bytes/Text: 9 + len(payload)
- Array: 9 + sum(EstimateSize(items))
- Map: 9 + sum(EstimateSize(key) + EstimateSize(value))
- Tag: 9 + EstimateSize(inner)

This is deliberately conservative (uses max header size, not shortest)
to avoid underestimation.

`EncodeWithHint` is trivial:
```go
func EncodeWithHint(dst []byte, v cbor.Value, opts EncodeOpts, hint int) ([]byte, error) {
    if cap(dst)-len(dst) < hint {
        grown := make([]byte, len(dst), len(dst)+hint)
        copy(grown, dst)
        dst = grown
    }
    return Encode(dst, v, opts)
}
```

---

### Extension 6: Deterministic map key order memoization

#### Problem

In deterministic mode, every `encodeMap` call encodes all keys to a
scratch buffer, sorts them, then writes the sorted output.  For COSE
and CWT, the same protected-header map (same keys, same order) is
encoded on every sign/verify/encrypt operation.  Re-encoding and
re-sorting the same keys every time is pure waste.

#### API

```go
// MapKeyOrder is a pre-computed sort order for a known set of map keys.
// It caches the encoded key bytes and their sorted order, eliminating
// the encode-sort-encode cycle for maps with stable key sets.
//
// MapKeyOrder is immutable after construction and safe for concurrent use.
type MapKeyOrder struct {
    encodedKeys [][]byte  // pre-encoded key bytes in sorted order
    sortedIdx   []int     // original index → sorted position
}

// PrecomputeMapOrder computes the deterministic key order for the given
// keys under the specified sort mode. The returned order can be reused
// across any number of encode calls with the same key set.
func PrecomputeMapOrder(keys []cbor.Value, mode SortMode, opts EncodeOpts) (*MapKeyOrder, error)

// EncodeMapPreordered encodes a map using a pre-computed key order.
// The map MUST have exactly the same keys (in any order) as were used
// to compute the MapKeyOrder. If the key set doesn't match, behavior
// is undefined (not checked at runtime for performance).
//
// Values are encoded in sorted key order using the pre-computed indices.
func EncodeMapPreordered(dst []byte, m cbor.Map, order *MapKeyOrder, opts EncodeOpts) ([]byte, error)
```

#### Usage pattern

```go
// One-time setup (e.g., in init or constructor):
headerKeys := []cbor.Value{cbor.Text("alg"), cbor.Text("kid")}
order, _ := rfc8949.PrecomputeMapOrder(headerKeys, rfc8949.SortBytewiseLex, opts)

// Hot path (called millions of times):
dst, err = rfc8949.EncodeMapPreordered(dst, protectedHeader, order, opts)
```

#### Implementation

`PrecomputeMapOrder` encodes each key once, sorts the encoded forms,
and stores the permutation.  `EncodeMapPreordered` writes the map
header, then iterates in pre-computed order emitting the cached encoded
keys and encoding only the values:

```go
func EncodeMapPreordered(dst []byte, m cbor.Map, order *MapKeyOrder, opts EncodeOpts) ([]byte, error) {
    dst = wire.AppendHead(dst, wire.MajorMap, uint64(len(m)))
    for i, keyBytes := range order.encodedKeys {
        dst = append(dst, keyBytes...)
        var err error
        dst, err = encode(dst, m[order.sortedIdx[i]].Value, opts)
        if err != nil {
            return dst, err
        }
    }
    return dst, nil
}
```

This eliminates: key encoding (N×key_size bytes of work), sort buffer
allocation, and sort comparison (N log N compares) — all replaced by a
single indexed iteration.

---

### Extension 7: Cursor-based lazy decode (skip without parsing)

#### Problem

Many CBOR consumers need only one or two fields from a large document.
The standard `Decode` parses the entire tree — allocating containers,
copying strings, building the full Value tree — only for the caller to
discard 95% of it.

#### API

```go
// Cursor provides lazy, forward-only traversal of CBOR data without
// decoding values that aren't accessed. It reads only the wire headers
// to determine structure and length, skipping over payloads until the
// caller requests a specific value.
//
// Cursors are NOT goroutine-safe and hold a reference to the source
// buffer.
type Cursor struct {
    src  []byte
    pos  int
    opts DecodeOpts
}

// NewCursor creates a cursor over the given CBOR data.
func NewCursor(src []byte, opts DecodeOpts) *Cursor

// Kind returns the CBOR major type of the current item without decoding it.
func (c *Cursor) Kind() (wire.Major, error)

// Skip advances past the current item (and all its children if it's a
// container) without decoding. Returns the number of bytes skipped.
func (c *Cursor) Skip() (int, error)

// Decode fully decodes the current item into a Value (standard decode).
func (c *Cursor) Decode() (cbor.Value, error)

// DecodeScalar decodes the current item only if it's a scalar (uint,
// negint, bool, float, null, undefined, simple). Returns ErrNotScalar
// if the current item is a container. Zero allocation for all scalar types.
func (c *Cursor) DecodeScalar() (cbor.Value, error)

// EnterArray positions the cursor at the first element of the current
// array. Returns the array length. After processing, call ExitArray
// to resume at the item following the array.
func (c *Cursor) EnterArray() (int, error)

// EnterMap positions the cursor at the first key of the current map.
// Returns the map pair count. Keys and values alternate: read key,
// read/skip value, read key, read/skip value, ...
func (c *Cursor) EnterMap() (int, error)

// ExitArray / ExitMap skips remaining items and positions the cursor
// after the container.
func (c *Cursor) ExitArray() error
func (c *Cursor) ExitMap() error

// FindMapKey scans forward in the current map for a text key matching
// the given string. Positions the cursor at the value for that key.
// Returns ErrKeyNotFound if the key doesn't exist.
// Note: only scans forward — cannot find keys already passed.
func (c *Cursor) FindMapKey(key string) error

// Offset returns the current byte offset in src.
func (c *Cursor) Offset() int

// RawBytes returns the raw CBOR bytes of the current item without
// decoding. Useful for forwarding, hashing, or deferred decode.
func (c *Cursor) RawBytes() ([]byte, error)
```

#### Usage pattern

```go
// Extract "alg" from a COSE protected header without decoding anything else:
cursor := rfc8949.NewCursor(protectedHeaderBytes, rfc8949.DecodeOpts{})
n, _ := cursor.EnterMap()
_ = cursor.FindMapKey("alg")
alg, _ := cursor.DecodeScalar()
// Done — never decoded the other 15 header fields
```

#### Implementation

`Skip` is the key operation — it reads the head, computes the total
byte span of the item (for definite-length) or scans for the break
code (indefinite), and advances `pos` without decoding any content.

For definite-length items, `Skip` is O(1) for strings/bytes (just add
header + payload length) and O(n) for containers (must skip each child
recursively — but no allocations, just pointer arithmetic).

---

### Extension 8: Streaming encode without Value construction

#### Problem

The existing `StreamEncoder` (§6) accepts `WriteValue(v Value)` which
still requires constructing a `Value` for every item.  For callers
driving encode imperatively (reading from a database cursor, iterating
a channel, constructing CBOR from non-CBOR sources), the Value
construction is pure overhead — they know the exact wire type and payload.

#### API

```go
// Direct-write methods on StreamEncoder — bypass Value construction.

func (s *StreamEncoder) WriteUint(v uint64) error
func (s *StreamEncoder) WriteNegInt(v uint64) error
func (s *StreamEncoder) WriteBytes(b []byte) error
func (s *StreamEncoder) WriteText(t string) error
func (s *StreamEncoder) WriteBool(v bool) error
func (s *StreamEncoder) WriteNull() error
func (s *StreamEncoder) WriteUndefined() error
func (s *StreamEncoder) WriteFloat32(v float32) error
func (s *StreamEncoder) WriteFloat64(v float64) error
func (s *StreamEncoder) WriteTag(id uint64) error  // next write is the tag's content
func (s *StreamEncoder) WriteSimple(v uint8) error

// WriteRawCBOR writes pre-encoded CBOR bytes directly to the output
// without validation. Use for forwarding already-encoded fragments.
// The caller is responsible for ensuring the bytes are valid CBOR.
func (s *StreamEncoder) WriteRawCBOR(raw []byte) error
```

#### Usage pattern

```go
s := enc.Stream(w)
s.BeginMap(3)
s.WriteText("id")
s.WriteUint(42)             // no Value allocation
s.WriteText("data")
s.WriteBytes(largePayload)  // streamed directly to w
s.WriteText("nested")
s.WriteRawCBOR(preEncoded)  // forwarded without re-parsing
s.EndMap()
s.Flush()
```

#### Implementation

Each `Write*` method encodes directly to the underlying `io.Writer`:
```go
func (s *StreamEncoder) WriteUint(v uint64) error {
    s.scratch = wire.AppendHead(s.scratch[:0], wire.MajorUint, v)
    _, err := s.w.Write(s.scratch)
    return err
}
```

No `Value` struct, no interface dispatch, no intermediate buffer beyond
a fixed-size scratch (9 bytes max for a head).

---

### Extension 9: Per-decode memory budget

#### Problem

Individual resource limits (`MaxByteStringLength`, `MaxArrayLength`,
`MaxNestingDepth`) gate specific shapes of abuse but don't prevent a
crafted payload from exhausting memory through many medium-sized
allocations.  A document with 10,000 arrays of 1,000 elements each
passes all individual limits but allocates ~80 MB.

#### API

```go
// WithMemoryBudget sets a global allocation budget for a single decode
// operation. The decoder tracks cumulative allocations and returns
// ErrMemoryBudgetExceeded when the total exceeds the budget.
//
// Budget is approximate — tracking is per-container and per-string,
// not per-byte. Overhead of tracking is negligible (one addition per
// allocation site).
//
// A budget of 0 disables tracking (the default).
func WithMemoryBudget(bytes int) DecoderOption

// ErrMemoryBudgetExceeded is returned when cumulative decode allocations
// exceed the configured memory budget.
var ErrMemoryBudgetExceeded = errors.New("cbor: memory budget exceeded")
```

#### Implementation

The decoder maintains a running counter:
```go
type decodeState struct {
    allocated int
    budget    int
}

func (ds *decodeState) charge(n int) error {
    ds.allocated += n
    if ds.budget > 0 && ds.allocated > ds.budget {
        return fmt.Errorf("%w: %d bytes used, budget %d",
            cbor.ErrMemoryBudgetExceeded, ds.allocated, ds.budget)
    }
    return nil
}
```

Every allocation site (`make([]Value, n)`, `make([]MapEntry, n)`,
`make([]byte, n)`, `string(...)`) calls `charge` with the approximate
allocation size before allocating.  If the budget is exceeded, decode
returns immediately with the error — no partial tree, no lingering
allocations from a half-decoded document.

---

### Extension 10: SIMD/branchless batch decode for homogeneous arrays

#### Problem

CBOR arrays where every element is the same major type (all uint, all
bytes of fixed length, all float64) are extremely common in telemetry
and sensor data.  The generic decode loop dispatches per-element through
the full type-switch machinery, paying branch-prediction and function-
call overhead for every item.

#### API

```go
// DecodeUintArray decodes a CBOR array where every element is major
// type 0 (unsigned integer) directly into a []uint64. Returns
// ErrTypeMismatch if any element is not a uint.
//
// This is a specialized fast path — it does not construct a Value tree
// and allocates only the result slice.
func DecodeUintArray(src []byte, opts DecodeOpts) ([]uint64, int, error)

// DecodeFloat64Array decodes a CBOR array of float64 (or promotable
// float16/float32) directly into a []float64.
func DecodeFloat64Array(src []byte, opts DecodeOpts) ([]float64, int, error)

// DecodeBytesArray decodes a CBOR array of byte strings into a [][]byte.
func DecodeBytesArray(src []byte, opts DecodeOpts) ([][]byte, int, error)

// DecodeTextArray decodes a CBOR array of text strings into a []string.
func DecodeTextArray(src []byte, opts DecodeOpts) ([]string, int, error)
```

#### Implementation

The fast path reads the array header, pre-allocates the result slice,
then enters a tight loop that expects a specific major type on every
element.  For `DecodeUintArray`, the inner loop is:

```go
for i := range count {
    if pos >= len(src) {
        return nil, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
    }
    b := src[pos]
    if b&0xe0 != 0x00 {  // not major 0
        return nil, pos, fmt.Errorf("%w at offset %d: expected uint, got major %d",
            ErrTypeMismatch, pos, b>>5)
    }
    arg, n := readArg(src[pos:])  // inlined, branchless for common cases
    result[i] = arg
    pos += n
}
```

On amd64, the `readArg` can be optimized with `encoding/binary`
load-and-mask patterns that the compiler can vectorize.  The key win
is eliminating: type-switch dispatch, Value construction, interface
boxing, and per-element function calls.

**Future**: architecture-specific assembly (SIMD) for packed arrays of
fixed-width items (e.g., 1000 × uint8 → 1000 single-byte CBOR items
can be bulk-verified with a single SIMD mask check).

---

## Interactions between extensions

Several extensions compose naturally:

| Combination | Effect |
|---|---|
| Arena + Zero-copy | Minimal allocations: arena for containers, zero-copy for leaves |
| Arena + String interning | Arena for structure, intern for key strings |
| Cursor + Zero-copy | Extract one field with zero allocations total |
| Pre-sizing + Key memoization | Tight encode loop: known size, no sort overhead |
| Memory budget + Arena | Budget tracks arena charges too (prevents arena overuse) |
| Streaming write + Key memoization | Write pre-sorted header directly, skip sort |

Incompatible combinations:

| Combination | Why |
|---|---|
| Zero-copy + Arena (for strings) | Zero-copy returns src subslices; arena wants to own the memory. Choose one for strings. |
| Cursor + Arena | Cursor doesn't decode containers — arena has nothing to carve |

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| Zero-copy decode: 0 allocs for scalar-only payload | `BenchmarkDecodeScalarsZeroCopy` shows 0 allocs/op | Yes |
| Zero-copy decode: byte string decode is 0-alloc | `BenchmarkDecodeBytesZeroCopy` | Yes |
| Arena decode: ≤ 2 allocs for deeply nested map (arena pre-sized) | `BenchmarkDecodeNestedMapArena` | Yes |
| Arena Reset: no allocs on second decode with reused arena | `BenchmarkDecodeArenaReuse` | Yes |
| String interning: steady-state 0 allocs for repeated keys | `BenchmarkDecodeRepeatedKeysIntern` | Yes |
| Hash dedup: O(n) for 1000-key strict map (vs O(n²) linear) | `BenchmarkDecodeStrictLargeMap` improvement ≥5x | Yes |
| Pre-sizing: 0 reallocs for known-size encode | `BenchmarkEncodePresized` shows 1 alloc (initial make) | Yes |
| Key memoization: encode hot-path map with 0 sort overhead | `BenchmarkEncodePreordered` vs `BenchmarkEncodeDeterministic` ≥30% faster | Yes |
| Cursor Skip: traversal of 1MB document in ≤ 1ms | `BenchmarkCursorSkipLarge` | Yes |
| Cursor FindMapKey: extract 1 field from 50-key map with ≤ 1 alloc | `BenchmarkCursorFindKey` | Yes |
| Streaming direct-write: 0 allocs per scalar write | `BenchmarkStreamWriteUint` shows 0 allocs | Yes |
| Memory budget: decode aborts at configured limit | `TestMemoryBudgetEnforcement` | Yes |
| Homogeneous array: DecodeUintArray ≥2x throughput vs generic decode | `BenchmarkDecodeUintArray` vs `BenchmarkDecodeScalars` | Yes |
| Default path unregressed: all §9 benchmarks within 2% | CI bench comparison gate | Yes |
| All extensions are opt-in: zero impact when not configured | `BenchmarkDecode_NoExtensions` matches baseline | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | Zero-copy decode + supporting `BytesView` semantics | Pending | 0-alloc byte/text decode on benchmarks |
| B | Arena allocator + WithArena decoder option | Pending | ≤ 2 allocs for nested map; reuse works |
| C | String interning + WithStringIntern option | Pending | Steady-state 0 allocs for repeated keys |
| D | Hash-based dedup (auto-switch at threshold) | Pending | 5x improvement on 1000-key strict map |
| E | Encode pre-sizing (EstimateSize + EncodeWithHint) | Pending | 0 reallocs for pre-sized encode |
| F | MapKeyOrder memoization (PrecomputeMapOrder) | Pending | ≥30% improvement on hot-path deterministic encode |
| G | Cursor-based lazy decode | Pending | Skip + FindMapKey benchmarks pass |
| H | Streaming direct-write methods | Pending | 0-alloc scalar write to io.Writer |
| I | Per-decode memory budget | Pending | Budget enforcement test passes |
| J | Homogeneous array fast paths | Pending | ≥2x throughput for DecodeUintArray |

Phases A-D are decode-side and can proceed in parallel.  Phases E-F are
encode-side and can proceed in parallel with A-D.  Phase G is
independent.  Phase H depends on the existing StreamEncoder.  Phase I
is independent.  Phase J depends on Phase A (shares the no-alloc
decode patterns).

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestZeroCopyLifetime` | Decoded values alias src; mutation visible | `rfc8949/zerocopy_test.go` |
| `TestZeroCopyIncompatibleWithReader` | Error on WithZeroCopy + DecodeFrom | same |
| `TestArenaReset` | Values invalid after reset (best-effort check) | `rfc8949/arena_test.go` |
| `TestArenaGrowth` | Arena grows gracefully beyond initial size | same |
| `TestInternCapLimit` | Interner degrades to alloc at capacity | `rfc8949/intern_test.go` |
| `TestInternPrefill` | Prefilled keys never evicted | same |
| `TestHashDedupCorrectness` | Same results as linear dedup | `rfc8949/dedup_test.go` |
| `TestHashDedupThreshold` | Auto-switch at 16 keys | same |
| `TestEstimateSize` | Never underestimates; overestimates ≤9 per node | `rfc8949/estimate_test.go` |
| `TestMapKeyOrderEquivalence` | Preordered output == standard deterministic | `rfc8949/preorder_test.go` |
| `TestCursorSkip` | Skip advances correctly for every major type | `rfc8949/cursor_test.go` |
| `TestCursorFindMapKey` | Finds keys, returns ErrKeyNotFound for missing | same |
| `TestStreamDirectWrite` | Output matches Encode for same logical value | `rfc8949/stream_write_test.go` |
| `TestMemoryBudget` | Exceeds budget → ErrMemoryBudgetExceeded | `rfc8949/budget_test.go` |
| `TestDecodeUintArray` | Correct values; rejects non-uint elements | `rfc8949/homogeneous_test.go` |
| `FuzzCursorSkipMatchesDecode` | Skip(n) + Decode == Decode at same offset | fuzz target |
| `FuzzZeroCopyRoundTrip` | encode(zeroCopyDecode(x)) == encode(normalDecode(x)) | fuzz target |

---

## Performance

| Metric | Current (baseline) | Target (with extension) | Test mechanism |
|---|---|---|---|
| Decode nested map allocs (arena) | ~6 (post-016) | ≤ 2 | `-benchmem` |
| Decode scalar-only (zero-copy) | 1 alloc/op | 0 allocs/op | `-benchmem` |
| Decode repeated-key stream (intern) | N allocs/msg | ~0 allocs/msg (steady state) | `-benchmem` |
| Strict 1000-key map (hash dedup) | ~500ms | ~50ms | `go test -bench` |
| Encode COSE header (key memo) | 150ns | ≤100ns | `go test -bench` |
| Cursor skip 1MB document | — | ≤1ms | `go test -bench` |
| Stream write uint (no Value) | 1 alloc | 0 allocs | `-benchmem` |
| DecodeUintArray vs generic | 1x | ≥2x throughput | `go test -bench` |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Zero-copy misuse (use-after-free of src) | high (users will misuse) | high (silent corruption) | Document aggressively; lint rule suggestion; `go vet` analyzer proposal |
| Arena lifecycle confusion (use after Reset) | medium | medium (stale data) | Best-effort poisoning in debug builds (fill freed slabs with sentinel); document clearly |
| String interner unbounded growth | medium | low (OOM in extreme case) | Hard cap with graceful degradation; `max` parameter required |
| Cursor API complexity (forward-only, enter/exit state machine) | medium | low (user confusion) | Clear docs; panics on misuse (exit without enter, etc.) |
| `unsafe.String` dependency for zero-copy text | low | low (build-tag alternative available) | Provide safe fallback (`//go:build !unsafe_zerocopy`) that copies; default to unsafe on Go 1.20+ |
| SIMD/arch-specific code maintenance burden | medium | medium | Gate behind build tags; fallback to generic Go; only for Phase J |
| API surface bloat (too many knobs) | medium | medium (user paralysis) | Group into "profiles" (`DecodeOpts.Performance = PerformanceMaxThroughput`) for common combos |
| Default-path regression from opt-in check overhead | low | high | Each extension check is a single nil/zero comparison; benchmark gate in CI |

---

## Alternatives considered

### Single "fast mode" flag instead of granular knobs

Rejected.  A single flag forces all-or-nothing tradeoffs.  A caller who
wants arena allocation but not zero-copy (because they mutate decoded
byte strings) would have to give up both or accept both.  Granular knobs
let callers opt into exactly the tradeoffs they've profiled for.

However: a **preset** that combines compatible extensions is valuable for
discoverability.  Proposed (non-normative, sugar only):

```go
func MaxThroughputOpts() DecodeOpts {
    return DecodeOpts{
        ZeroCopy:  true,
        Arena:     NewArena(1024, 256),
        Interner:  NewStringInterner(4096),
        DedupMode: DuplicateKeyHash,
    }
}
```

### Implement all extensions in a separate `fastcbor` package

Rejected.  Splitting the optimization surface into a separate package
creates a fork-choice problem: callers must decide at import time
whether they might ever need performance extensions.  Extensions belong
in the same `rfc8949` package, behind opt-in options, using the same
types.  No separate type universe, no adapter layer.

### Use `go:linkname` or runtime hacks for zero-copy string

Rejected.  `go:linkname` is unstable across Go versions and explicitly
discouraged.  `unsafe.String` (Go 1.20+) is the supported mechanism
for zero-copy string construction from a byte slice.  A build-tag
fallback covers older compilers.

### Make arena the default (automatic pooling)

Rejected.  Arenas have lifecycle semantics that differ from normal Go
garbage collection.  Making them the default would introduce
use-after-Reset bugs for callers who hold decoded Values beyond a single
decode call.  The default path must remain "safe Go" — no lifecycle
management, no dangling references, no surprises.

### Generate SIMD assembly for all architectures

Rejected for initial scope.  Phase J starts with pure-Go branchless
patterns that the compiler can auto-vectorize on amd64/arm64.  Hand-
written assembly is a future follow-up only if the compiler can't close
the gap, and only for amd64 (largest deployment target).

---

## Open questions

- **Zero-copy + GC interaction**: If `src` is a pooled buffer that gets
  returned to a `sync.Pool`, decoded Values silently alias freed memory.
  Should we provide a `Value.Detach()` method that copies the backing
  data, converting a zero-copy value into an independent one?  Lean: yes,
  as a safety valve.

- **Arena sizing heuristics**: Should the arena expose a `Stats()` method
  (peak usage, growth count) so callers can tune their pre-size?
  Lean: yes, zero-cost when not called.

- **Interner eviction policy**: LRU, LFU, or none (just cap + degrade)?
  Lean: none (simplest; cap + degrade).  CBOR map keys are typically a
  small fixed set — eviction logic adds complexity for a case that
  rarely occurs in practice.

- **Cursor + streaming decode composition**: Should `Cursor` work over
  `io.Reader` (buffered) or only `[]byte`?  Lean: `[]byte` only for
  Phase G.  Reader-backed cursor is significantly more complex (can't
  seek backward, can't return `RawBytes` cheaply).

- **Homogeneous array detection**: Should the generic `Decode` auto-
  detect homogeneous arrays and dispatch to the fast path, or should
  callers always call `DecodeUintArray` etc. explicitly?  Lean: explicit
  only.  Auto-detection adds a speculative branch to the hot path and
  the cost of a wrong guess (fallback to generic) may exceed the benefit.

- **Profile presets**: How many presets and what names?  Candidates:
  - `PerformanceMaxThroughput` (zero-copy + arena + intern + hash dedup)
  - `PerformanceLowLatency` (zero-copy + cursor, no arena overhead)
  - `PerformanceConstrained` (arena only, no unsafe)
  Lean: ship the individual knobs first, add presets in a follow-up
  based on observed usage patterns.

---

## Cross-references

- Spec: §9 of `encoder-decoder-spec.md` (performance requirements)
- Proposal 016 — tagged-union struct (prerequisite; eliminates interface
  boxing)
- Proposal 017 — COSE encoder reuse (complements key memoization)
- Proposal 015 — TinyGo support (constrains which extensions can use
  `unsafe` or `sync.Pool`)
- Proposal 001 Phase 4 — mentions "buffer pooling" and "decode allocator
  amortization" as future work; this proposal is that work, specified.
- Go 1.20 release notes: `unsafe.String`, `unsafe.SliceData`
- Go runtime `mallocgc` source: understanding allocation cost
- Prior art: `github.com/valyala/fastjson` (arena-based JSON decode),
  `github.com/bytedance/sonic` (SIMD JSON), `github.com/segmentio/encoding`
  (zero-copy JSON strings)

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-23 | Initial draft | corecbor maintainers |
