# 021 — Core codec safety fixes

## Header

| Field | Value |
|---|---|
| **Number** | 021 |
| **Tier** | 1 |
| **Status** | Draft |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 008 (Marshal/Unmarshal), 016 (struct Value), 020 (internal arena), 034 (compatibility policy) |
| **Supersedes** | none |
| **Spec sections touched** | §2.3, §2.5, §3.4, §4.3, §5, §6.1, §7.1 |

---

## TL;DR

A review of the root package on 2026-11-20 found defects that cause
data races, silent memory corruption, panics on untrusted input, and
wrong output on the wire. All of them were reproduced with throwaway
probe tests, and every one breaks a MUST in the spec. This proposal
fixes them without redesigning anything. Each fix comes with a
regression test that fails on `main@00e1307`.

Two related defects are out of scope here:

- `RawMessage` re-encodes its content (the bytes aren't raw). Covered by
  [022](022-raw-byte-preservation.md).
- `StrictDecoder` rejects every tag. Covered by
  [023](023-strict-decode-policy-and-errors.md).

Acceptance: every regression test in the table below passes under
`go test -race ./...`, the new fuzz targets run for 60 s in CI without
findings, and no §9 metric regresses by more than 5% against
`engineering-docs/bench-020-baseline.txt`.

---

## Motivation

The spec makes three promises that these defects break.

- §2.3 and §3.4: "Panic on caller input" is forbidden, on both the
  encoder side and the decoder side.
- §2.1: deterministic modes are "byte-identical for equal inputs".
- §3.2 and §8.2: the library is meant for inputs that feed
  cryptographic primitives. A race in the deterministic encoder can
  produce wrong bytes that then get signed.

These were found by probe tests, not by the fuzz catalog (§7.1). That
shows a coverage gap, which this proposal also closes (see Test
surface).

| # | Defect | Evidence | Observed |
|---|---|---|---|
| D1 | Package-level `Marshal` and `Unmarshal` race with each other. `defaultEncoder` comes from `New` instead of `NewShared`, so `SortStateCache.used` is shared without synchronization. `defaultDecoder` has one internal arena that every `Decode` call resets. | `marshal.go:31-34`, `rfc8949/encode.go:35-51`, `decoder.go:136-141` | `-race`: `DATA RACE … rfc8949.(*Arena).Reset()` from two `corecbor.Unmarshal` goroutines |
| D2 | The arena aliases into values the caller keeps. A `cbor.Value` struct field, or a tag returned through `any`, is stored straight from arena-backed memory, and the next `Decode` on the same decoder overwrites it. | `reflect_decode.go:54` (`target.Set(reflect.ValueOf(val))`), `reflect_decode.go:343` (`case KindTag: return val`) | `s1.X` read `zzzz yyyy` after the second `Unmarshal` (it had been `aaaa bbbb`) |
| D3 | Untrusted input can panic. Decoding into `any` builds a `map[any]any` whose keys can be `[]byte`, `[]any`, or `map[...]`, and those types can't be map keys in Go. | `reflect_decode.go:330-334` | `{h'01': 1}` panics: `hash of unhashable type []uint8` |
| D4 | Embedded struct fields are written under the wrong keys. `getStructFields` sets `ef.index = i`, the index of the *embedded* field, so every promoted field encodes as the whole embedded struct. | `reflect_encode.go:309-316`; read via `rv.Field(fi.index)` at `:256` and `reflect_decode.go:281` | `Outer{Inner{A:1,B:"x"},C:2}` encodes as `{"a":{"a":1,"b":"x"},"b":{"a":1,"b":"x"},"c":2}` |
| D5 | Times and bignums are converted wrongly. `TimeTo` encodes pre-epoch times as huge uints. `AsTime` overflows when the uint is greater than MaxInt64, or when the float exceeds the int64 range of nanoseconds. A NaN float gives an undefined result. `BigIntTo(nil)` panics. | `cbor/tags.go:56-58`, `:38-46`, `:91` | `TimeTo(time.Unix(-10,0))` emits `1(18446744073709551606)` |
| D6 | `StreamEncoder` gets nesting and determinism wrong. `BeginArray` and `BeginMap` don't count against the parent container, so an overflow isn't detected. Maps in deterministic modes aren't sorted, which breaks the §2.1 promise. Overflow and underflow errors are bare `errors.New`, against §5. | `stream.go:57-101`, `:168-184`, `:45` | `BeginArray(1); BeginArray(0); End; BeginArray(0)` produced the malformed `818080` with no error. Writing a Core Deterministic map with keys `"b","a"` produced `a2 6162 01 6161 02` |
| D7 | Negative integers come back wrong. In `valueToAny`, `-1 - int64(n)` wraps when n ≥ 2^63. Struct key lookup does `int64(UintVal())` and `-1 - int64(NegIntVal())` without checking range, so a wrapped key can match the wrong field. | `reflect_decode.go:310`, `:264`, `:270` | -2^64 decodes to `0`. uint 2^64-1 matches a field tagged `cbor:"-1"` |
| D8 | `DecodeSequence` never resets `Budget.Allocated`, so the memory budget accumulates across calls. It also skips the internal arena; that is fine, but the docs don't say so. | `sequence.go:68-80` vs `decoder.go:133-135` | (by inspection) |
| D9 | `WithBufferPool` does an unchecked type assertion `.(*[]byte)`. A pool with a nil `New`, or one holding a different type, panics. | `encoder.go:77` | (by inspection) |

---

## Proposal

### D1 — Concurrency contract

- Construct `defaultEncoder` with `NewShared(ModeCoreDeterministic)`.
- Construct `defaultDecoder` with `NewDecoder(WithoutInternalArena())`.
  Package-level `Unmarshal` must be goroutine-safe, which matches the
  contract callers already expect from `encoding/json`.
- Add a godoc concurrency section to `Encoder` and `Decoder`:

```go
// Concurrency: an *Encoder from New is NOT safe for concurrent use;
// use NewShared for values shared across goroutines. A *Decoder with
// its internal arena (the default) is NOT safe for concurrent use and
// returned Values are valid only until the next Decode; construct with
// WithoutInternalArena() to obtain a goroutine-safe decoder whose
// results outlive the call. Package-level Marshal/Unmarshal are safe
// for concurrent use.
```

- `SortStateCache` stays goroutine-local by design. Its comment
  (`rfc8949/encode.go:35`) gains a "must not be shared" note.

### D2 — Arena results never escape through reflection

`Decoder.Unmarshal` creates Go values that the caller owns. When the
destination is a `cbor.Value` (directly or nested) or an interface
holding a tag `Value`, the reflection layer stores `val.Clone()`. That
copy is independent of both the arena and zero-copy source storage
(`cbor/value.go:174`).

The clone is skipped when the decoder has no arena and no zero-copy:
`d.cfg.noInternalArena && d.cfg.opts.Arena == nil && !d.cfg.opts.ZeroCopy`.
The arena-backed fast path for scalar and struct targets is unaffected.

### D3 — Hashable keys for `any`

`valueToAny` maps CBOR map keys to Go types that can always be map
keys:

| CBOR key kind | Go key in `map[any]any` |
|---|---|
| Uint / NegInt / Bool / Text / Float | as today |
| Bytes | `string(bytes)` wrapped as `cbor.ByteKey` (new named string type) |
| Array / Map / Tag | the key's Core Deterministic encoding, wrapped as `cbor.EncodedKey` (new named string type) |
| Null / Undefined | `cbor.Value` (comparable once Items/Pairs are nil) |

```go
// ByteKey is used as a Go map key when a CBOR map key is a byte string.
type ByteKey string

// EncodedKey is used as a Go map key when a CBOR map key is a container
// or tag; the string holds the key's Core Deterministic encoding.
type EncodedKey string
```

Callers who need the original key type should decode into
`cbor.Value`, or into `[]MapEntry` with 025's accessors. The same
treatment applies to `cwt.fromValue` (`cwt/claims.go:264`), tracked in
proposal 031.

### D4 — Embedded struct field paths

Replace `fieldInfo.index int` with `index []int` and read fields with
`rv.FieldByIndex`. Name conflicts follow the `encoding/json` rules:

1. The shallowest field wins.
2. Among fields at the same depth, a tagged field wins over an
   untagged one.
3. Any remaining tie drops all the conflicting fields.

Embedded pointers to structs are supported. On encode, a nil embedded
pointer omits its fields. On decode, it is allocated. Results are
cached per `reflect.Type` in a `sync.Map`. That also fixes the
per-call cost of `getStructFields`; see the 025 cross-reference.

### D5 — Time and bignum helpers

```go
// TimeTo encodes t as tag 1 with an integer epoch-seconds argument
// (major 0 for t >= epoch, major 1 for t < epoch). Sub-second
// precision is truncated; use TimeToFloat to retain it.
func TimeTo(t time.Time) Value

// AsTime returns an error wrapping ErrTimeRange if the encoded instant
// is outside the range representable by time.Time, or if a float
// argument is NaN or ±Inf.
func AsTime(t Value) (time.Time, error)

// BigIntTo returns Null() for a nil n.
func BigIntTo(n *big.Int) Value
```

New sentinel: `ErrTimeRange = errors.New("cbor: time value out of range")`,
added to the §5 catalog.

For float epochs, `AsTime` splits the value with `math.Modf` so the
seconds don't overflow when multiplied by 1e9. Unify `timeToValue` in
`reflect_encode.go:204` with `TimeTo`, since the reflect path already
handles negative times correctly.

### D6 — StreamEncoder correctness

- `BeginArray` and `BeginMap` call `trackWrite()` on the parent before
  pushing the new frame, the same way `WriteTag` should. Tags count as
  part of the item they wrap, so `WriteTag` must not call `trackWrite`.
  The tagged item's own write does.
- **Deterministic map order: validate, don't sort.** In deterministic
  modes, each map frame keeps the encoded bytes of the previous key and
  a hash set of seen keys. When a new key isn't strictly greater than
  the previous one under the mode's `SortMode`, the stream returns
  `ErrStreamMapOrder` (wrapping new sentinel `ErrNotDeterministic`, see
  024). It costs one key's bytes per open map, so §9's 8 KiB ceiling
  still holds.
  - We rejected buffering and sorting, because it breaks the §6.1
    no-intermediate-buffer rule.
  - We rejected banning `BeginMap` in deterministic modes, because
    callers streaming CTAP2 or COSE maps with keys known ahead of time
    need it.
  - Callers who can't pre-sort should build a `Value` and use
    `EncodeTo`.
- Replace the `errors.New` calls with sentinels:

```go
var (
	ErrContainerOverflow  = errors.New("corecbor: stream container overflow")
	ErrContainerUnderflow = errors.New("corecbor: stream container underflow")
	ErrNoOpenContainer    = errors.New("corecbor: no open container")
	ErrStreamMapOrder     = errors.New("corecbor: stream map keys out of deterministic order")
)
```

### D7 — Integer range in reflection

- `valueToAny` returns `*big.Int` for NegInt n ≥ 2^63. The doc comment
  on `Unmarshal` states this.
- Struct int-key lookup rejects out-of-range keys: Uint > MaxInt64 or
  NegInt ≥ 2^63. Such a key is treated as unknown. With
  `DisallowUnknownFields` (025) it becomes an error.

### D8 and D9 — Sequence budget, buffer pool

- `DecodeSequence` resets the budget once per call, matching `Decode`.
- `WithBufferPool` wraps the pool so a nil or mistyped result
  allocates a fresh buffer instead of panicking. The godoc states the
  expected element type, `*[]byte`.

### Behavior / migration

- **D4 changes wire output.** Values encoded from embedded structs will
  differ after this change. The current output is not decodable by
  other implementations, so we treat this as a bug fix. It goes in the
  CHANGELOG under "breaking: wire format".
- **D3 changes decoded types.** The Go type of non-text, non-scalar map
  keys in `any` decoding changes. Today those inputs panic, so no
  existing caller can depend on the old behavior.
- Everything else is additive or a pure fix.

### Failure modes

New sentinels:

- `ErrTimeRange`
- `ErrContainerOverflow`
- `ErrContainerUnderflow`
- `ErrNoOpenContainer`
- `ErrStreamMapOrder` (also wraps `ErrNotDeterministic` from 024)

Each one is added to the §5 table. Nothing panics on caller input.

---

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).
Everything in this proposal is a **Defect**: races, aliasing, panics, or
wire output that other decoders read as a different value. Per 034,
defects get no selector. The root `CompatV02()` bundle includes nothing
from 021.

| Change | Class | Default (v0.30) | Selector |
|---|---|---|---|
| D1 package-level `Marshal`/`Unmarshal` concurrency | Defect | safe for concurrent use | none — defect |
| D2 decoded `cbor.Value`/`any` no longer alias the internal arena | Defect | independent copies | none — defect (callers wanting aliasing use `WithArena`, 018) |
| D3 non-hashable `any` map keys decode to `cbor.ByteKey` etc. instead of panicking | Defect | no panic | none — defect |
| D4 embedded-struct fields flattened on the wire | Defect | flattened (`encoding/json` rules) | none — defect. v0.2.2 output is pinned as a *negative* golden vector (documents the old bytes; not reproducible) |
| D5 `TimeTo` pre-1970 emits major type 1; `AsTime` range-checks | Defect | `c1 29` for −10 s | none — defect. Stored v0.2 values (huge uint) now return `ErrTimeRange`; the migration guide shows the one-line `int64(n)` reinterpretation for callers who must read them |
| D5 `BigIntTo(nil)` returns `Null()` | Defect | `Null()` | none — defect |
| D6 `StreamEncoder` counts nested containers; deterministic modes reject out-of-order map keys | Defect | `ErrContainerOverflow` / `ErrStreamMapOrder` | none — defect (callers that can't pre-sort use `EncodeTo`) |
| D7 negint ≥ 2^63 into `any` returns `*big.Int`; out-of-range int struct keys don't match | Defect | `*big.Int` / unknown key | none — defect |
| D8/D9 sequence budget reset; buffer pool type check | Defect | fixed | none — defect |

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| 8 goroutines × 200 iterations of `Marshal`+`Unmarshal` are race-free | `TestPackageLevelConcurrency` under `-race` | Yes |
| A `cbor.Value` field survives a subsequent `Unmarshal` on the same decoder | `TestUnmarshalValueFieldNotAliased`: decode `{"x":["aaaa","bbbb"]}`, then `{"x":["zzzz","yyyy"]}`; first result unchanged | Yes |
| `Unmarshal({h'01':1}, &any)` returns a map keyed by `cbor.ByteKey("\x01")`, no panic | `TestUnmarshalAnyBytesKey`, plus array, map, and tag keys | Yes |
| `Marshal(Outer{Inner{1,"x"},2})` == `a3 6161 01 6162 6178 6163 02` (Core Deterministic) | `TestEmbeddedStructFlattening`; also `encoding/json`-style conflict cases | Yes |
| `TimeTo(time.Unix(-10,0))` == `c1 29`; `AsTime(1(18446744073709551615))` returns `ErrTimeRange` | `TestTimeToNegative`, `TestAsTimeRange` | Yes |
| `BigIntTo(nil)` == `Null()` | `TestBigIntToNil` | Yes |
| The nested `BeginArray` overflow sequence returns `ErrContainerOverflow` | `TestStreamNestedOverflow` | Yes |
| A Core Deterministic stream map with keys `"b","a"` returns `ErrStreamMapOrder` | `TestStreamDeterministicKeyOrder` | Yes |
| -2^64 decoded into `any` is a `*big.Int` equal to -2^64 | `TestUnmarshalAnyNegIntOverflow` | Yes |
| uint 2^64-1 does not populate a field tagged `cbor:"-1"` | `TestStructIntKeyNoWrap` | Yes |
| Two `DecodeSequence` calls under `WithMemoryBudget(n)` each succeed when each fits in n | `TestDecodeSequenceBudgetReset` | Yes |
| `WithBufferPool(&sync.Pool{})` does not panic | `TestBufferPoolNilNew` | Yes |
| No §9 metric regresses by more than 5% against `bench-020-baseline.txt` | `make bench` + `benchstat` | Yes |
| D4 and D5 v0.2.2 outputs are captured in `testdata/legacy-v0.2.2/` as negative golden vectors, and the migration guide shows each before/after | golden test + doc review | Yes |
| No selector is added for any 021 change (034 Defect class) | API review | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | D1, D2, D3: race, aliasing, panic (the security-relevant ones) | Pending | First three rows pass |
| 2 | D4, D7: reflection correctness | Pending | Embedded and int-key rows pass |
| 3 | D5, D6, D8, D9: helpers, stream, misc | Pending | Remaining rows pass |

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| Regression tests named above | D1–D9 | `marshal_test.go`, `stream_write_test.go`, `cbor/tags_test.go`, `sequence_test.go` |
| `FuzzUnmarshalAnyNeverPanics` (new §7.1 target) | arbitrary bytes → `Unmarshal(&any)`, `&map[any]any`, and a struct with `cbor.Value`, `any`, embedded, and int-keyed fields; no panic | `fuzz_test.go` |
| `FuzzUnmarshalConcurrent` (new) | the same corpus decoded concurrently via package-level `Unmarshal` under `-race` | `fuzz_test.go` |
| `FuzzStreamMatchesBatch` (new §7.1 target) | random `Value` → write via `StreamEncoder`, pre-sorted for deterministic modes; bytes equal to `Encode` | `stream_write_test.go` |
| `FuzzDecodeNeverPanics` (existing) | extend its seed corpus with every probe input from this proposal | `testdata/fuzz/` |

---

## Performance

| Metric | Target | Test mechanism |
|---|---|---|
| `BenchmarkUnmarshal*` (package level, now without the internal arena) | ≤ 10% slower than baseline; justified because it fixes a race | `go test -bench Unmarshal -benchmem` |
| `BenchmarkDecode*` via an explicit `NewDecoder()` | unchanged (±3%) | same |
| Stream deterministic map key check | ≤ 1 key-sized allocation per open map | `-benchmem` on `BenchmarkStreamMap` |
| `Clone` on Value-typed fields | only when an arena or zero-copy is active | allocation count test |

If the package-level `Unmarshal` regression exceeds 10%, Phase 1 may
use a `sync.Pool` of internal-arena decoders instead. That is safe
because `unmarshalValue` copies out before the decoder goes back in
the pool, which the D2 fix guarantees.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| D4 output change breaks persisted data | low | med | The current output isn't interoperable. Release-note it, and leave an escape hatch via the `cbor:"name"` tag on the embedded field |
| `ByteKey`/`EncodedKey` surprise callers using `any` | med | low | Godoc it and point to `cbor.Value` decoding |
| Stream order check rejects maps callers emitted on purpose | low | med | Only in deterministic modes, where unsorted output already broke §2.1 |
| `Clone` adds allocations | med | low | Gated on arena or zero-copy being active. Benchmarked |

---

## Alternatives considered

- **Make `Decoder` itself goroutine-safe with a mutex.** Rejected:
  every caller would pay for the lock, and it still wouldn't fix D2,
  because results are invalidated by the next decode no matter which
  goroutine runs it.
- **Panic recovery in `Unmarshal`.** Rejected: §2.3 and §3.4 require
  typed errors by construction, and recovery hides further bugs.
- **Error on non-hashable `any` keys instead of mapping them.**
  Considered. It's simpler but makes valid CBOR (COSE_Key with bstr
  labels in private use) undecodable into `any`. We kept the mapping;
  an opt-in `RejectNonScalarAnyKeys` remains possible later.

---

## Open questions

1. Should `ByteKey` and `EncodedKey` live in `cbor` or the root? We
   propose `cbor`, re-exported from the root like the other `Value`
   types.
2. Should D6's order check be optional (`WithoutStreamOrderCheck`) for
   callers who already validate? Not proposed unless benchmarks
   justify it.

---

## Cross-references

- Spec: §2.1, §2.3, §3.4, §5, §6.1, §7.1, §9
- Proposals: [008](008-reflective-marshal-unmarshal.md), [014](014-raw-message-and-tag-wrapping.md), [020](020-default-decode-recovery.md), [022](022-raw-byte-preservation.md) (RawMessage re-encoding), [023](023-strict-decode-policy-and-errors.md) (tag policy, `DecodeError`), [024](024-serialization-profiles-alignment.md) (`ErrNotDeterministic`), 025 (reflection ergonomics, `DisallowUnknownFields`, field cache), 031 (CWT `fromValue` panic)
- RFCs: RFC 8949 §3.4.2 (epoch time, negative values), §3.4.3 (bignums), §5.6 (map keys)
- `encoding/json` embedded field rules: https://pkg.go.dev/encoding/json#Marshal

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft from the 2026-11-20 codebase review | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
