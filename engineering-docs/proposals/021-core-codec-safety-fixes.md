# 021 — Core codec safety fixes

## Header

| Field | Value |
|---|---|
| **Number** | 021 |
| **Tier** | 1 |
| **Status** | Closed |
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
- Package-level `Unmarshal` must be goroutine-safe, which matches the
  contract callers already expect from `encoding/json`. *As
  implemented:* each call takes an arena-backed `*Decoder` from a
  `sync.Pool`, so concurrent calls never share an arena and the default
  path keeps 020's arena performance. `defaultDecoder` (used by
  `DecodeSequence`, which doesn't touch the arena) is built with
  `WithoutInternalArena()`.
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
| Null / Undefined / simple | `nil`, unchanged from v0.2.2 (already hashable; `cbor.Value` isn't comparable because it holds slices) |
| NegInt below `math.MinInt64` | `cbor.EncodedKey` (as a value it decodes to `*big.Int`, D7) |

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

A tag that only sets options (`cbor:",omitempty"`) keeps the default
field name. v0.2.2 used the empty string as the key, contradicting
proposal 008's tag table. An embedded struct with a name in its tag is
a regular named field, not flattened (`encoding/json` rule).

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

### D10–D17 — Defects found while capturing v0.2.2 golden vectors

Added 2026-11-20. Each one is pinned by a golden vector (the id is in
parentheses) and moves to the module's `goldenChanges` allowlist in the
commit that fixes it.

- **D10 — `DecodeFrom` reads past the item and re-decodes quadratically**
  (`rfc8949/stream_decode.go:14-37`). It re-runs `Decode` over the whole
  buffer after every 256-byte read (O(n²) for an n-byte item) and
  discards the bytes it read beyond the first item (`_ = consumed`), so
  consecutive `DecodeFrom` calls on one reader lose data. Fix: when `r`
  is an `io.ByteScanner`/`*bufio.Reader`, read exactly one item by
  walking heads (`wire.ParseHead`) with the same nesting/length limits
  and preallocation bounds as `Decode`. Otherwise read only the bytes
  the item's heads declare, so nothing beyond the item is consumed.
  A truncated item returns `io.ErrUnexpectedEOF` wrapped with
  `ErrTruncated`.
- **D11 — `Diagnostic` prints −2^64 as `-0`** (`diagnostic.go`, NegInt
  path overflows int64) (`root/diag/negint-min`). Fix: format NegInt as
  `-1 - n` with unsigned arithmetic (`-18446744073709551616`).
- **D12 — `DiagIndicators()` doesn't mark encoding indicators**
  (`root/diag/indicators-*`). RFC 8949 §8.1 indicators for indefinite
  length (`[_ 1, 2]`) and non-shortest arguments (`0_0`) aren't emitted;
  `Diagnostic` with `DiagIndicators()` must work from the source bytes
  (cursor walk), since a decoded `Value` has lost them.
  `DiagnosticValue` documents that it can't show indicators.
- **D13 — `Diagnostic` renders invalid UTF-8 as a valid character**
  (`root/diag/invalid-utf8`). `61ff` prints `"\u00ff"`, which reads as
  the valid text U+00FF. Diagnostic notation has no text-string form for
  invalid UTF-8, so print the string's bytes with a comment that says
  what they are: `/ text, invalid UTF-8 / h'ff'`. The output stays
  readable and can't be mistaken for valid text.
- **D14 — Encoder emits ill-formed simple values** (`root/encode/simple-24`).
  `Simple(24)` through `Simple(31)` encode as `f818`…`f81f`, which RFC
  8949 §3.3 says MUST NOT be used. Fix: return `ErrReservedSimple`
  (new sentinel) from `Encode` for 24–31 (20–23 already have named
  kinds and encode as such). `Simple`'s godoc already states the valid
  range (`cbor/value.go:116-117`).
- **D15 — Deterministic modes encode duplicate map keys**
  (`root/encode/deterministic-dup-key`). RFC 8949 §5.6 says a map with
  duplicate keys isn't valid CBOR, and §4.2.1's ordering is undefined
  for them. Fix: in deterministic modes, adjacent equal encoded keys
  after sorting return `ErrDuplicateMapKey`. Permissive mode is
  unchanged (it emits what it's given, as documented).
- **D16 — Stray break byte reported as `ErrTruncated`**
  (`root/decode/stray-break`). `ff` outside an indefinite container
  isn't well-formed (RFC 8949 §3.2.1). Fix: return new sentinel
  `ErrUnexpectedBreak`. It's still a decode error, so callers checking
  `err != nil` are unaffected; callers matching `ErrTruncated` for this
  input were relying on a misreport.
- **D17 — Smaller fixes outside the root package**:
  - `cose.AlgHPKEBaseP256SHA256AES128GCM.String()` returns `"unknown"`
    (`cose/algorithm.go`). Fix: add the case. (cose `cose/alg-string-hpke`)
  - `cwt.Validator` with negative `Leeway` rejects unexpired tokens
    (`cwt/validate.go:31,37`). Fix: `Validate` returns
    `ErrInvalidValidator` (new) for `Leeway < 0` rather than silently
    tightening the window. (cwt `validator/negative-leeway`)

D4 is also clarified: per the `encoding/json` rules it already cites,
exported fields of an *unexported* embedded struct type, and fields of
embedded struct *pointers*, are promoted. v0.2.2 silently dropped both
(`root/marshal/embedded-unexported`, `root/marshal/embedded-pointer`).

### Implementation notes (2026-11-20)

Decisions taken while implementing, recorded so review can check them:

- **AI 31 on integer and tag heads** (`0x1f`, `0x3f`, `0xdf`) now returns
  `ErrReservedAI`. v0.2.2 read them as the value 0, which isn't
  well-formed (RFC 8949 §3) and let a duplicate key slip past
  `StrictDecoder`. Same class as D16.
- **D6 details.** A tag opens an item without counting it; a tag can't
  overflow a full container and a container can't end right after a
  tag; an indefinite map can't end right after a key. A repeated key in
  a deterministic stream returns `ErrStreamMapOrder`, which also wraps
  `ErrDuplicateMapKey`. `BeginMap` whose item count overflows `int`
  returns `ErrMaxArrayLength`. Key bytes are captured through a writer
  tee installed only while a key is being written.
- **D10 details.** `DecodeFrom` applies limits as each head arrives, so
  a structural error (limit, reserved AI, stray break, truncation) can
  surface before a content error that `Decode` would hit first.
  `BufferedReader` buffers internally (4 KiB) and gains `ReadByte`;
  `DecodeFromBuffered` is `DecodeFrom` on it. A stray break inside a
  `Stream` now surfaces through `Err()` instead of ending the stream.
- **D15** also applies to `PrecomputeMapOrder`. `StrictDecoder` still
  accepts keys that differ only in float width (1.0 as f16 vs f32);
  D15 refuses to re-encode them. Fixing decoder key equality is 024.
- **D3.** Typed `map[any]any` targets and non-empty interface targets
  (e.g. a `fmt.Stringer` field) panicked too; both now return errors or
  hashable keys (found by `FuzzUnmarshalAnyNeverPanics`).

Follow-ups found during implementation, not in 021's scope:

- `Cursor.skipItem` doesn't reject stray breaks, reserved AI or AI 31,
  and it recurses without a depth bound. → 022 (Cursor promotion).
- `StreamEncoder.WriteValue` writes floats without the mode's float rule
  and doesn't validate UTF-8 in text values. → D18 below.

### D18 — `StreamEncoder.WriteValue` ignores mode float rules and UTF-8

`WriteValue` should produce the same bytes as `Encode` for the same
value and mode (§6.1). Fix: route float and text values through the
same rules as `Encode` (shortest/forced-64 float per mode; UTF-8
validation unless `AllowInvalidUTF8`). Contract defect (§6.1).

### D19 — `Diagnostic` hides duplicate map entries

`Diagnostic` decoded into a `Value` and rendered that, and the
forgiving decoder resolves duplicate map keys last-wins, so
`a2 6161 01 6161 02` printed `{"a": 2}` and silently dropped `"a": 1`.
After D12 the indicators view rendered from bytes and showed both,
so the two views disagreed (`root/diag/map-dup-key`). A map with
duplicate keys is well-formed but not valid CBOR (RFC 8949 §5.6), and
diagnostic notation describes the data item as encoded (§8), so
`Diagnostic` now always renders from the source bytes after
validating them. Without `DiagIndicators()` the output is otherwise
unchanged (no `_` markers; indefinite strings shown concatenated).
`DiagnosticValue` still renders the `Value` it is given. Contract
defect (RFC 8949 §8).

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
No exported identifier changes signature. Every behavior change is a
**Safety defect** or a **Contract defect** (the implementation
contradicts what it documents), so per 034 none gets a selector and the
root `CompatV02()` bundle includes nothing from 021. New identifiers
(`ByteKey`, `EncodedKey`, `ErrTimeRange`, `ErrContainerOverflow`,
`ErrStreamMapOrder`, `ErrReservedSimple`, `ErrUnexpectedBreak`,
`cwt.ErrInvalidValidator`) are **Additive**.

| Change | Class | Contract restored | Existing identifiers in v0.30 | Selector |
|---|---|---|---|---|
| D1 package-level `Marshal`/`Unmarshal` concurrency | Safety defect | spec §2.5 "No goroutine-safety footguns" (`encoder-decoder-spec.md:160`); package-level functions are concurrency-safe by Go convention (`encoding/json`) | safe for concurrent use | none |
| D2 decoded `cbor.Value`/`any` targets no longer alias the internal arena | Safety defect | memory safety; `decoder.go:95-101` scopes arena lifetime to `Decode`, not `Unmarshal` targets | independent copies | none (aliasing remains available through `WithArena`, 018) |
| D3 non-hashable `any` map keys decode to `cbor.ByteKey`/`cbor.EncodedKey` instead of panicking | Safety defect | — (panic on untrusted input) | no panic; text-keyed and scalar-keyed maps decode exactly as in v0.2.2 | none |
| D4 embedded-struct fields flattened on the wire | Contract defect | proposal 008 struct mapping (`encoding/json` field rules) | flattened | none. v0.2.2 output pinned as a *negative* golden vector |
| D5 `TimeTo` pre-1970 emits major type 1; `AsTime` range-checks | Contract defect | RFC 8949 §3.4.2 (tag 1 = signed epoch seconds), which `TimeTo` (`cbor/tags.go:55`) and `AsTime` claim to implement | `c1 29` for −10 s; out-of-range input → `ErrTimeRange` | none (034: v0.2 output was not a valid time). Migration guide shows the `int64(n)` reinterpretation for stored v0.2 values |
| D5 `BigIntTo(nil)` returns `Null()` instead of panicking | Safety defect | — | `Null()` | none |
| D6 `StreamEncoder` counts nested containers; deterministic modes reject out-of-order map keys | Contract defect | `doc.go:12-17` (deterministic modes sort map keys); spec §6.1 | `ErrContainerOverflow` / `ErrStreamMapOrder` | none (callers that can't pre-sort use `EncodeTo`) |
| D7 negint ≥ 2^63 into `any` returns `*big.Int`; out-of-range int struct keys don't match | Contract defect | `marshal.go:41-46` (`Unmarshal` decodes the data into `v`; v0.2 produced a different integer) | `*big.Int` / unknown key; every in-range value decodes as in v0.2.2 | none |
| D8/D9 sequence budget reset; buffer-pool type check | Contract defect / Safety defect | `decoder.go:60-63` (budget is "for a single decode operation") | fixed | none |
| D10 `DecodeFrom` consumes exactly one item, linear time | Contract defect | `stream.go` godoc "reads exactly one CBOR value from r" | no over-read | none |
| D11–D13 diagnostic output: −2^64, indicators, invalid UTF-8 | Contract defect | RFC 8949 §8, §8.1 (which `Diagnostic` claims) | corrected text | none |
| D14 `Simple(24..31)` rejected at encode | Contract defect | RFC 8949 §3.3; `cbor/value.go:116-117` valid range | `ErrReservedSimple` | none |
| D15 duplicate keys rejected in deterministic modes | Contract defect | RFC 8949 §5.6, §4.2.1 (which the modes claim) | `ErrDuplicateMapKey` | none (Permissive unchanged) |
| D16 stray break → `ErrUnexpectedBreak` | Contract defect | RFC 8949 §3.2.1 | new sentinel | none |
| D19 `Diagnostic` renders every encoded map entry | Contract defect | RFC 8949 §8, §5.6 | duplicates shown | none |
| D17 HPKE alg `String()`; negative `Leeway` | Contract defect | `cose/algorithm.go` `String`; `cwt.Validator.Leeway` doc (tolerance) | fixed; `ErrInvalidValidator` | none |

No `...Option` parameters are appended to existing functions.

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
| No exported identifier present in v0.2.2 is removed, renamed, or retyped, and no method is added to an exported interface (034 API stability) | `apidiff` against `v0.2.2` for this module, run in `make check` | Yes |
| Existing identifiers called with no new options reproduce the v0.2.2 golden vectors, except the contract-defect fixes listed under Compatibility selection | `testdata/legacy-v0.2.2/` golden tests | Yes |

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
| 2026-11-20 | API stability (signature + semantics) per revised 034 | corecbor maintainers |
| 2026-11-20 | Add D10–D17 from v0.2.2 golden-vector capture; clarify D4 promotion rules | corecbor maintainers |
| 2026-11-20 | Implementation notes: D1 decoder pool; D3 null/simple keys unchanged; D4 option-only tags keep the field name | corecbor maintainers |
| 2026-11-20 | Implementation notes from D6/D10/D14–D16 work; add D18 (stream WriteValue float/UTF-8) | corecbor maintainers |
| 2026-11-20 | Add D19 (Diagnostic renders from bytes so duplicate keys aren't hidden) | corecbor maintainers |
| 2026-11-20 | Status: Closed (D1–D19 on main; CI green on linux/amd64 incl. fuzz) | corecbor maintainers |
