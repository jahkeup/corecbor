# corecbor — encoder/decoder requirements + acceptance criteria

**Status:** Foundational engineering spec. Tier-1 work.
**Filed:** 2026-05-20
**Owner:** corecbor maintainers

This document specifies the contract for corecbor's two halves: a **strict
RFC-conformant encoder** with required modes, and a **forgiving decoder** with
knobs to control strictness. Together they form the core of the library.

The spec is language-agnostic in the requirements layer. Go is the
implementation target and the example language; sample code blocks are Go.
The acceptance criteria are testable in any language with equivalent
primitives.

---

## 0 — Scope and non-goals

### In scope

- Encode + decode of every RFC 8949 (CBOR) major type and the standard tags
  required by RFC 8949 §3.4 + the IANA tags registry (subset, see §4).
- A strict encoder with selectable modes (Canonical, CTAP2, RFC 8949 Core
  Deterministic, plus a permissive default for codepaths that don't need
  determinism).
- A forgiving decoder with explicit per-feature strictness knobs.
- Streaming encode/decode for large payloads.
- Round-trip property: `decode(encode(v)) == v` for every value the encoder
  accepts.

### Out of scope (this spec, this phase)

- A schema/IDL layer (no Smithy/Protobuf-style definitions).
- A reflection-based "marshal arbitrary Go struct" surface — that lives in a
  follow-up package or a separate library that consumes corecbor's primitives.
- CBOR Sequence (RFC 8742) framing — addressed in a tier-2 proposal.
- COSE / CWT / CDDL — tier-3, separate libraries that depend on corecbor.

---

## 1 — Why two halves with different strictness postures

The library serves two distinct caller populations:

| Caller class | Encoder need | Decoder need |
|---|---|---|
| **Storage / cryptographic AAD** | Strict deterministic encoding (byte-identical output for byte-identical input across processes, architectures, library versions). | Strict — reject anything that wouldn't round-trip. |
| **Wire protocol implementation** | Strict spec-conformant; doesn't necessarily need determinism. | Permissive — accept the protocol's defined wire form even when peers emit non-canonical variants. |
| **Data interchange / integration** | Permissive default — encode "any sensible value" without forcing the caller to pick a mode. | Forgiving — accept legacy / quirky producers (other CBOR libraries with known divergences). |

**Postel's Law applied to CBOR**: be strict in what you produce (no choice of
output forms when the spec gives one), be liberal in what you accept (within
defined safety bounds, with knobs for callers who want to tighten). The
encoder enforces; the decoder negotiates.

---

## 2 — Encoder requirements

### 2.1 Required modes

The encoder MUST support at least four modes, selected at construction time.
Modes are immutable on a constructed encoder; switching modes constructs a
new encoder.

| Mode | Determinism | Map sort | Float encoding | Length encoding | Use case |
|---|---|---|---|---|---|
| `Permissive` (default) | none guaranteed | insertion order | shortest preserving | shortest | Casual encoding; round-trip safe but bytes may vary across runs |
| `Canonical` | byte-identical for equal inputs | bytewise-lex on bytes of encoded keys | shortest preserving | shortest | RFC 7049 "Canonical CBOR" (legacy spec) |
| `CTAP2` | byte-identical for equal inputs | bytewise-lex on encoded keys, then by length | float64 only | shortest | FIDO/WebAuthn |
| `CoreDeterministic` | byte-identical for equal inputs | bytewise-lex on encoded keys (keys sorted as encoded byte strings) | shortest preserving (incl. float16 if lossless) | shortest preserving | RFC 8949 §4.2.1 — the modern default for new protocols |

Mode names match RFC terminology; do not invent synonyms.

### 2.2 Required RFC 8949 conformance

The strict encoder MUST:

- Emit definite-length variants only. Indefinite-length forms are
  permissive-decode-accepted but never encoded.
- Use the shortest preferred encoding for arguments (per RFC 8949 §3.1) when
  the mode requires "shortest" (Canonical, CTAP2, CoreDeterministic). The
  Permissive mode MAY emit shortest by default; consumers SHOULD NOT depend
  on it.
- Reject NaN/Inf encoding by default; offer a per-encoder knob
  (`AllowNonFiniteFloats bool`) to permit NaN/Inf encoding for callers who
  consciously want it.
- For deterministic modes, normalize NaN to a single canonical bit pattern
  (RFC 8949 §3.4.7.2 / §4.2.2).
- Encode strings (major 3) as valid UTF-8. Reject non-UTF-8 input strings
  with a typed error in strict modes; offer a per-encoder knob
  (`AllowInvalidUTF8 bool`) to permit them in Permissive mode.
- Encode byte strings (major 2) without modification.

### 2.3 Encoder MUST NOT

- Silently re-order user-supplied list / array elements (lists are ordered).
- Apply any tag wrapping the user did not request.
- Allocate intermediate full-size buffers when streaming output is requested
  (see §6).
- Panic on caller input. Every malformed input MUST surface as a typed error.

### 2.4 Encoder API shape (Go example)

```go
// Encoder is constructed once per mode and reused per goroutine.
// Concurrent use across goroutines is safe; concurrent use of a single
// Encoder is not (the implementation may pool internal buffers).
type Encoder struct { /* unexported */ }

type Mode int

const (
    ModePermissive Mode = iota
    ModeCanonical
    ModeCTAP2
    ModeCoreDeterministic
)

// New constructs an encoder in the given mode. Options control
// per-encoder knobs that don't change the wire format choice.
func New(mode Mode, opts ...Option) *Encoder

type Option func(*encoderOptions)

func AllowNonFiniteFloats() Option
func AllowInvalidUTF8() Option
func WithBufferPool(p *sync.Pool) Option

// Encode appends the CBOR encoding of v to dst and returns the
// extended slice. dst MAY be nil (allocates fresh).
//
// Encode is the primary API. It validates v against the encoder's
// mode and emits bytes, returning a typed error on validation
// failure. The error SHOULD wrap a sentinel from the package's
// error catalog (see §5).
func (e *Encoder) Encode(dst []byte, v Value) ([]byte, error)

// EncodeTo writes the CBOR encoding of v to w in a streaming
// fashion, suitable for large payloads where holding the whole
// output in memory is impractical. Same validation, same errors;
// the only difference is the output sink.
func (e *Encoder) EncodeTo(w io.Writer, v Value) error
```

Note the `Value` type — see §4 for the value model.

### 2.5 Encoder acceptance criteria

| Criterion | Test mechanism |
|---|---|
| RFC 8949 conformance vector pass-through | Vendored test vectors from RFC 8949 Appendix A; every sample encodes byte-identical to the reference. |
| Determinism in `Canonical` / `CTAP2` / `CoreDeterministic` modes | Property test: encode the same logical value 100 times, assert all 100 outputs are byte-equal. Map-key shuffle test: build a map by inserting keys in 100 different orders, assert all 100 encoded forms are byte-equal. |
| `Permissive` mode is round-trip safe | Property test: `decode(encode(v)) == v` for every input the encoder accepts. |
| NaN/Inf rejection in strict mode | Negative test: encode `math.NaN()` returns `ErrNonFiniteFloat`. Same for `+Inf` / `-Inf`. |
| NaN normalization in deterministic modes | Encode `math.NaN()` with `AllowNonFiniteFloats()` ten times in `CoreDeterministic`; assert all ten outputs are the canonical NaN bit pattern. |
| Invalid-UTF-8 rejection in strict mode | Negative test: encode `String("\x80")` returns `ErrInvalidUTF8`. With `AllowInvalidUTF8()` opt-in: emits a non-conformant text string with a documented warning surface. |
| Streaming encoder allocates O(1) per item | Bench: `EncodeTo(io.Discard, hugeNestedMap)` under a tight `runtime.MemProfileRate` ceiling. Acceptance: <8 KiB resident growth across the encode regardless of input size. |
| No goroutine-safety footguns | Race-detector test: shared `*Encoder` used from N goroutines via `sync.Mutex`-bounded calls; cgo-style stress for pool reuse. |

---

## 3 — Decoder requirements

### 3.1 Strictness knobs (decoder is forgiving by default)

The decoder MUST be **forgiving by default** — accept every well-formed
CBOR byte sequence the spec defines, plus the well-known "common quirks"
(see §3.3) — and offer per-feature strictness knobs so callers who need
strict-input validation can opt in.

```go
type Decoder struct { /* unexported */ }

type DecoderOption func(*decoderOptions)

// Strictness knobs (defaults forgiving):
func RejectIndefiniteLength() DecoderOption
func RejectNonShortestArgs() DecoderOption          // §4.2.1 §3.1
func RejectInvalidUTF8() DecoderOption              // major 3 must be valid UTF-8
func RejectDuplicateMapKeys() DecoderOption         // RFC 8949 §5.6
func RejectUnknownTags() DecoderOption              // unknown major-6 IDs
func RejectNonFiniteFloats() DecoderOption          // NaN/Inf in major 7
func RejectNullMapKeys() DecoderOption              // some libs emit Null keys

// Resource limits (always enforced; the values are knobs):
func WithMaxNestingDepth(n int) DecoderOption       // default 256
func WithMaxArrayLength(n int) DecoderOption        // default 1<<20
func WithMaxByteStringLength(n int) DecoderOption   // default 16<<20

func NewDecoder(opts ...DecoderOption) *Decoder

func (d *Decoder) Decode(src []byte) (Value, error)
func (d *Decoder) DecodeFrom(r io.Reader) (Value, error)
func (d *Decoder) Stream(r io.Reader) Stream        // §6
```

### 3.2 Strict-mode preset

For the storage / AAD / cryptographic-input use case, a single preset locks
all relevant strictness knobs to "reject":

```go
// StrictDecoder returns a decoder that rejects every common
// CBOR malleability vector. Use for inputs feeding into
// cryptographic primitives where bit-equal round-trip is a
// security property.
func StrictDecoder(opts ...DecoderOption) *Decoder {
    return NewDecoder(append([]DecoderOption{
        RejectIndefiniteLength(),
        RejectNonShortestArgs(),
        RejectInvalidUTF8(),
        RejectDuplicateMapKeys(),
        RejectNonFiniteFloats(),
        RejectNullMapKeys(),
    }, opts...)...)
}
```

`RejectUnknownTags()` is NOT in the strict preset by default — many
protocols use registered tags the decoder doesn't natively model, and
rejecting them prevents the decoder from being a useful pass-through.
Callers who want it pass it explicitly.

### 3.3 Common quirks the forgiving decoder MUST handle

These are well-attested deviations from major CBOR encoders. The forgiving
decoder accepts; the strict decoder (or relevant `Reject*` knob) refuses.

| Quirk | Source | Forgiving behavior | Strict knob |
|---|---|---|---|
| Indefinite-length strings (major 2/3 with chunks) | RFC 8949 permits; many encoders emit | concatenate chunks, return single Value | `RejectIndefiniteLength()` |
| Indefinite-length arrays/maps | same | accumulate to definite-length Value | `RejectIndefiniteLength()` |
| Non-shortest argument encoding (e.g., `1` encoded as `0x18 0x01` instead of `0x01`) | older encoders, manual byte-construction | accept | `RejectNonShortestArgs()` |
| Float16 → Float32 promotion on decode | RFC 8949 permits decoders to promote | promote, no precision loss | n/a (always promotes; Float16 is read-only) |
| Duplicate map keys | RFC 8949 §5.6 says "MUST NOT" but doesn't say "decoder MUST reject" | last-write-wins | `RejectDuplicateMapKeys()` |
| Invalid UTF-8 in text strings | strict spec violation; common in older libs | accept; preserve raw bytes | `RejectInvalidUTF8()` |
| Unknown tag IDs | spec permits | wrap in opaque `Tag{ID, Value}` | `RejectUnknownTags()` |
| Self-describe tag (55799) at the head | RFC 8949 §3.4.6 magic | strip silently | n/a |
| Nested tags wrapping the same value | spec permits | preserve nesting in returned Value | n/a |
| Null map keys | spec violation; some libs emit | accept | `RejectNullMapKeys()` |
| Trailing bytes after first complete value | spec violation in single-value mode | reject by default in `Decode`; `Stream` accepts (next item starts there) | n/a |

### 3.4 Decoder MUST NOT

- Panic on any input. Every malformed input MUST surface as a typed error.
  This is non-negotiable for every fuzzer the library ships.
- Allocate unbounded memory on adversarial input. Resource limits
  (`MaxNestingDepth`, `MaxArrayLength`, `MaxByteStringLength`) are
  enforced before allocation, not after.
- Decode a tag's contents as more than an opaque Value. Tag interpretation
  is the caller's responsibility (or a higher-layer codec's).
- Consume from `io.Reader` past the end of the first complete value when
  called as `DecodeFrom` (vs `Stream`, which is iterator-shaped).

### 3.5 Decoder acceptance criteria

| Criterion | Test mechanism |
|---|---|
| RFC 8949 conformance vector pass-through | Same vectors as encoder; every sample decodes to the documented Value. |
| Forgiving acceptance of every quirk in §3.3 | One typed test per quirk per knob state (forgiving accepts; strict rejects). |
| Strict preset rejects every quirk in §3.3 | `StrictDecoder()` round-trip: every §3.3 quirk produces a typed error. |
| Resource-limit enforcement | Negative tests: depth-limit-exceeded, array-length-exceeded, byte-string-length-exceeded each return the corresponding typed error before any partial allocation. |
| No panics on adversarial input | Continuous fuzz at HEAD; `make fuzz` in CI runs each registered fuzzer for ≥ 1 minute with `-fuzztime`. |
| `Stream` decoder consumes incrementally | Bench: stream-decode 1 GiB of nested data with ≤16 KiB resident; assert via heap-alloc profiler. |

---

## 4 — Value model

### 4.1 Type hierarchy

The library exposes a `Value` interface with one variant per CBOR major type
+ tag. The value tree is the *output of decode* and the *input of encode* —
both halves operate on the same types.

| CBOR major type | Value variant (Go) | Purpose |
|---|---|---|
| 0 (uint) | `Uint(uint64)` | non-negative integers, range [0, 2^64-1] |
| 1 (negint) | `NegInt(uint64)` | negative integers; encoded value is `-1 - argument`, range [-2^64, -1] |
| 2 (bytes) | `Bytes([]byte)` | byte strings |
| 3 (text) | `Text(string)` | UTF-8 text strings (subject to `RejectInvalidUTF8`) |
| 4 (array) | `Array([]Value)` | ordered list |
| 5 (map) | `Map([]MapEntry)` (NOT `map[K]V`) | key-value list; see §4.2 |
| 6 (tag) | `Tag{ID uint64, Inner Value}` | tagged value; `Inner` is opaque |
| 7 (simple) | `Bool(bool)`, `Null{}`, `Undefined{}`, `Float32(float32)`, `Float64(float64)` | simple values + floats |

### 4.2 Why `Map` is `[]MapEntry`, not `map[Value]Value`

CBOR maps preserve key order on the wire (the decoder MUST preserve it for
indefinite-length maps and round-trip semantics). Go's native `map` does
not. CBOR map keys are also full Values (uints, byte strings, arrays,
tags); Go map keys are restricted.

```go
type MapEntry struct {
    Key   Value
    Value Value
}

type Map []MapEntry
```

This forces callers who want O(1) lookup to build an index from the slice.
The library MAY ship a helper:

```go
// AsMap returns a map[string]Value if every key is Text. Used
// by callers who know the schema. Returns ErrNonStringKey if
// any key is not Text.
func (m Map) AsMap() (map[string]Value, error)
```

### 4.3 Required tags (encoder must emit, decoder must surface)

Per RFC 8949 §3.4 + IANA registry, the library SHOULD model these
"well-known" tags as first-class:

| Tag | Meaning | Library handling |
|---|---|---|
| 0 | Standard date/time string (RFC 3339) | helper `AsTime` |
| 1 | Epoch-based date/time | helper `AsTime` |
| 2 / 3 | Unsigned/negative bignum | helper `AsBigInt` |
| 21 / 22 / 23 | Expected base64url / base64 / base16 conversion (decoder hint) | preserve as Tag |
| 24 | Encoded CBOR data item (nested) | helper `AsNestedCBOR` |
| 32 | URI | preserve as Tag |
| 35 | Regular expression | preserve as Tag |
| 55799 | Self-describe (CBOR magic) | strip on decode if at head |
| 258 | Mathematical-finite Set | preserve as Tag (encoder MAY emit on `MarkAsSet` API) |

Other tags pass through opaque (`Tag{ID, Inner}`); `RejectUnknownTags()`
turns this into an error.

---

## 5 — Error catalog

Every error returned MUST be one of the catalog members or wrap one. Callers
discriminate via `errors.Is`. Adding a new error type is a tier-1
proposal-level decision; ad-hoc `fmt.Errorf` without wrapping a sentinel is
forbidden.

| Error sentinel | Meaning | Layer |
|---|---|---|
| `ErrNonShortest` | argument encoded longer than necessary | decoder (knob) |
| `ErrIndefiniteLength` | indefinite-length variant encountered | decoder (knob) |
| `ErrInvalidUTF8` | text string contains invalid UTF-8 | encoder (strict) / decoder (knob) |
| `ErrDuplicateMapKey` | map key appears more than once | decoder (knob) |
| `ErrUnknownTag` | tag ID not in the knob's allowlist | decoder (knob) |
| `ErrNonFiniteFloat` | NaN / Inf without `AllowNonFiniteFloats` | encoder (strict) / decoder (knob) |
| `ErrNullMapKey` | map key is the Null value | decoder (knob) |
| `ErrTrailingBytes` | bytes remain after first complete value (single-value mode) | decoder |
| `ErrTruncated` | input ended mid-value | decoder |
| `ErrMaxNestingDepth` | nesting limit exceeded | decoder (always) |
| `ErrMaxArrayLength` | array element count exceeds limit | decoder (always) |
| `ErrMaxByteStringLength` | byte/text string length exceeds limit | decoder (always) |
| `ErrNonStringKey` | `Map.AsMap()` called on map with non-Text keys | helper |
| `ErrInvalidMode` | encoder constructed with unknown mode | encoder |

Wrapped errors carry context: `fmt.Errorf("%w at offset %d", ErrTruncated, off)`.

---

## 6 — Streaming

The library MUST support streaming on both halves so callers can encode/decode
payloads larger than memory.

### 6.1 Streaming encode

`Encoder.EncodeTo(w io.Writer, v Value) error` — writes incrementally. The
implementation MUST NOT buffer the full output; intermediate buffers are
bounded by the largest single primitive (a single byte string can be
arbitrarily large but is written as `[length-arg][payload]` directly to `w`).

For callers who want to drive the encode imperatively (write a header, write
N items, write a trailer), expose an imperative API:

```go
type StreamEncoder struct{ /* unexported */ }

func (e *Encoder) Stream(w io.Writer) *StreamEncoder

func (s *StreamEncoder) BeginArray(n int) error    // n=-1 for indefinite (Permissive mode only)
func (s *StreamEncoder) BeginMap(n int) error
func (s *StreamEncoder) WriteValue(v Value) error
func (s *StreamEncoder) EndArray() error
func (s *StreamEncoder) EndMap() error
func (s *StreamEncoder) Flush() error
```

### 6.2 Streaming decode

`Decoder.Stream(r io.Reader) Stream` — returns an iterator-shaped object.

```go
type Stream interface {
    Next() bool                // advances to next top-level value
    Value() Value              // current value; valid until Next()
    Err() error                // terminal error if Next() returned false
    Close() error              // releases reader-side resources
}
```

Useful for CBOR Sequences (RFC 8742) and for line-delimited CBOR-over-X
protocols.

---

## 7 — Fuzz testing

Where to fuzz, how aggressively, what targets to register. Fuzzing is not
optional; this section is part of the acceptance criteria.

### 7.1 Targets (each registered with `go test -fuzz`)

| Target | What it exercises | Seed corpus |
|---|---|---|
| `FuzzDecodeNeverPanics` | every `Decoder` configuration + arbitrary bytes; assert no panic, only typed errors | RFC 8949 vectors + every encoded form from prior fuzz hits |
| `FuzzDecodeRoundTripPermissive` | `decode(bytes)` then `encode(decoded)` then `decode(encoded)`; assert second decode equals first | same |
| `FuzzDecodeRoundTripStrict` | same, but with `StrictDecoder()` on both decodes; output of strict re-encode MUST be byte-equal to the strict-decoder-canonicalized form of input | strict-canonicalized RFC vectors |
| `FuzzEncodeAcceptsValidValue` | constructed `Value` trees (generated via property-based generator); every encode MUST succeed in `Permissive` mode | small hand-built tree set |
| `FuzzEncodeStrictDeterminism` | constructed `Value` trees; encode 10 times in `CoreDeterministic`; assert all 10 outputs byte-equal | same |
| `FuzzMapKeyOrderInvariance` | construct a map, encode in `CoreDeterministic`, shuffle the input order, re-encode; assert byte-equal | same |
| `FuzzStreamDecodeMatchesBatch` | stream-decode N values; batch-decode the same bytes as a CBOR Sequence; assert equal Value lists | sequence-shaped seeds |
| `FuzzResourceLimits` | inputs designed to exceed each `Max*` limit; assert the corresponding typed error before any allocation > 2x the limit | hand-crafted adversarial inputs |
| `FuzzTagPreservation` | encoded tags (known + unknown IDs) round-trip through decode + encode; assert tag ID + inner value preserved | RFC tags + random IDs |

### 7.2 Coverage discipline

- Every typed error in §5 MUST be reachable from at least one registered
  fuzz target (verified via a meta-test that walks the error catalog).
- Every fuzz failure goes into `testdata/fuzz/<TargetName>/` and stays there
  until the regression is fixed AND a corresponding hand-written test case
  is added to lock the fix in. Fuzz-corpus files are checked into the repo.
- The Makefile target `make fuzz` runs every registered fuzzer for the time
  set in `FUZZTIME` (default 30s). CI runs `FUZZTIME=2m make fuzz` on
  every push to `main`.
- Continuous-fuzzing (OSS-Fuzz integration or equivalent) is a tier-2
  enhancement, not a tier-1 acceptance criterion.

### 7.3 Fuzz target DOs and DON'Ts

**DO**

- Use `go test -fuzz` for the registered targets.
- Provide a generator-based seed corpus for valid-input fuzzers (the
  fuzzer's mutation finds the malformed cases; the seed bootstraps the
  state space).
- Assert structural properties (round-trip, determinism, no-panic), not
  byte-equality against fixtures (fixtures rot; properties don't).

**DON'T**

- Skip a fuzz target because "the unit tests cover it." Fuzzers find the
  unit-test gaps.
- Lower a `Max*` resource limit in the test default just to make a fuzzer
  happy. Fix the underlying allocation.
- Fuzz against `fmt.Errorf("...")`-wrapped errors without checking the
  sentinel via `errors.Is`. The wrap layer is allowed to drift; the
  sentinel is the contract.

---

## 8 — Edge cases and known use cases

### 8.1 Edge cases the implementation MUST handle correctly

These are the "things that look simple but break naïve implementations."
Each MUST have a typed test plus fuzz coverage.

| Edge case | What it tests |
|---|---|
| Empty top-level map / array (`a0` / `80`) | Length-0 container header dispatch. |
| Single-element container | Boundary between argument-as-immediate (length<24) and argument-as-byte (length<256). |
| Container with exactly 24 elements | Argument encoding: shortest is single byte 24, not 0x18 0x18. |
| Map with key types of every major type | Key sort comparison MUST work across types (CoreDeterministic encodes keys as byte sequences and sorts those, not the in-memory representations). |
| `NegInt(0)` representing `-2^64` | Edge of negint range; decoder must surface this without overflow on a `int64` coerce. |
| Tag wrapping a tag wrapping a tag | Recursive tag preservation. |
| Zero-byte text string vs zero-byte byte string | Major-type distinction: `60` (text "") and `40` (bytes empty). |
| Zero-byte byte string array element | Array with byte-string element of length 0. |
| Tag 24 (encoded CBOR data item) | Inner is a byte string whose contents are themselves CBOR; helpers MUST decode it on demand, not eagerly. |
| Self-describe tag (55799) wrapping the entire payload | Decoder strips silently; round-trip preserves only if the caller asks for `WithSelfDescribePreserve`. |
| Float subnormals | Encode/decode parity across float16/32/64 promotion paths. |
| Float negative-zero | Encoded as `0xf90000` in float16-shortest; round-trip MUST distinguish from `+0.0`. |
| NaN bit-pattern variants | Strict mode normalizes; permissive mode preserves. |
| Indefinite-length text-string with chunks containing partial UTF-8 codepoints | Reassembly MUST validate the concatenated string, not each chunk individually. |
| Map with duplicate keys at different positions | Last-write-wins under default; rejection under `RejectDuplicateMapKeys()`. Both MUST be deterministic. |
| Adversarially nested array (depth 10000) | `MaxNestingDepth` triggers BEFORE stack overflow. |
| Adversarial array length (`9b ffffffffffffffff`) declaring 2^64 elements | Length is read but the allocation is gated on the arrival of bytes; never pre-allocates. |
| Truncated input mid-tag | `ErrTruncated` with offset; no partial Value returned. |
| Trailing bytes after first complete value | `ErrTrailingBytes` in `Decode`; accepted in `Stream` (next iteration). |
| `Tag{Inner: nil}` constructed in user code | Encoder rejects with typed error (no nil Values in the tree). |

### 8.2 Known caller use cases

| Use case | Spec section it stresses |
|---|---|
| **Storage / AAD-bound encryption** | §2 strict deterministic encoding; §3.2 `StrictDecoder`; §7 round-trip property fuzzing. |
| **Cryptographic signing (COSE-shaped)** | §2 strict deterministic; §4.3 tag preservation for COSE headers. |
| **Wire protocol implementation (rpcv2Cbor, FIDO/WebAuthn)** | §2 `CTAP2` mode for WebAuthn; §3 forgiving decoder; §6 streaming. |
| **Configuration file parser** | §3 forgiving with `RejectDuplicateMapKeys()` + `RejectInvalidUTF8()` for human-authored files. |
| **Schema-less data interchange** | §3 forgiving default; §4 Value model with helpers for pulling typed shapes out. |
| **Large-payload streaming (telemetry, logs)** | §6 streaming encode+decode; §3 with `MaxByteStringLength` raised. |
| **Compatibility test harness** | §3 every quirk knob individually toggleable for fixture-based testing. |

---

## 9 — Performance requirements

Performance is a tier-1 acceptance criterion — the library is "core" CBOR;
inefficiency propagates everywhere.

| Metric | Target | Test mechanism |
|---|---|---|
| Encode throughput, scalar-only payload, Permissive mode | ≥ 500 MB/s on a 2024-class amd64 / arm64 | `go test -bench BenchmarkEncodeScalars` |
| Encode throughput, deeply-nested map payload, CoreDeterministic mode | ≥ 100 MB/s | `BenchmarkEncodeNestedMap` |
| Decode throughput, scalar-only payload, forgiving mode | ≥ 400 MB/s | `BenchmarkDecodeScalars` |
| Decode throughput, deeply-nested map payload, StrictDecoder | ≥ 80 MB/s | `BenchmarkDecodeNestedMapStrict` |
| Allocations per `Encoder.Encode` call (re-used encoder, scalar input) | 0 | `-benchmem` |
| Allocations per `Decoder.Decode` call (scalar input) | 1 (the returned Value) | `-benchmem` |
| Streaming encode resident memory ceiling | ≤ 8 KiB regardless of input size | heap profile under `EncodeTo(io.Discard, ...)` |
| Streaming decode resident memory ceiling | ≤ 16 KiB regardless of input size | same |

Performance regressions require a proposal (tier-1) before landing.

---

## 10 — Phases (implementation evolution)

Each phase is independently shippable. Each phase has its own proposal under
`engineering-docs/proposals/` (see template).

### Phase 1 — Foundational primitives (tier-1, blocking)

- Value type hierarchy (§4).
- Encoder in `Permissive` + `CoreDeterministic` modes only.
- Decoder in forgiving default mode + every knob from §3.1.
- `StrictDecoder` preset.
- Error catalog (§5) wired.
- Every fuzz target from §7.1 registered (may have empty seed corpus
  initially).
- Makefile + lint (see §11).
- Bench harness in place; targets from §9 measurable.

**Acceptance:** RFC 8949 vectors round-trip; every §3.3 quirk has a typed
test in both directions; `make fuzz FUZZTIME=30s` runs clean.

### Phase 2 — Streaming + remaining encoder modes

- `Canonical` and `CTAP2` encoder modes.
- Streaming encode/decode (§6).
- `Stream` iterator API.
- Resource-limit fuzzers (§7.1 row "FuzzResourceLimits").

**Acceptance:** large-payload bench targets from §9 met; CBOR Sequence
seeds in `FuzzStreamDecodeMatchesBatch`.

### Phase 3 — Tag helpers + well-known shapes

- Helpers from §4.3 (`AsTime`, `AsBigInt`, `AsNestedCBOR`).
- `Map.AsMap()` helper.
- Self-describe tag handling.
- Tag preservation fuzzer (§7.1 row "FuzzTagPreservation").

**Acceptance:** every RFC 8949 §3.4 well-known tag has a helper or a
preserve-as-opaque pathway.

### Phase 4 — Performance pass

- Buffer pooling on Encoder.
- Decode allocator amortization (single-allocation Map decode, etc.).
- Profile-driven optimization on the hot paths the bench harness names.
- Per-mode benchmarks check the §9 targets in CI.

**Acceptance:** §9 targets met on the reference hardware; perf regression
gate added to CI.

### Phase 5 — Tier-2 work (opt-in, post-Phase-4)

Anything not above. Each lives behind its own proposal:

- CBOR Sequence (RFC 8742) explicit support.
- Reflective marshal/unmarshal layer (`MarshalCBOR` / `UnmarshalCBOR`
  interface).
- COSE / CWT helper packages (separate modules).
- CDDL validator integration.
- OSS-Fuzz / continuous fuzzing.
- Plan9-style alternative interfaces.

These are explicitly **not** tier-1. The Phase 1–4 work ships first.

---

## 11 — Build hygiene (Makefile + linting)

The repo MUST have a Makefile with these targets, and CI MUST gate on
`make check`:

```make
# Makefile (sketch)

GO        := go
GOFUMPT   := $(GO) tool gofumpt
LINT      := $(if $(shell command -v golangci-lint 2>/dev/null),golangci-lint run,)
FUZZTIME  ?= 30s

.PHONY: help fmt fmt-check vet lint test bench fuzz check

help:
	@awk -F'## ' '/^[a-zA-Z_-]+:.*## /{printf "  %-12s %s\n",$$1,$$NF}' Makefile

fmt: ## gofumpt across the tree (excludes vendored / generated)
	$(GOFUMPT) -w .

fmt-check: ## fail if gofumpt would change anything
	@diff_files=$$($(GOFUMPT) -l .); \
	if [ -n "$$diff_files" ]; then \
		echo "ERROR: gofumpt violations:"; echo "$$diff_files" | sed 's/^/  /'; \
		exit 1; \
	fi

vet:
	$(GO) vet ./...

lint: vet ## go vet always; golangci-lint enforced if on PATH
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --timeout 5m ./...; \
	else \
		echo "golangci-lint not on PATH; skipping (install: brew install golangci-lint)"; \
	fi

test:
	$(GO) test -race ./...

bench:
	$(GO) test -run NONE -bench . -benchmem ./...

fuzz: ## run every registered fuzz target for FUZZTIME (default 30s)
	@for t in $$(grep -rEho 'func Fuzz[A-Z][A-Za-z0-9_]+' --include='*_test.go' . | awk '{print $$2}'); do \
		echo ">> $$t for $(FUZZTIME)"; \
		$(GO) test -run NONE -fuzz "^$$t$$" -fuzztime $(FUZZTIME) ./...; \
	done

check: fmt-check vet lint test ## CI-gating set
```

**Linting policy** (consistent with the upstream consumer's policy):

- `gofumpt` is a Go tool (`go get -tool mvdan.cc/gofumpt`); not a system
  install. CI uses `make fmt-check`.
- `golangci-lint` is **opportunistic in invocation** but **strict in
  findings** when present — exit non-zero on any finding. CI installs it;
  developer machines may skip via PATH absence.
- The default linter set + the `gofumpt` formatter is the baseline.
- Findings ARE NOT suggestions. New code MUST land lint-clean. Pre-existing
  findings get a tracking proposal (tier-2) before bulk-fixing.

---

## 12 — Proposal-driven development (focus discipline)

This document is the **tier-1 spec**. Subsequent in-flight proposals
(under `engineering-docs/proposals/`) extend or refine it. The discipline:

1. **Every change to scope or contract** lands as a proposal first, code
   second. Proposals reference §-anchors in this document.
2. **Tier-1 work blocks tier-2.** A proposal marked tier-2 sits in
   `proposals/` until every tier-1 proposal it depends on is closed.
3. **In-flight proposals** carry a status header (Draft / In-Review /
   Accepted / In-Progress / Closed / Rejected). The `engineering-docs/
   README.md` enumerates them.
4. **Velocity > polish on tier-1.** Tier-1 work ships incomplete-but-
   correct rather than blocking on tier-2 reviews. Comments on tier-2
   surface get filed as their own proposals; the tier-1 pull-request
   doesn't wait.
5. **Rollback-safe code paths.** Every Phase-N feature MUST be revertable
   without breaking Phase-(N-1) guarantees. Behind a flag if necessary
   during the transition.

---

## 13 — Cross-references

The RFCs cited below are vendored under `engineering-docs/rfcs/` for
offline reference. See `rfcs/README.md` for refresh procedure.

- [RFC 8949 (CBOR)](rfcs/rfc8949.txt) — primary spec.
- [RFC 8742 (CBOR Sequences)](rfcs/rfc8742.txt) — Phase 5 dependency.
- [RFC 9562 (UUID, including v7)](rfcs/rfc9562.txt) — interesting tag-1
  timestamp interplay for COSE downstream consumers.
- [RFC 7049 (legacy CBOR)](rfcs/rfc7049.txt) — obsoleted by 8949 but cited
  for the "Canonical CBOR" encoder mode (§2.1).
- [RFC 9052 (COSE)](rfcs/rfc9052.txt) — downstream consumer; not in scope
  here but informs tag-preservation requirements (§4.3).
- IANA CBOR tags registry (live, not vendored): https://www.iana.org/assignments/cbor-tags/
  — Phase 3 helper coverage.
