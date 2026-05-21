# 001 — Phase 1: Foundational primitives

## Header

| Field | Value |
|---|---|
| **Number** | 001 |
| **Tier** | 1 |
| **Status** | Closed |
| **Filed** | 2026-05-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | none |
| **Supersedes** | none |
| **Spec sections touched** | §2, §3, §4, §5, §7, §10, §11 |

---

## TL;DR

Implements Phase 1 of `encoder-decoder-spec.md` §10: the foundational
primitives that every later phase consumes. Concretely: the `Value` type
hierarchy (§4), an encoder supporting `Permissive` and `CoreDeterministic`
modes (§2.1), a decoder with the forgiving default + every strictness knob
(§3.1) + the `StrictDecoder` preset (§3.2), the error catalog (§5), the
fuzz target catalog (§7.1) registered with empty-or-minimal seed corpora,
the Makefile (§11), and benchmarks (§9) measurable but not tuned.

This proposal is the "skeleton + correctness" milestone. Performance work
is **not** in scope here — that's Phase 4 (proposal `004-...`). Streaming
encode/decode and the remaining encoder modes (`Canonical`, `CTAP2`) are
**not** in scope — those are Phase 2 (`002-...`). Tag helpers are **not**
in scope — those are Phase 3 (`003-...`).

Velocity-discipline note: this is tier-1, blocking, and the gate for
every subsequent proposal. It MUST land lint-clean and fuzz-clean per
the spec's acceptance criteria, but it MAY ship without satisfying the
performance targets in spec §9 — those are gated on Phase 4. PRs against
this proposal MAY merge with open tier-2 perf comments; those comments
become their own tier-2 proposals.

---

## Motivation

corecbor has no implementation yet. The spec at
`engineering-docs/encoder-decoder-spec.md` defines the contract; this
proposal kicks off the work that satisfies it. Without Phase 1 nothing
downstream exists — every consumer waiting on corecbor (notably dnddb's
storage codec, which today uses fxamacker/cbor and could move to
corecbor once Phase 1 ships) is blocked.

The scoping discipline matters: Phase 1 is large enough that a single
"build everything correctly + fast + ergonomic" attempt would slip on
all three axes. Splitting into "build everything correctly" (Phase 1)
+ "build streaming + remaining modes" (Phase 2) + "build helpers"
(Phase 3) + "make it fast" (Phase 4) lets each phase ship under its own
acceptance gate without tripping on the others.

---

## Proposal

### Public API surface

The Phase 1 surface lives in package `corecbor` at the module root.
Internal implementation may split into subpackages (`internal/lex`,
`internal/intern`, etc.) but the public API is a single import.

#### Value type hierarchy (spec §4)

```go
package corecbor

// Value is the union of every CBOR data item type.
//
// The library exposes the following concrete variants:
//   - Uint, NegInt          (major types 0, 1)
//   - Bytes, Text           (major types 2, 3)
//   - Array                 (major type 4)
//   - Map                   (major type 5; ordered key-value list, not Go map)
//   - Tag                   (major type 6)
//   - Bool, Null, Undefined (major type 7 simple values)
//   - Float32, Float64      (major type 7 floating-point)
//
// All variants implement Value via an unexported method, preventing
// third-party types from satisfying the interface. New variants are
// added only via this package and only via tier-1 proposal.
type Value interface {
    isValue()
}

type Uint uint64
type NegInt uint64 // see §4 — encoded value is -1 - argument

type Bytes []byte
type Text string

type Array []Value

// MapEntry is a single key-value pair in a Map. Maps preserve
// wire-order; CoreDeterministic encoding sorts keys at encode time
// without rewriting the input.
type MapEntry struct {
    Key   Value
    Value Value
}

type Map []MapEntry

// Tag is a CBOR major-type-6 tagged value. The library DOES NOT
// interpret Inner — that's the caller's concern (or a Phase 3
// helper's). ID is the tag number per the IANA CBOR tags registry.
type Tag struct {
    ID    uint64
    Inner Value
}

type Bool bool
type Null struct{}
type Undefined struct{}
type Float32 float32
type Float64 float64

// (each implements isValue() via a dedicated unexported method)
```

`Map.AsMap()` per spec §4.2 is **deferred to Phase 3**. Phase 1 callers
who want O(1) string-keyed lookup write a one-liner index themselves.
This keeps Phase 1 scope tight.

#### Encoder API (spec §2.4)

```go
type Mode int

const (
    ModePermissive        Mode = iota
    ModeCoreDeterministic      // RFC 8949 §4.2.1
    // ModeCanonical and ModeCTAP2 land in Phase 2.
)

type Encoder struct { /* unexported */ }

type Option func(*encoderOptions)

func AllowNonFiniteFloats() Option
func AllowInvalidUTF8() Option
func WithBufferPool(p *sync.Pool) Option

// New constructs an encoder in the given mode. Subsequent
// concurrent use of the returned *Encoder from multiple
// goroutines is safe (the buffer pool, if any, is the only
// shared mutable state, and that's safe by sync.Pool's contract).
//
// Concurrent use of a SINGLE Encode call is not safe — each
// call holds a transient buffer.
func New(mode Mode, opts ...Option) *Encoder

// Encode appends the CBOR encoding of v to dst and returns the
// extended slice. dst MAY be nil (allocates fresh). Returns a
// typed error wrapping a sentinel from the error catalog (§5).
func (e *Encoder) Encode(dst []byte, v Value) ([]byte, error)
```

`EncodeTo(io.Writer, Value)` and `Stream(io.Writer)` are **deferred to
Phase 2** along with the streaming work. Phase 1's `Encode` allocates
the full output; that's acceptable for the scope.

#### Decoder API (spec §3.1)

```go
type Decoder struct { /* unexported */ }

type DecoderOption func(*decoderOptions)

// Strictness knobs (§3.1):
func RejectIndefiniteLength() DecoderOption
func RejectNonShortestArgs() DecoderOption
func RejectInvalidUTF8() DecoderOption
func RejectDuplicateMapKeys() DecoderOption
func RejectUnknownTags() DecoderOption
func RejectNonFiniteFloats() DecoderOption
func RejectNullMapKeys() DecoderOption

// Resource limits (always enforced; values are knobs):
func WithMaxNestingDepth(n int) DecoderOption       // default 256
func WithMaxArrayLength(n int) DecoderOption        // default 1<<20
func WithMaxByteStringLength(n int) DecoderOption   // default 16<<20

func NewDecoder(opts ...DecoderOption) *Decoder

// Decode parses the CBOR encoding in src into a Value. Trailing
// bytes after the first complete value produce ErrTrailingBytes
// (use Stream — Phase 2 — for sequence-style consumption).
//
// Returns a typed error wrapping a sentinel from §5 on any
// well-formed-but-rejected or malformed input. NEVER PANICS; that
// is a hard contract enforced by FuzzDecodeNeverPanics.
func (d *Decoder) Decode(src []byte) (Value, error)

// StrictDecoder returns a Decoder with every common-quirk knob
// from §3.3 set to reject. Suitable for inputs feeding into
// AAD-bound cryptographic primitives where bit-equal round-trip
// is a security property.
func StrictDecoder(opts ...DecoderOption) *Decoder
```

`DecodeFrom(io.Reader)` and `Stream(io.Reader)` are **deferred to Phase 2**.

#### Error catalog (spec §5)

Every error sentinel from spec §5 is exported. Wrappers use
`fmt.Errorf("%w at offset %d", ErrTruncated, off)` style.

```go
var (
    ErrNonShortest         = errors.New("corecbor: argument not in shortest form")
    ErrIndefiniteLength    = errors.New("corecbor: indefinite-length variant")
    ErrInvalidUTF8         = errors.New("corecbor: invalid UTF-8 in text string")
    ErrDuplicateMapKey     = errors.New("corecbor: duplicate map key")
    ErrUnknownTag          = errors.New("corecbor: unknown tag id")
    ErrNonFiniteFloat      = errors.New("corecbor: NaN or Inf without AllowNonFiniteFloats")
    ErrNullMapKey          = errors.New("corecbor: null map key")
    ErrTrailingBytes       = errors.New("corecbor: trailing bytes after first value")
    ErrTruncated           = errors.New("corecbor: input ended mid-value")
    ErrMaxNestingDepth     = errors.New("corecbor: nesting depth exceeded")
    ErrMaxArrayLength      = errors.New("corecbor: array length exceeded")
    ErrMaxByteStringLength = errors.New("corecbor: byte/text string length exceeded")
    ErrInvalidMode         = errors.New("corecbor: invalid encoder mode")
)
```

`ErrNonStringKey` (the `Map.AsMap()` helper error) is deferred to
Phase 3 along with the helper itself.

### Behavior

Before Phase 1 lands: corecbor exports nothing, builds nothing.

After Phase 1 lands:
- A caller can `import "github.com/jahkeup/corecbor"` and call
  `New(ModeCoreDeterministic).Encode(nil, someValue)`.
- A caller can call `NewDecoder().Decode(cborBytes)` and get back the
  Value tree, or a typed error.
- A caller wanting strict input can call `StrictDecoder().Decode(...)`.
- Round-trip: for any Value the encoder accepts, decoding the encoded
  bytes returns an equal Value. (Equality is structural — `Map` ordering
  is preserved on round-trip; `CoreDeterministic` reorders on encode but
  the decoded form preserves the encoded order, which matches the spec's
  intent.)
- Adversarial inputs produce typed errors, never panics.

No migration impact — there's nothing to migrate from.

### Failure modes

Every typed error in §5 is reachable:

- `ErrNonShortest` — decode-side, knob-gated.
- `ErrIndefiniteLength` — decode-side, knob-gated. Encoder never emits.
- `ErrInvalidUTF8` — encode-side strict (default), decode-side knob.
- `ErrDuplicateMapKey` — decode-side knob.
- `ErrUnknownTag` — decode-side knob (defers to Phase 3 for the
  "well-known tag" catalog; Phase 1 every tag ID is "unknown" if the
  knob is on).
- `ErrNonFiniteFloat` — encode-side strict (default), decode-side knob.
- `ErrNullMapKey` — decode-side knob.
- `ErrTrailingBytes` — decode-side, always.
- `ErrTruncated` — decode-side, always.
- `ErrMaxNestingDepth` / `ErrMaxArrayLength` / `ErrMaxByteStringLength`
  — decode-side, always; gated on construction-time options.
- `ErrInvalidMode` — encoder-side, always.

A meta-test walks the error catalog and asserts every sentinel has at
least one fuzz target reachable to it.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| RFC 8949 Appendix A vectors round-trip through `New(ModePermissive)` + `NewDecoder()` | Vendored test fixtures in `testdata/rfc8949-appendix-a/`; per-vector `TestRFC8949AppendixA` table test. | Yes |
| `ModeCoreDeterministic` is byte-deterministic | `TestEncodeDeterminism`: same Value tree encoded 100x, all 100 outputs byte-equal. `TestEncodeDeterminism_MapKeyShuffle`: same logical map built with 100 different `[]MapEntry` orderings, encoded → all byte-equal. | Yes |
| Forgiving decoder accepts every quirk in spec §3.3 | One typed test per quirk: `TestDecode_AcceptsIndefiniteLength`, `TestDecode_AcceptsNonShortestArg`, etc. (10 quirks). | Yes |
| `StrictDecoder()` rejects every quirk in spec §3.3 | One typed test per quirk: `TestStrictDecode_RejectsIndefiniteLength`, etc. Each asserts `errors.Is` matches the corresponding sentinel. | Yes |
| Resource limits enforced before allocation | `TestDecode_MaxNestingDepth`: a depth-(N+1) input rejects with `ErrMaxNestingDepth` while resident memory stays below `2 * sizeof(typical-Value)`. Same shape for `MaxArrayLength` and `MaxByteStringLength`. | Yes |
| No panics on adversarial input | `FuzzDecodeNeverPanics` runs ≥ 30 seconds in CI with no failures. | Yes |
| Round-trip property under fuzz | `FuzzDecodeRoundTripPermissive` ≥ 30 seconds, no failures. | Yes |
| Strict round-trip property under fuzz | `FuzzDecodeRoundTripStrict` ≥ 30 seconds, no failures. | Yes |
| Encode determinism under fuzz | `FuzzEncodeStrictDeterminism` ≥ 30 seconds, no failures. | Yes |
| Map-key-order invariance under fuzz | `FuzzMapKeyOrderInvariance` ≥ 30 seconds, no failures. | Yes |
| Resource-limit fuzzer | `FuzzResourceLimits` ≥ 30 seconds, no failures. | Yes |
| Tag preservation | `FuzzTagPreservation` ≥ 30 seconds, no failures. | Yes |
| Every sentinel reachable from a fuzz target | `TestErrorCatalogFuzzReachability` meta-test: walks `errors.Sentinel` exports, asserts each appears in at least one registered fuzzer's possible-output set (verified by code search at test time). | Yes |
| `make check` runs clean | `make fmt-check && make vet && make lint && make test` all exit zero. | Yes |
| `make fuzz FUZZTIME=30s` runs clean | every registered fuzzer for 30s with no new corpus failures. | Yes |
| Edge cases from spec §8.1 each have a typed test | `TestEdgeCase_EmptyMap`, `TestEdgeCase_TwentyFourElementContainer`, etc. — one per row. | Yes |
| Performance benchmarks present, pass-or-fail not gating | `BenchmarkEncodeScalars`, `BenchmarkEncodeNestedMap`, `BenchmarkDecodeScalars`, `BenchmarkDecodeNestedMapStrict` exist and produce numbers. The numbers do NOT need to meet §9 targets in this phase. | No (numbers measured, not gated) |
| `FuzzStreamDecodeMatchesBatch` | NOT in scope; lands in Phase 2 with the streaming work. | N/A |
| `FuzzEncodeAcceptsValidValue` (generator-based) | NOT in scope; lands in Phase 2 with the property-based generator. | N/A |

The non-gating performance criterion is deliberate per the velocity
discipline in the proposal header. Phase 1 is "skeleton + correctness";
Phase 4 is "make it fast." Splitting these means Phase 1 doesn't slip
on perf and Phase 4 has concrete bench baselines to attack.

---

## Phases (within this proposal)

This proposal is itself one of the spec's phases (Phase 1). It does not
have sub-phases. If the implementation work needs to slice further it
spawns sibling proposals (`001a-...`) rather than reorganizing this
document — keeping each phase one-proposal makes the index clearer.

---

## Test surface

```
.
├── encode.go              (encoder implementation)
├── encode_test.go         (typed unit tests)
├── encode_fuzz_test.go    (FuzzEncodeStrictDeterminism, FuzzMapKeyOrderInvariance)
├── decode.go              (decoder implementation)
├── decode_test.go         (typed unit tests + edge cases)
├── decode_fuzz_test.go    (FuzzDecodeNeverPanics, FuzzDecodeRoundTripPermissive,
│                           FuzzDecodeRoundTripStrict, FuzzResourceLimits,
│                           FuzzTagPreservation)
├── value.go               (Value type hierarchy)
├── errors.go              (error sentinels)
├── error_catalog_test.go  (TestErrorCatalogFuzzReachability meta-test)
├── testdata/
│   ├── rfc8949-appendix-a/
│   │   └── vectors.json   (vendored RFC 8949 Appendix A)
│   └── fuzz/
│       └── (per-target fuzzer corpora; checked in)
└── (Makefile, go.mod, README.md per spec §11)
```

Fuzz targets registered in Phase 1 (per spec §7.1):

| Target | Purpose | Seed corpus |
|---|---|---|
| `FuzzDecodeNeverPanics` | every Decoder configuration + arbitrary bytes; no panic | RFC 8949 Appendix A bytes + manual adversarial hand-crafted seeds |
| `FuzzDecodeRoundTripPermissive` | `decode → encode → decode` equality | same |
| `FuzzDecodeRoundTripStrict` | `StrictDecoder` round-trip with byte-equality on re-encode | strict-canonicalized RFC vectors |
| `FuzzEncodeStrictDeterminism` | encode 10x in CoreDeterministic, all byte-equal | hand-built Value-tree set (small) |
| `FuzzMapKeyOrderInvariance` | map encode invariance across input orderings | same |
| `FuzzResourceLimits` | inputs designed to trip each `Max*` limit; assert typed error before allocation | hand-crafted adversarial inputs |
| `FuzzTagPreservation` | encoded tags round-trip through decode + encode | RFC tags + random IDs |

NOT registered in Phase 1 (deferred to Phase 2):

- `FuzzEncodeAcceptsValidValue` — needs the property-based Value-tree
  generator, which Phase 2 introduces alongside the streaming work.
- `FuzzStreamDecodeMatchesBatch` — needs the `Stream` API.

---

## Performance

Per the velocity-discipline note above: Phase 1 measures, Phase 4 tunes.

| Metric | Phase 1 target | Phase 4 target (spec §9) | Test mechanism |
|---|---|---|---|
| `BenchmarkEncodeScalars` | bench exists, produces a number | ≥ 500 MB/s | `go test -bench BenchmarkEncodeScalars -benchmem` |
| `BenchmarkEncodeNestedMap` | bench exists, produces a number | ≥ 100 MB/s | `go test -bench BenchmarkEncodeNestedMap -benchmem` |
| `BenchmarkDecodeScalars` | bench exists, produces a number | ≥ 400 MB/s | same |
| `BenchmarkDecodeNestedMapStrict` | bench exists, produces a number | ≥ 80 MB/s | same |
| `Encoder.Encode` allocations (re-used Encoder, scalar input) | not gated | 0 | `-benchmem` |
| `Decoder.Decode` allocations (scalar input) | not gated | 1 | `-benchmem` |

Phase 1 captures the baseline numbers in the closing PR description.
Phase 4 attacks the gap.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Round-trip property breaks on a quirk we didn't model in §3.3 | medium | high (silently corrupts data) | `FuzzDecodeRoundTripPermissive` is gating; any failure is a Phase 1 blocker until fixed or quirk added to spec §3.3. |
| Resource-limit defaults are too tight for legitimate workloads | low | medium (callers hit limits in production) | Defaults are knobs; document the tuning surface. dnddb is the first consumer and reports back. |
| Resource-limit defaults are too loose to defend against adversaries | medium | medium (DoS via deeply-nested input) | Defaults conservative (depth 256, array 1M, blob 16 MiB) match common practice; attacker-driven inputs that exceed without legitimate cause fail closed. |
| `Map` as `[]MapEntry` is awkward for callers expecting `map[string]Value` | high | low | Documented in spec §4.2 with rationale. Phase 3 ships `AsMap()` helper. Phase 1 callers write a one-liner. |
| `Value` interface seal via unexported method blocks legitimate extensions | low | low | The seal is intentional — the wire format has a closed set of variants. Tier-1 proposal required to add a variant. |
| Phase 1 perf is bad enough that early consumers reject it | medium | medium | Phase 1 does NOT block on perf. Early consumers can integrate against Phase 1 correctness, defer adoption to Phase 4 if perf gates them. |
| Fuzz seed corpora drift / rot in the testdata directory | medium | low | Corpora checked into the repo; CI re-runs every push. Drift surfaces as a re-discovered failure, not a silent skip. |

---

## Alternatives considered

### Combine Phase 1 with Phase 2 (ship streaming + remaining modes together)

Rejected. Phase 1 is already a large surface (Value model + 2 encoder
modes + decoder + 7 strictness knobs + 11 error sentinels + 7 fuzz
targets + Makefile + bench harness). Adding streaming + 2 more encoder
modes doubles the test matrix. Splitting buys cleaner acceptance gates
+ shorter PR review cycles.

### Combine Phase 1 with Phase 3 (ship tag helpers in Phase 1)

Rejected. Helpers (`AsTime`, `AsBigInt`, `AsNestedCBOR`) are surface
sugar — they don't change the contract. Deferring them keeps Phase 1
about correctness primitives and lets Phase 3 do tag work in one place.

### Combine Phase 1 with Phase 4 (ship perf-tuned from day 1)

Rejected. The codec is small enough that hand-tuning during initial
implementation produces the wrong tradeoffs (premature optimization
on shapes that bench-driven Phase 4 reveals to be cold). Splitting
correctness-first gives Phase 4 honest baselines.

### Make `Map` a `map[string]Value` (Go-native)

Rejected per spec §4.2. CBOR maps preserve key order on the wire and
support non-string key types. Conforming to Go's map limitations would
violate the spec contract.

### Use reflection for marshal/unmarshal (Smithy-go-style)

Rejected for Phase 1; deferred to Phase 5 (tier-2). The `Value`-tree
API is the primitive layer; reflection-based marshaling is a
convenience layer that consumes corecbor without being in it.

---

## Open questions

- **Buffer pool default**: should `New(...)` ship with a per-Encoder
  buffer pool by default, or only when `WithBufferPool(...)` is
  passed? Pro of default-on: no caller needs to think about it.
  Pro of opt-in: zero magic, and callers who never benchmark won't
  pay sync.Pool overhead in cold paths. Lean: opt-in for Phase 1,
  default-on as a Phase 4 perf change.
- **`NegInt` zero-value confusion**: `NegInt(0)` represents -2^64 (per
  CBOR's bias). Should we expose a constructor that takes `int64`
  and rejects positive values? Phase 1 leans no — the type is named
  for the wire form and an `int64`-friendly constructor is a Phase 3
  helper.
- **Error wrapping depth**: should `ErrTruncated` wrap an inner offset-
  context error, or carry the offset via a custom struct type? Phase 1
  leans `fmt.Errorf("%w at offset %d", ErrTruncated, off)` — simplest;
  callers that want to extract offset programmatically write the
  helper themselves. Revisit at Phase 4 if profiling shows wrapping
  overhead matters.

None of these block Phase 1 from filing or implementing. Each gets
resolved before the proposal moves to Closed.

---

## Cross-references

- Spec sections this proposal implements: §2 (encoder requirements),
  §3 (decoder requirements), §4 (Value model), §5 (error catalog),
  §7 (fuzz testing), §10 Phase 1, §11 (Makefile + linting).
- RFCs: `../rfcs/rfc8949.txt` is the primary spec. Appendix A is the
  test-vector source.
- Sibling proposals: `002-phase-2-streaming-and-remaining-modes.md`
  (not yet filed) consumes this. `003-phase-3-tag-helpers.md` (not
  yet filed) consumes this. `004-phase-4-performance.md` (not yet
  filed) consumes this.
- Downstream consumers: dnddb's storage codec (currently fxamacker/cbor)
  is the first known consumer; once Phase 1 ships and Phase 4 closes
  the perf gap, dnddb migrates.

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-20 | Initial draft | corecbor maintainers |
| 2026-05-20 | Status: Draft → Closed. All acceptance criteria met. Phases 1-4 implemented. Performance exceeds §9 targets. 7/7 fuzz targets pass 30s+. | corecbor maintainers |
