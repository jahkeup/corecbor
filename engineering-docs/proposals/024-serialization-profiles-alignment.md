# 024 — Align encoder modes and checking decoders with CBOR Serialization (draft-ietf-cbor-serialization)

## Header

| Field | Value |
|---|---|
| **Number** | 024 |
| **Tier** | 1 |
| **Status** | Draft |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001, 021 (`ErrNotDeterministic` user), 023 (`DecodeError`), 034 (compatibility policy) |
| **Supersedes** | none |
| **Spec sections touched** | §2.1, §2.2, §3.1, §3.2, §5, §7.1 |

---

## TL;DR

The CBOR WG's `draft-ietf-cbor-serialization-13` ("CBOR Serialization
and Determinism") is in IETF Last Call, ending 2026-11-30, with
Proposed Standard as the intended status. It defines two named
serializations:

- **Preferred-Plus**: shortest arguments, definite lengths only,
  shortest exact floats, NaN only as `0xf97e00`, and bignums with no
  leading zeros, reduced to major type 0/1 when they fit.
- **Deterministic**: Preferred-Plus plus bytewise-lex map key order.
  This is RFC 8949 §4.2.1 except for the NaN rule.

The draft also defines optional **checking decoders** that reject
input not in the chosen serialization. `draft-ietf-cbor-cde` (CDE) is
parked and expired.

Our encoder modes come close, but not all the way. We also have no
checking decoder: `StrictDecoder` accepts unsorted maps, non-shortest
floats, and duplicate NaN keys. This proposal:

1. Fixes the bignum and NaN gaps that RFC 8949 itself requires
   (§3.4.3 preferred bignum serialization; §2.2 NaN in CTAP2).
2. Implements RFC 8949 erratum 8589.
3. Adds `RequireDeterministic()`, a checking decoder for the published
   RFC 8949 §4.2.1 rules.
4. Adds, **as opt-in Draft behavior** per proposal 034,
   `ModePreferredPlus` and `RequirePreferredPlus()`, which implement
   draft-13 §4 and Appendix G. Defaults stay on RFC 8949 until the
   draft publishes.

After items 1–2, `ModeCoreDeterministic` output is byte-identical to the
draft's Deterministic Serialization, because the only remaining
difference (NaN) is already normalized to `f97e00`.

Velocity note: exported names are provisional until the draft becomes
an RFC. Phase 1 (bug fixes that are correct under RFC 8949 alone) is
not gated on that.

---

## Motivation

Probes on `main@00e1307` (`AllowNonFiniteFloats` set where NaN is
involved):

| Input | Mode / decoder | Output | Draft requirement |
|---|---|---|---|
| `Float64(NaN, payload 0x123)` | CoreDeterministic, Canonical | `f97e00` | ✓ `0xf97e00` |
| same | CTAP2 | `fb7ff8000000000123` | §2.2 of our spec already requires NaN normalization in deterministic modes. ✗ |
| `Float32(NaN 0xffc00001)` | CTAP2 | `fbfff8000020000000` (payload and sign kept) | ✗ |
| `Tag(2, h'0001')` | CoreDeterministic | `c2420001` | ✗ no leading zeros; must be `01` (major 0) |
| `a2 6162 01 6161 02` (unsorted) | `StrictDecoder` | accepted | checking-deterministic decoder rejects |
| `fa 3f800000` (1.0 as f32) | `RejectNonShortest()` | accepted | checking-preferred-plus decoder rejects (non-shortest float) |
| `{NaN:1, NaN:2}` (`a2 f97e00 01 f97e00 02`) | `RejectDuplicateMapKeys()` | accepted | duplicate (RFC 8949 §5.6.1 + erratum 8589) |

Why these matter:

- **NaN map keys.** `valuesEqual` (`rfc8949/decode.go:705-708`)
  compares floats with `==`, so NaN never equals NaN and
  duplicate-key detection is bypassed. Erratum 8589, verified, against
  RFC 8949 §5.6.1 says two NaNs are equal map keys when their
  significands match after zero-extension *and* their sign bits match.
- **Bignums.** `BigIntTo` (`cbor/tags.go:89`) always emits tag 2/3,
  even for values that fit in major type 0/1, and the encoder passes
  tag 2/3 contents through unchanged. Deterministic output for "the
  same integer" then depends on how the caller built it. This breaks
  §2.1's "byte-identical for equal inputs" promise at the data-model
  level.
- **Checking decoders.** §3.2's strict preset says it is for
  "cryptographic inputs where bit-equal round-trip is a security
  property". Without a deterministic check, two encodings of the same
  map both pass `StrictDecoder` and re-encode identically, so
  signature-over-re-encoding schemes stay malleable. This is the
  complement to 022, which preserves raw bytes.
- **The spec table in §2.1 is wrong.** It describes `Canonical`
  (RFC 7049 §3.9) as "bytewise-lex" and `CTAP2` as "bytewise-lex …
  then by length". The code (`encoder.go:106-113`) and `doc.go` use
  length-first for both, which is correct for both RFC 7049 §3.9 and
  CTAP2 §6. The spec is updated to match the code.

---

## Proposal

### Encoder modes

```go
const (
	ModePermissive        Mode = iota // unchanged: input-width floats, insertion order
	ModeCoreDeterministic             // RFC 8949 §4.2.1 ≡ draft-ietf-cbor-serialization §5 Deterministic
	ModeCanonical                     // RFC 7049 §3.9 (length-first)
	ModeCTAP2                         // CTAP2 canonical
	// ModePreferredPlus is Experimental: it implements
	// draft-ietf-cbor-serialization-13 §4 (preferred-plus, insertion
	// order). The name and NaN rule are provisional until the draft is
	// published as an RFC; see proposal 034 (Draft class).
	ModePreferredPlus
)
```

`ModePreferredPlus` behaves like `ModeCoreDeterministic` except that
maps keep insertion order. It is for wire protocols that want
canonical scalars without paying for sorting, such as CoAP payloads
and logs. It is appended to the end of the enum so existing values
don't change, and the bounds check in `encoder.go:71` is updated.

Changes to the existing deterministic modes:

| Rule | CoreDeterministic | Canonical | CTAP2 | PreferredPlus |
|---|---|---|---|---|
| NaN → `f97e00` (sign and payload dropped) | already | already | **new** — emitted as `fb7ff8000000000000` (CTAP2 forces float64) | yes |
| Bignum leading-zero strip | **new** | **new** | **new** | yes |
| Bignum fits in uint64/negint → major 0/1 | **new** | **new** | **new** | yes |
| Map sort | bytewise-lex | length-first | length-first | none |

Bignum normalization applies only to `Tag(2|3, Bytes(...))` Values.
The draft explicitly exempts tags 2/3 from its new rule against tags
affecting other types (it updates RFC 8949 §7). Rewriting a
caller-supplied tag 2/3 into an integer is therefore a semantics-
preserving normalization, not "tag wrapping the user did not request"
(§2.3). `BigIntTo` reduces in every mode, and in Permissive mode it
returns `Uint`/`NegInt` when the value fits.

### Checking decoder options

```go
// RequirePreferredPlus is Experimental: it implements the checking
// decoder of draft-ietf-cbor-serialization-13 (§4, Appendix G) and is
// provisional until the draft is published (proposal 034, Draft class).
// It rejects input that is not preferred-plus serialized:
// non-shortest arguments (incl. float width: a value encodable exactly
// in a narrower float MUST use it), indefinite lengths, NaN other than
// f97e00, bignums with leading zeros or that fit major 0/1.
// Errors wrap ErrNotPreferred.
func RequirePreferredPlus() DecoderOption

// RequireDeterministic rejects input that is not RFC 8949 §4.2.1 Core
// Deterministic: non-preferred serialization (§4.1, §3.4.3: shortest
// arguments and float widths, definite lengths, preferred bignums) and
// maps whose keys are not in strictly increasing bytewise-lex order of
// their encodings (which also rejects duplicates). It is based on the
// published RFC only; combine with RequirePreferredPlus for the draft's
// additional NaN rule. Errors wrap ErrNotDeterministic, or
// ErrNotPreferred for serialization violations.
func RequireDeterministic() DecoderOption
```

New sentinels, added to §5:

```go
// ErrNotPreferred indicates input that violates preferred-plus
// serialization in a checking decoder.
ErrNotPreferred = errors.New("cbor: input not in preferred serialization")

// ErrNotDeterministic indicates input that violates deterministic
// serialization (map key order) in a checking decoder or a
// deterministic StreamEncoder (021 D6).
ErrNotDeterministic = errors.New("cbor: input not in deterministic serialization")
```

Where the existing per-knob sentinel applies, the error wraps both
(`fmt.Errorf("%w: %w", ErrNotPreferred, ErrNonShortest)`), so
`errors.Is(err, ErrNonShortest)` keeps working.

`StrictDecoder` does **not** add `RequireDeterministic()`. Deployed
COSE/CWT encoders commonly emit unsorted maps, and proposal 034's first
precedence rule (interoperate with what's deployed) decides it. A new
`DeterministicDecoder(opts...)` preset (= `StrictDecoder` +
`RequireDeterministic()`) is provided instead.

### Erratum 8589: NaN key equality

`valuesEqual` and the dedup hash (`rfc8949/decode.go:634-675`) compare
floats by canonical bit pattern:

1. Two NaNs are equal when, after zero-extension to binary64, their
   significands *and* sign bits match.
2. Non-NaN floats compare by value.
3. `+0` and `-0` are *equal* keys (RFC 8949 §5.6.1: "-0.0 is equal to
   0.0").
4. Floats with different widths that represent the same value are
   equal keys (for example `f93c00` and `fa3f800000`). Today they compare
   unequal, because `valuesEqual` first requires the same `Kind`, and
   half-precision input decodes as `KindFloat64` while single-precision
   input decodes as `KindFloat32`.

### Spec edits (§2.1, §2.2)

- Fix the §2.1 table's Canonical and CTAP2 sort descriptions so they
  say length-first.
- Add a `PreferredPlus` row.
- Add a "Serialization references" note:
  `ModeCoreDeterministic` ≡ draft-ietf-cbor-serialization
  Deterministic, and `ModePreferredPlus` ≡ Preferred-Plus.
- Make §2.2's NaN bullet cite `f97e00` explicitly.

### Behavior / migration

- **CTAP2 NaN output changes.** CTAP2 forbids NaN in practice, so the
  impact is nil.
- **Bignum output changes in deterministic modes.** Values built with
  `BigIntTo(small)` now encode as plain integers. Byte-level golden
  files that contain small bignums will change. That fixes a §2.1
  violation (RFC 8949 §3.4.3 + §4.2.1). `WithLegacyBignumPassthrough()`
  restores v0.2 output.
- **Reflection round-trip.** Because small bignums now arrive as
  `Uint`/`NegInt`, `Unmarshal` into `big.Int`/`*big.Int` must accept
  major types 0/1 as well as tags 2/3 (RFC 8949 §3.4.3 decoders MUST
  handle both forms). `decodeBigInt`/`decodeBigIntPtr` (`reflect_decode.go:350-372`) and the tag-only check in `valueToGo` change accordingly.
- **New modes and options are additive.**

### Failure modes

- New sentinels: `ErrNotPreferred` and `ErrNotDeterministic`.
- Duplicate NaN keys now trigger the existing `ErrDuplicateMapKey`.

---

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).
Defaults follow RFC 8949 and its verified errata. Draft-13 behavior is
opt-in only, documented `Experimental:` with the draft name and
revision.

| Change | Class | Default (v0.30) | Selector |
|---|---|---|---|
| CTAP2 NaN normalized to `fb7ff8000000000000` | Defect (§2.2) | normalized | none — defect |
| Bignum leading zeros stripped in deterministic modes (RFC 8949 §3.4.3, §4.2.1) | Conformance | stripped | `func WithLegacyBignumPassthrough() Option` — Deprecated; emits tag 2/3 contents as supplied |
| Bignums that fit major 0/1 encoded as integers in deterministic modes; `BigIntTo` reduces | Conformance | reduced | same `WithLegacyBignumPassthrough()` (encoder). `BigIntTo` has no options; v0.2 behavior is `cbor.MakeTag(2, cbor.Bytes(n.Bytes()))` and the migration guide says so |
| Duplicate-key equality: NaN sign bit (erratum 8589), ±0 equal, cross-width float equality | Conformance | erratum rules | `func WithLegacyFloatKeyEquality() DecoderOption` — Deprecated; v0.2 `Kind`-and-`==` comparison |
| `RequireDeterministic()`, `DeterministicDecoder()` | Additive (RFC 8949 §4.2.1) | off | n/a — opt-in |
| `ModePreferredPlus` | Draft (draft-13 §4) | off | the mode itself is the opt-in; `Experimental:` doc |
| `RequirePreferredPlus()` (NaN-only-`f97e00` check, Appendix G) | Draft (draft-13) | off | the option itself is the opt-in; `Experimental:` doc |
| `StrictDecoder` contents | unchanged | no `RequireDeterministic` | n/a |

Root bundles: `CompatV02() Option` includes `WithLegacyBignumPassthrough()`;
`CompatV02Decoding() DecoderOption` includes `WithLegacyFloatKeyEquality()`.

When draft-ietf-cbor-serialization publishes: re-run 034's precedence.
If the RFC matches what's deployed, `ModePreferredPlus` and
`RequirePreferredPlus` drop the `Experimental:` marker (renamed if the
RFC renames them). That is a separate proposal.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| CTAP2 encodes every NaN bit pattern as `fb7ff8000000000000` | `TestCTAP2NaNNormalized` | Yes |
| `Tag(2,h'0001')` → `01`; `Tag(2,h'00ff…' 9 bytes)` → `c2 48 …` (leading zero stripped) in all deterministic modes | `TestBignumPreferred` | Yes |
| `BigIntTo(big.NewInt(-5))` → `NegInt(4)` | `TestBigIntToReduces` | Yes |
| `ModePreferredPlus` keeps insertion order and otherwise matches CoreDeterministic for scalars | `TestPreferredPlusMode` | Yes |
| `RequireDeterministic` rejects `a2 6162 01 6161 02` with `ErrNotDeterministic` | `TestRequireDeterministicUnsorted` | Yes |
| `RequirePreferredPlus` rejects `fa3f800000`, `f97e01`, `c2 42 0001`, `9f ff`, `18 01` with `ErrNotPreferred` | `TestRequirePreferredPlus` table | Yes |
| `RejectDuplicateMapKeys` rejects `{NaN:1,NaN:2}`, `{+0:1,-0:2}` and `{f93c00:1, fa3f800000:2}`; accepts `{f97e00:1, f9fe00:2}` (sign bits differ, per erratum 8589) | `TestDuplicateKeyFloatEquivalence` | Yes |
| Every Appendix-level example in draft-ietf-cbor-serialization-13 that has a hex encoding passes as an encode and checking-decode vector | `testdata/serialization-13/*.json` + `TestSerializationDraftVectors` | Yes |
| Encode output of every §2.1 deterministic mode passes `RequireDeterministic` (CoreDeterministic) or `RequirePreferredPlus` (Canonical, CTAP2 floats excepted) | `FuzzEncodePassesCheckingDecoder` | Yes |
| The draft is cited by URL in the spec (not vendored, per `rfcs/README.md` "Do not vendor I-Ds"); swapped for a vendored `rfcNNNN.txt` once published | doc review | Yes |
| §2.1 table corrected | doc review | Yes |
| `WithLegacyBignumPassthrough()` reproduces v0.2.2 bytes for `Tag(2,h'0001')` (`c2 42 0001`) and `BigIntTo`-built values; default strips/reduces | `TestCompatBignumPassthrough` vs `testdata/legacy-v0.2.2/` | Yes |
| `WithLegacyFloatKeyEquality()` accepts `{f93c00:1, fa3f800000:2}` as v0.2.2 did; default rejects | `TestCompatFloatKeyEquality` | Yes |
| `Unmarshal(01, &big.Int)` and `Unmarshal(c2 41 01, &big.Int)` both yield 1 | `TestUnmarshalBigIntFromInt` | Yes |
| Legacy selectors carry `// Deprecated:` with removal floor v0.32.0; `ModePreferredPlus` and `RequirePreferredPlus` carry `Experimental:` naming draft-ietf-cbor-serialization-13 | doc review + staticcheck SA1019 fixture | Yes |
| `StrictDecoder()` accepts the unsorted map `a2 6162 01 6161 02`; `DeterministicDecoder()` rejects it | `TestStrictVsDeterministicPreset` | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | Correct under RFC 8949 alone: CTAP2 NaN (§2.2), erratum 8589 key equality, bignum reduction in `BigIntTo`, §2.1 table fix | Pending | First three rows + erratum row pass |
| 2 | `RequirePreferredPlus` / `RequireDeterministic` + sentinels | Pending | Checking-decoder rows pass |
| 3 | Encoder-side bignum normalization (RFC 8949 §3.4.3) + `WithLegacyBignumPassthrough` | Pending | Bignum rows pass |
| 4 | Draft class (034): `ModePreferredPlus`, `RequirePreferredPlus` documented Experimental; draft vectors | Pending | Draft rows pass; **renamed/finalized when the RFC publishes, per 034 lifecycle** |

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| Tests named above | modes, checks, erratum | `determinism_test.go`, `edge_cases_test.go` |
| `FuzzEncodePassesCheckingDecoder` (new §7.1 target) | random `Value` → encode in mode M → decode with the matching checking decoder → no error | `fuzz_test.go` |
| `FuzzCheckingDecoderIdempotent` (new) | input accepted by `RequireDeterministic` → decode → CoreDeterministic encode == input | `fuzz_test.go` |
| `FuzzDecodeRoundTripStrict` (existing) | extended with `RequireDeterministic` | `fuzz_test.go` |
| `FuzzMapKeyOrderInvariance` (existing) | add NaN (both signs), ±0 and mixed-width float keys to the generator | `fuzz_test.go` |

---

## Performance

| Metric | Target | Test mechanism |
|---|---|---|
| `BenchmarkDecodeNestedMapStrict` with `RequireDeterministic` | ≥ 80 MB/s (§9 target holds). The order check compares each key's encoded span with the previous one, with no extra allocation | `go test -bench DecodeNestedMapStrict` |
| `BenchmarkEncodeNestedMap` (CoreDeterministic) | unchanged ±3%. Bignum check is a branch on `KindTag && Num ∈ {2,3}` | bench |
| `RequirePreferredPlus` float-width check | ≤ 5 ns per float | microbench |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| The draft changes in Last Call or IESG review (NaN rule, names) | med | med | Phase 3 names are provisional; Phases 1–2 are justified by RFC 8949 and erratum 8589 alone |
| `RequireDeterministic` in `StrictDecoder` rejects real-world COSE/CWT that isn't sorted (many encoders don't sort) | high | high | Don't add it to `StrictDecoder` by default (Open question 1). 022 preserves the raw bytes, which is the correct fix for signatures |
| Normalizing bignums surprises callers who expect tag 2 on the wire (for example, ASN.1-style fixed widths) | low | low | Permissive mode passes tag 2/3 through unchanged; document it |

---

## Alternatives considered

- **Implement `draft-ietf-cbor-cde` (CDE) instead.** Rejected: the WG
  has parked it and it has expired. The serialization draft is the
  active document. Reconsider if CDE revives with application profiles
  (dCBOR and similar).
- **Rename `ModeCoreDeterministic` to `ModeDeterministic`.** Rejected
  for now: §2.1 says "Mode names match RFC terminology" and RFC 8949
  §4.2.1 is still the normative name. Add an alias after the draft is
  published, if it is.
- **Float-to-int reduction** (encode `1.0` as `01`). The draft
  doesn't require it, and it changes the data model type. It stays
  out of scope, but dCBOR-style profiles may want it as an opt-in
  later.

---

## Open questions

1. ~~Should `StrictDecoder` include `RequireDeterministic`?~~
   Resolved by proposal 034: no; `DeterministicDecoder` preset instead.
2. Should `RejectNonShortest` also cover float width? Today it covers
   only arguments; float width moves under `RequirePreferredPlus`.
   Folding it into `RejectNonShortest` changes existing behavior.
3. When CTAP2 forces float64, should NaN be `fb7ff8000000000000`
   (float64 quiet NaN) or should NaN be rejected outright? CTAP2 §6
   doesn't address NaN.

---

## Cross-references

- Spec: §2.1 (table fix), §2.2, §3.1, §3.2, §5, §7.1
- Proposals: [021](021-core-codec-safety-fixes.md) (stream order check uses `ErrNotDeterministic`), [022](022-raw-byte-preservation.md), [023](023-strict-decode-policy-and-errors.md)
- RFCs: `rfcs/rfc8949.txt` §3.4.3, §4.1, §4.2.1, §4.2.2, §5.6.1; `rfcs/rfc7049.txt` §3.9
- RFC 8949 erratum 8589 (verified; §5.6.1 NaN sign bit): https://www.rfc-editor.org/errata/eid8589
- draft-ietf-cbor-serialization-13 (IETF LC ends 2026-11-30): https://datatracker.ietf.org/doc/draft-ietf-cbor-serialization/
- draft-ietf-cbor-cde-13 (parked, expired): https://datatracker.ietf.org/doc/draft-ietf-cbor-cde/
- FIDO CTAP 2.2 §6 (CTAP2 canonical CBOR)

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft from the 2026-11-20 codebase review + IETF upstream check | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
