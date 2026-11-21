# 024 — Align encoder modes and checking decoders with CBOR Serialization (draft-ietf-cbor-serialization)

## Header

| Field | Value |
|---|---|
| **Number** | 024 |
| **Tier** | 1 |
| **Status** | In-Progress |
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
2. Implements RFC 8949 erratum 8589 and makes map-key identity and
   duplicate handling explicit, caller-selected choices (see "Map key
   identity and duplicate policy").
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
(§2.3). The normalization happens in the *encoder*, at encode time, in
the three deterministic modes only. `cbor.BigIntTo` keeps its v0.2.2
semantics (it always returns `Tag(2|3, Bytes)`, so
`AsBigInt(BigIntTo(n))` keeps working), and Permissive mode keeps
emitting tag 2/3 as supplied. A new helper gives callers the preferred
form as a `Value`:

```go
// BigIntToPreferred returns the RFC 8949 §3.4.3 preferred
// representation of n: Uint or NegInt when n fits in 64 bits,
// otherwise Tag(2|3, Bytes) with no leading zeros.
func BigIntToPreferred(n *big.Int) Value
```

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

`StrictDecoder` does **not** add `RequireDeterministic()`. Its
documented contract (spec §3.2) is a fixed list of knobs, and 034 keeps
existing identifiers' semantics; deployed COSE/CWT encoders also emit
unsorted maps that `StrictDecoder` callers accept today. A new
`DeterministicDecoder(opts...)` preset (= `StrictDecoder` +
`RequireDeterministic()`) is the standards-current identifier instead.

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

### Map key identity and duplicate policy

Two independent questions decide what a decoder does with repeated map
keys, and v0.2.2 answers neither consistently: maps of up to 16 entries
compare keys as data-model values (`valuesEqual`), so `01` and `1800`
collide and last-write-wins keeps only the second; larger maps compare
the encoded bytes (dedup hash, `rfc8949/decode.go:634-675`), so the same
pair keeps both entries and `RejectDuplicateMapKeys` misses it. Spec
§8.1 requires the default to be last-write-wins *and deterministic*, so
the split is a contract defect. Which notion of "same key" is right is
the caller's call: a protocol implementation wants the RFC data model,
while someone auditing an encoder or treating key bytes as opaque wants
`01` and `1800` kept apart.

**Key identity** — new option, default unchanged in meaning for every
map size once the split is fixed:

```go
// KeyIdentity selects when two map keys are the same key.
type KeyIdentity int

const (
	// KeyIdentityValue compares keys in the CBOR data model (RFC 8949
	// §5.6.1 + erratum 8589): 01 and 1800 are the same key, as are
	// f93c00 and fa3f800000; integer 1 and float 1.0 are not. Default.
	KeyIdentityValue KeyIdentity = iota
	// KeyIdentityEncoded treats keys as the same only when their encoded
	// bytes are identical: 01 and 1800 are different keys.
	KeyIdentityEncoded
)

// WithMapKeyIdentity selects key identity for duplicate detection.
func WithMapKeyIdentity(k KeyIdentity) DecoderOption
```

**Duplicate policy** — what happens when a key repeats under the chosen
identity:

| Policy | Identifier | Status |
|---|---|---|
| Last-write-wins | default (spec §3.3, §8.1) | unchanged |
| Reject | `RejectDuplicateMapKeys()` | existing |
| Keep every entry, in input order, no merging | `KeepDuplicateMapKeys() DecoderOption` | new |

`KeepDuplicateMapKeys` is cheap because `cbor.Value` maps are
`[]MapEntry`. Combining it with `RejectDuplicateMapKeys` is a
configuration error (`ErrInvalidOption`, new). Combinations compose:
`WithMapKeyIdentity(KeyIdentityEncoded)` + `RejectDuplicateMapKeys()`
rejects only byte-identical repeats.

All map sizes use one implementation: the dedup hash keys on the
canonical form for `KeyIdentityValue` (Core Deterministic encoding of
the key, with erratum 8589 float/NaN normalization) and on the input
bytes for `KeyIdentityEncoded`, with `valuesEqual` (or `bytes.Equal`)
confirming hash hits. The small-map linear scan uses the same predicate.

Documented consequences:

- `Unmarshal` into a Go `map` can't hold duplicates; the last entry is
  assigned last regardless of policy. Use a `cbor.Value` or
  `[]cbor.MapEntry` target to keep them.
- Deterministic encoding writes `1800` as `01`, so a `Value` decoded
  with `KeyIdentityEncoded` + `KeepDuplicateMapKeys` and re-encoded in a
  deterministic mode fails with `ErrDuplicateMapKey` (021 D15) instead
  of silently merging.
- Raw views are available whatever the policy: `Diagnostic` renders
  every encoded entry (021 D19), and `Cursor`/`DecodeRaw` (022) expose
  the bytes.

### Spec edits (§2.1, §2.2)

- Fix the §2.1 table's Canonical and CTAP2 sort descriptions so they
  say length-first.
- Add a `PreferredPlus` row.
- Add a "Serialization references" note:
  `ModeCoreDeterministic` ≡ draft-ietf-cbor-serialization
  Deterministic, and `ModePreferredPlus` ≡ Preferred-Plus.
- Make §2.2's NaN bullet cite `f97e00` explicitly.

### Implementation notes (2026-11-20)

- **Key identity everywhere.** One predicate (`keysEqual`, RFC 8949
  §5.6.1 + erratum 8589) and a matching data-model hash (`keyHash`)
  serve every map size; v0.2.2 hashed encoded bytes above 16 entries.
  Arrays, tags and maps compare structurally (maps order-independently).
  `KeyIdentityEncoded` compares input bytes (`bytes.Equal`, FNV hash for
  large maps); indefinite maps keep the v0.2 linear scan.
- **Half-precision NaN payloads.** `wire.DecodeFloat16` used to return
  Go's `math.NaN()` for every half NaN, which made `f97e00` and `f97e01`
  equal keys, contrary to erratum 8589. It now zero-extends the sign and
  significand into binary64. No golden vector changed.
- **Checking decoders** run as a separate pass over the item's bytes
  after a successful decode (`rfc8949/check.go`), so default decode hot
  paths are untouched. Options live on `rfc8949.DecodeOpts`
  (`RequirePreferred`, `RequireSortedMapKeys`, `RequireCanonicalNaN`);
  `RequireDeterministic()` sets the first two, `RequirePreferredPlus()`
  the first and third. Errors are 023 `DecodeError`s wrapping
  `ErrNotPreferred` (plus `ErrNonShortest`/`ErrIndefiniteLength`) or
  `ErrNotDeterministic` (plus `ErrDuplicateMapKey` for equal keys).
  `RequireDeterministic` keeps NaN payloads in their shortest width
  (RFC 8949 §4.1); the draft's `f97e00`-only rule comes from
  `RequirePreferredPlus`.
- **`ErrInvalidOption`** is returned by `rfc8949.Decode` (so by every
  decode entry point) when `KeepDuplicateMapKeys` and
  `RejectDuplicateMapKeys` are both set; options can't fail at
  construction without changing `NewDecoder`'s signature.
- **`ModePreferredPlus`** uses a new `rfc8949.SortNone`; deterministic
  `StreamEncoder` key-order checks are skipped for it.
  `StreamEncoder.WriteTag(2)` + `WriteBytes` is written as supplied; the
  stream can't rewrite a bignum it has already started (use `WriteValue`).
- **Raw path (022).** The raw-span `Unmarshal` path re-derived merges
  with v0.2-era rules and disagreed with the decoder after this change
  (e.g. two NaN keys). The decoder now records each resulting entry's
  key and kept-value spans (`rfc8949.MapEntrySpans`), and the raw merge
  path consumes them. A full-tree offset side table was not added:
  profiling `BenchmarkUnmarshalStructRawMessage` shows cursor walking at
  ~2% of CPU, and that benchmark is already ~19% faster than v0.2.2
  (1.558µs → 1.264µs; 2088 → 760 B/op).
- **Consumer byte-stability.** 36 golden vectors (variant-tag storage
  corpus: single-entry variant-tag maps, numbers as text, pre-sorted
  sets, invalid UTF-8 under `AllowInvalidUTF8`, a 40-attribute item)
  generated from v0.2.2 pin Core Deterministic output and its decode →
  re-encode; none is allowlisted.
- **Draft vectors.** All 25 Appendix K.2 examples
  (`testdata/serialization-13/examples.json`) pass the draft's K.1
  encode, decode and checking-decoder tests.
- **`DecodeFrom` / `Stream`** don't run the checking pass; it applies to
  `Decode`, `DecodePrefix`, `DecodeRaw`, `DecodeSequence` and
  `Unmarshal`.

### Behavior / migration

- **CTAP2 NaN output changes.** CTAP2 forbids NaN in practice, so the
  impact is nil.
- **Bignum output changes in deterministic modes.** Values built with
  `BigIntTo(small)` now encode as plain integers in the three
  deterministic modes (the `Value` itself is unchanged; Permissive
  output is unchanged). Byte-level golden
  files that contain small bignums will change. That fixes a §2.1
  violation (RFC 8949 §3.4.3 + §4.2.1). `WithLegacyBignumPassthrough()`
  restores v0.2 output.
- **Reflection round-trip.** Because small bignums now arrive as
  `Uint`/`NegInt`, `Unmarshal` into `big.Int`/`*big.Int` must accept
  major types 0/1 as well as tags 2/3, so that proposal 008's
  `Marshal`→`Unmarshal` round-trip for `big.Int` keeps holding. This
  only turns inputs that v0.2.2 rejected into successes. `cbor.AsBigInt`
  keeps its v0.2.2 semantics (tag 2/3 only); `cbor.AsBigIntAny(v Value)
  (*big.Int, error)` is added for callers who want either form. `decodeBigInt`/`decodeBigIntPtr` (`reflect_decode.go:350-372`) and the tag-only check in `valueToGo` change accordingly.
- **New modes and options are additive.**

### Failure modes

- New sentinels: `ErrNotPreferred` and `ErrNotDeterministic`.
- Duplicate NaN keys now trigger the existing `ErrDuplicateMapKey`.

---

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).
No exported identifier changes signature; `Mode` gains one constant at
the end of the enum, so existing values are unchanged. `BigIntTo`,
`AsBigInt` and `StrictDecoder` keep their v0.2.2 semantics. Draft-13
behavior is opt-in only, documented `Experimental:` with the draft name
and revision.

| Change | Class | Contract restored | Existing identifiers in v0.30 | Selector |
|---|---|---|---|---|
| CTAP2 NaN normalized to `fb7ff8000000000000` | Contract defect | spec §2.2 NaN bullet; `doc.go:16-17` (CTAP2 canonical) | normalized | none (034: v0.2 output violated its mode) |
| Bignum leading zeros stripped by the encoder in deterministic modes | Contract defect | `doc.go:12-15` (modes claim RFC 8949 §4.2.1, which requires preferred serialization, §4.1/§3.4.3) | stripped | `func WithLegacyBignumPassthrough() Option` — Deprecated; emits tag 2/3 contents as supplied |
| Bignums that fit major 0/1 encoded as integers in deterministic modes | Contract defect | same, RFC 8949 §3.4.3 ("preferred serialization … never makes use of bignums that also can be expressed as basic integers") | reduced at encode time; `BigIntTo` unchanged | same `WithLegacyBignumPassthrough()` |
| Duplicate-key equality: NaN sign bit, ±0 equal, cross-width float equality | Contract defect | RFC 8949 §5.6.1 + verified erratum 8589; `RejectDuplicateMapKeys` documents RFC 8949 §5.6 (spec `:182`) | erratum rules | `func WithLegacyFloatKeyEquality() DecoderOption` — Deprecated; v0.2 `Kind`-and-`==` comparison |
| Same key-identity rule for every map size (v0.2.2 used value identity up to 16 entries, encoded bytes above) | Contract defect | spec §3.3 last-write-wins and §8.1 "MUST be deterministic" | `KeyIdentityValue` at every size | none — callers who want byte identity choose `KeyIdentityEncoded` |
| `WithMapKeyIdentity`, `KeyIdentityValue`, `KeyIdentityEncoded` | Additive | — | default = data model (current standards state) | the option is the opt-in |
| `KeepDuplicateMapKeys()`, `ErrInvalidOption` | Additive | — | last-write-wins default unchanged | the option is the opt-in |
| `Unmarshal` into `big.Int` accepts major 0/1 | Additive (input v0.2.2 rejected now succeeds) | proposal 008 round-trip | tag 2/3 decode unchanged | n/a |
| `BigIntToPreferred`, `AsBigIntAny` | Additive | — | `BigIntTo`/`AsBigInt` unchanged | n/a |
| `RequireDeterministic()`, `DeterministicDecoder()` | Additive (RFC 8949 §4.2.1) | — | `StrictDecoder` unchanged | n/a — opt-in, recommended for AAD inputs |
| `ModePreferredPlus` | Draft (draft-13 §4) | — | n/a | the mode itself is the opt-in; `Experimental:` doc |
| `RequirePreferredPlus()` (NaN-only-`f97e00` check, Appendix G) | Draft (draft-13) | — | n/a | the option itself is the opt-in; `Experimental:` doc |

No `...Option` parameters are appended to existing functions. Root
bundles: `CompatV02() Option` includes `WithLegacyBignumPassthrough()`;
`CompatV02Decoding() DecoderOption` includes `WithLegacyFloatKeyEquality()`.

When draft-ietf-cbor-serialization publishes, the RFC behavior arrives
under new non-draft identifiers (or the draft identifiers lose their
`Experimental:` marker if the RFC matches draft-13 exactly), per 034's
lifecycle. That is a separate proposal.

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
| `{01:"a", 1800:"b"}` behaves identically at 2 and at 17+ entries: last-write-wins keeps `"b"`; `RejectDuplicateMapKeys` rejects | `TestKeyIdentityMapSizeIndependent` | Yes |
| `KeyIdentityEncoded`: `{01:"a", 1800:"b"}` keeps both under last-write-wins and isn't rejected by `RejectDuplicateMapKeys`; `{01:"a", 01:"b"}` is | `TestKeyIdentityEncoded` | Yes |
| `KeepDuplicateMapKeys`: every entry kept in input order for both identities; with `RejectDuplicateMapKeys` → `ErrInvalidOption` | `TestKeepDuplicateMapKeys` | Yes |
| Decode with each identity × policy agrees with a reference model over random maps | `FuzzMapKeyIdentity` | Yes |
| `Unmarshal(01, &big.Int)` and `Unmarshal(c2 41 01, &big.Int)` both yield 1 | `TestUnmarshalBigIntFromInt` | Yes |
| Legacy selectors carry `// Deprecated:` with removal floor v0.32.0; `ModePreferredPlus` and `RequirePreferredPlus` carry `Experimental:` naming draft-ietf-cbor-serialization-13 | doc review + staticcheck SA1019 fixture | Yes |
| `StrictDecoder()` accepts the unsorted map `a2 6162 01 6161 02`; `DeterministicDecoder()` rejects it | `TestStrictVsDeterministicPreset` | Yes |
| No exported identifier present in v0.2.2 is removed, renamed, or retyped, and no method is added to an exported interface (034 API stability) | `apidiff` against `v0.2.2` for this module, run in `make check` | Yes |
| Existing identifiers called with no new options reproduce the v0.2.2 golden vectors, except the contract-defect fixes listed under Compatibility selection | `testdata/legacy-v0.2.2/` golden tests | Yes |
| `AsBigInt(BigIntTo(n))` round-trips for every n, and `BigIntTo(big.NewInt(5))` still returns a tag-2 `Value` | `TestBigIntToUnchanged` | Yes |
| Permissive-mode output for tag 2/3 Values is byte-identical to v0.2.2 | golden test | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | Correct under RFC 8949 alone: CTAP2 NaN (§2.2), erratum 8589 key equality, one key-identity rule for all map sizes, encode-time bignum strip/reduction in deterministic modes (`BigIntTo` unchanged), §2.1 table fix | Done | First three rows + erratum + map-size rows pass |
| 1b | Caller-selected key identity and duplicate policy: `WithMapKeyIdentity`, `KeepDuplicateMapKeys` | Done | identity/policy rows + `FuzzMapKeyIdentity` pass |
| 2 | `RequirePreferredPlus` / `RequireDeterministic` + sentinels | Done | Checking-decoder rows pass |
| 3 | Encoder-side bignum normalization (RFC 8949 §3.4.3) + `WithLegacyBignumPassthrough` | Done | Bignum rows pass |
| 4 | Draft class (034): `ModePreferredPlus`, `RequirePreferredPlus` documented Experimental; draft vectors | Done | Draft rows pass; **renamed/finalized when the RFC publishes, per 034 lifecycle** |

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
   Resolved by proposal 034: no (existing semantics kept); `DeterministicDecoder` preset instead.
2. ~~Should `RejectNonShortest` also cover float width?~~ Resolved by
   034 (existing identifiers keep their semantics): no. Float width is
   checked by `RequireDeterministic` and `RequirePreferredPlus` only.
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
| 2026-11-20 | API stability (signature + semantics) per revised 034 | corecbor maintainers |
| 2026-11-20 | Map key identity (value vs encoded) and duplicate policy (last-wins / reject / keep) as explicit caller choices; fix small/large-map split (maintainer decision) | corecbor maintainers |
| 2026-11-20 | Status: In-Progress; Phases 1, 1b, 2, 3, 4 implemented; implementation notes | corecbor maintainers |
| 2026-11-21 | Accepted perf trade-off (maintainer decision): strict decode of maps >16 entries ~+15% (DecodeStrictLargeMap100/1000), DecodeNestedMapStrict ~+5.5% vs pre-024 main, from data-model key identity at every map size; default/forgiving paths flat. Follow-up: reduce per-key cost in the strict hashed path (find/mapInsert, DecodeOpts size) | corecbor maintainers |
