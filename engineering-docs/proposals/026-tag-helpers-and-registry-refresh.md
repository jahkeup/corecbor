# 026 — Tag helpers for published CBOR tag RFCs, and registry refresh

## Header

| Field | Value |
|---|---|
| **Number** | 026 |
| **Tier** | 2 |
| **Status** | In-Progress |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 006 (registry codegen), 021 (core codec safety fixes — tag 1 / `TimeTo` range), 023 (tag allow-list in strict decode), 034 (compatibility policy) |
| **Supersedes** | none |
| **Spec sections touched** | §4.3 (required tags table, additive rows); §10 Phase 3 acceptance ("every well-known tag has a helper or a preserve-as-opaque pathway") |

---

## TL;DR

`cbor/tags.go` has helpers for tags 0, 1, 2, 3, and 24 only, plus seven
constants. Since that file was written, the CBOR tag space that real
consumers need has grown: UUIDs (tag 37), dates (100/1004, required by
mDL), extended time (1001–1003, RFC 9581), IP addresses (52/54,
RFC 9164), OIDs (111/112, RFC 9090), and the COSE / CWT / UCCS / EAT
envelope tags (16–18, 96–98, 61, 601, 602). The vendored IANA registry
(`registry/registry.json`, fetched 2026-05-21) is also about 20 entries
behind IANA (updated 2026-11-13).

This proposal adds typed constructor/accessor pairs for each published
tag RFC, adds stable hand-named constants for the envelope tags, refreshes
the generated registry, and parks diagnostic-notation alignment with
`draft-ietf-cbor-edn-literals` as a later phase gated on that draft
becoming an RFC.

**Acceptance:** each new helper round-trips against the RFC's own
examples, the regenerated registry matches IANA at refresh time, and
the sibling modules use the new constants instead of private literals.

---

## Motivation

### Consumers that need specific tags

| Consumer | Tags | Today |
|---|---|---|
| mDL / ISO 18013-5 | 24 (`IssuerSignedItemBytes`, `DeviceAuthenticationBytes`), 1004 (`birth_date`), 0 (`tdate`) | only `AsNestedCBOR` decode; no tag-24 *constructor*; no 1004 |
| COSE | 16, 17, 18, 96, 97, 98 | private constants at `cose/marshal.go:13` (`tagSign1`, ...) |
| CWT / ACE / SCITT | 61 (CWT), 601 (UCCS, RFC 9781) | absent: `cwt` neither emits nor accepts tag 61 (see proposal 031); 601 absent |
| EAT / RATS | 602 (Detached EAT Bundle, RFC 9711 §5), 37 / 111 (component IDs) | absent |
| Inventory / SBOM / network | 37 (UUID), 52/54 (IP addresses and prefixes), 111 (OID) | opaque `Tag` only |
| Storage | 55799, 55800 (RFC 9277 sequence magic) | only 55799 stripping at decode |

### Generated constant names are not a stable API

`registry/tags_gen.go` derives identifiers from the IANA *semantics*
text: `TagBinaryUUIDRFC9562Section4` (line 88),
`TagIPv4PrefixlenIPv4IPv4Prefixpart` (line 124),
`TagNumberOfDaysSinceTheEpochDate19700101` (line 229). When IANA edits
that text (it does), the generated name changes and downstream code
breaks. Consumers need short, hand-curated names for the tags they use.
The generated names stay available for lookup and diagnostics only.

### Known defect in the existing tag-1 helpers

`TimeTo` (`cbor/tags.go:55-57`) writes `Uint(uint64(t.Unix()))`, so
pre-1970 times become huge positive values on the wire. `AsTime`
(`cbor/tags.go:36-49`) overflows for `Uint > MaxInt64` and for float
inputs beyond ±292 years, and turns NaN into 1970. The fix belongs to 021.
This proposal adds RFC 9581 tag 1001 as the lossless, range-safe
alternative, and requires every new time helper to follow 021's range
rules.

### Registry drift

Refreshing `registry/registry.json` from IANA's CSV (registry updated
2026-11-13) adds 10 tags — 33000, 44252, 46010, 46011, 55003, 55004,
55005, 133133, 827539798 and 1735551332 — and removes none (260 → 270
rows). The remaining row changes are cosmetic: references reformatted
(`[RFC8949]` → `[RFC 8949]`, `][` → `]; `) and three TEMPORARY
registrations now reading "publication requested" instead of an expiry
date. An earlier XML-based count of 280 included unassigned/range rows,
which the CSV parser skips. (Corrected 2026-11-21: 10, 11 and 13 are
not CBOR tags; they are keys in RFC 9581's Time Tag Map Keys registry —
IXDTF time-zone hint, IXDTF suffix and timescale — and are relevant to
the tag 1001 helpers as map keys.) `cmd/cbor-registry-gen` already
supports `-fetch`, and the CSV source URL
(`https://www.iana.org/assignments/cbor-tags/tags.csv`) returns 200.

---

## Proposal

### Phase A — Envelope tag constants and tag-24 constructor

Add to `cbor/tags.go` (re-exported from the root like the existing set):

```go
const (
	TagCOSEEncrypt0      uint64 = 16    // RFC 9052 §2
	TagCOSEMac0          uint64 = 17    // RFC 9052 §2
	TagCOSESign1         uint64 = 18    // RFC 9052 §2
	TagCOSEEncrypt       uint64 = 96    // RFC 9052 §2
	TagCOSEMac           uint64 = 97    // RFC 9052 §2
	TagCOSESign          uint64 = 98    // RFC 9052 §2
	TagCWT               uint64 = 61    // RFC 8392 §6
	TagUCCS              uint64 = 601   // RFC 9781
	TagDetachedEATBundle uint64 = 602   // RFC 9711 §5
	TagCBORSequenceFile  uint64 = 55800 // RFC 9277
)

// WrapEncodedCBOR returns Tag(24, Bytes(encoded)). encoded MUST already
// be a single well-formed CBOR data item; use EncodeEncodedCBOR to build
// it from a Value.
func WrapEncodedCBOR(encoded []byte) Value
```

At the root, where the encoder and decoder are available:

```go
// EncodeEncodedCBOR encodes v with e and wraps the result in tag 24.
// The wrapped bytes are what a signature over "<<v>>" (CDDL) covers.
func (e *Encoder) EncodeEncodedCBOR(v Value) (Value, error)

// DecodeEncodedCBOR unwraps a tag-24 Value and decodes its content with
// d, enforcing that the content is exactly one data item
// (ErrTrailingBytes otherwise). It returns the decoded Value and the
// raw embedded bytes, so callers can hash or verify the exact bytes.
func (d *Decoder) DecodeEncodedCBOR(t Value) (Value, []byte, error)
```

`cose`, `cwt`, and `eat` switch to these constants.

### Phase B — Value-typed helpers for published tag RFCs

All helpers follow the existing `AsX` / `XTo` naming (`cbor/tags.go`).
Every `AsX` returns a wrapped sentinel error (§5); none panics on any
input.

```go
// --- RFC 9562 / tag 37: binary UUID ---
// UUIDTo returns Tag(37, Bytes(u[:])).
func UUIDTo(u [16]byte) Value
// AsUUID requires tag 37 with a 16-byte Bytes inner value.
func AsUUID(t Value) ([16]byte, error)

// --- RFC 8943: dates ---
// DateTo returns Tag(1004, Text("YYYY-MM-DD")) for the civil date of t
// in t's location. Used for mDL birth_date / issue_date.
func DateTo(t time.Time) Value
// DaysTo returns Tag(100, int) — days since 1970-01-01 (may be negative).
func DaysTo(t time.Time) Value
// AsDate accepts tag 100 or tag 1004 and returns midnight UTC of that day.
func AsDate(t Value) (time.Time, error)

// --- RFC 9581: extended time, duration, period ---
// ExtendedTime is the decoded form of tag 1001. Only the integer
// base-time key and the decimal sub-second keys down to nanoseconds are
// modelled (exact key numbers per RFC 9581 §3, verified against the
// vendored text at implementation time). Decimal-fraction and bigfloat
// base times return ErrMalformedTag as unsupported. All other keys are
// preserved in Extra so the value round-trips.
type ExtendedTime struct {
	Time  time.Time
	Extra []MapEntry // e.g. timescale (-13 / tag 13), IXDTF hints (tags 10/11)
}
func ExtendedTimeTo(et ExtendedTime) Value
func AsExtendedTime(t Value) (ExtendedTime, error)
// DurationTo / AsDuration: tag 1002 (map, same key space as 1001).
func DurationTo(d time.Duration) Value
func AsDuration(t Value) (time.Duration, error)
// Tag 1003 (period) is preserve-as-opaque in this phase.

// --- RFC 9164 / tags 52, 54: IP addresses and prefixes ---
// IPTo returns tag 52 (IPv4) or 54 (IPv6) with the address bytes.
func IPTo(a netip.Addr) Value
// PrefixTo returns the [prefixlen, truncated-address] form, with
// trailing zero bytes removed as RFC 9164 requires.
func PrefixTo(p netip.Prefix) Value
// AsIP / AsPrefix decode the address and prefix forms. The interface
// form [address, prefixlen] decodes with AsPrefix. Non-canonical
// prefixes (non-zero bits past prefixlen) return ErrNonCanonicalTag.
func AsIP(t Value) (netip.Addr, error)
func AsPrefix(t Value) (netip.Prefix, error)

// --- RFC 9090 / tags 111, 112: OIDs ---
// OIDTo returns Tag(111, Bytes(BER content octets of oid)).
func OIDTo(oid asn1.ObjectIdentifier) (Value, error)
// AsOID decodes tag 111, or tag 112 (relative to 1.3.6.1.4.1).
// Malformed BER (leading 0x80, truncated arc) returns ErrMalformedTag.
func AsOID(t Value) (asn1.ObjectIdentifier, error)
```

Two sentinels are added to `cbor/errors.go`: `ErrMalformedTag` (the inner
value has the wrong kind or shape) and `ErrNonCanonicalTag` (well-formed
but violates a canonical-form MUST in the tag RFC). The existing tag
helpers' `fmt.Errorf` strings (`cbor/tags.go:25-112`) are migrated to
wrap `ErrMalformedTag`, which is an additive change for `errors.Is` callers.

### Phase C — Registry refresh and naming policy

1. Run `go run ./cmd/cbor-registry-gen -fetch -cache registry/registry.json -out registry/tags_gen.go`.
   Commit the diff with the IANA `updated` date in the message.
2. Make the generator skip `Unassigned` and range rows deterministically
   (today they produce constants such as tag 12 "Unassigned").
3. **Generated identifiers are API and never change.** Every constant
   present in v0.2.2 `registry/tags_gen.go` keeps its name and value.
   The generator reads a checked-in `registry/names_frozen.txt` (seeded
   from v0.2.2) and always emits those names first. A newly registered
   tag gets a new name, which is then appended to the frozen list. If
   IANA rewrites a tag's description so the derived name would differ,
   the frozen name stays and the new name is **not** added (one name
   per tag). If IANA withdraws a tag, its constant stays with
   `// Deprecated: no longer in the IANA registry (YYYY-MM-DD)`.
   Hand-picked short names for common tags still live in `cbor/tags.go`
   (Phase A/B) for readability, not for stability.
4. Add a `make registry-check` target that fetches and diffs without
   writing. It is advisory only: CI never makes a network fetch a gate.
5. Add an `Allowed` set builder for 023's tag allow-list:
   `registry.TagSet(ids ...uint64)` plus the predefined sets
   `registry.CoreTags` (0–3, 24, 55799) and `registry.COSETags`
   (16–18, 61, 96–98).

### Phase D (later, optional) — RFC 8746 typed arrays

Tags 64–87 (typed arrays) map naturally onto the existing homogeneous
decoders (`rfc8949/homogeneous.go`). This phase is scoped only when a
consumer asks. The candidate API is
`AsUint16Array(t Value, order binary.ByteOrder) ([]uint16, error)` and
its siblings.

### Phase E (later, gated) — Diagnostic notation alignment

`draft-ietf-cbor-edn-literals-29` (retitled "Concise Diagnostic
Notation (CDN)", in WG Last Call as of 2026-10-31) and RFC 9682 refine
the RFC 8949 §8 / Appendix G notation. Candidate changes for
`diagnostic.go`:

- the `<<...>>` embedded-CBOR form for tag 24 / bstr-wrapped CBOR;
- app-string prefixes (`dt'...'`, `ip'...'`) for the tags in Phase B;
- the encoding-indicator spelling `_i`/`_0`…`_3`, which needs a check
  against today's `DiagIndicators` output.

This phase stays out of scope until the draft is published as an RFC,
per `rfcs/README.md` ("Do not vendor I-Ds") and proposal 034 (no draft
defaults). On publication, vendor the RFC and file the change as an
amendment to proposal 009. Per 034, `Diagnostic()` and
`DiagnosticValue()` keep their RFC 8949 §8 / Appendix G output as their
default (existing identifiers keep their semantics); the new notation
arrives as an opt-in `DiagCDN() DiagnosticOption`, recommended in godoc.

### Implementation notes (2026-11-21)

- **OIDs follow RFC 9090's preferred serialization.** `OIDTo` emits tag
  112 for OIDs under 1.3.6.1.4.1 (§2.2 makes the shorter form preferred
  and required in Core Deterministic encoding), otherwise tag 111.
  Tag 110 (relative OID) got `RelativeOIDTo`/`AsRelativeOID`, since the
  §2.1 validity rules are shared.
- **RFC 9164 Interface Format** has its own constructor,
  `InterfaceTo(netip.Prefix)` (the full address plus prefix length,
  unmasked). Zones are carried as the optional third element: numeric
  zones as integers, others as text. `IPTo` of a zoned address writes
  `[address, null, zone]`; `AsIP` accepts the Address and Interface
  formats, and `AsPrefix` accepts all three (the Address Format as a
  full-length prefix).
- **RFC 9581 coverage.** Base time key 1 (integer or float), decimal
  fractions -3/-6/-9 (at most one, integer key 1 only) and the UTC
  timescale (keys -1/-13/13 with value 0) are modelled. Keys 4/5,
  fractions -12/-15/-18, other timescales and unknown unsigned
  (critical) keys return `ErrMalformedTag`; other negative and text keys
  are preserved in `Extra`. `ExtendedTimeTo` picks the coarsest exact
  fraction key, which reproduces the RFC's examples. `DurationTo`
  rounds seconds toward negative infinity so the unsigned fraction is
  non-negative.
- **`DateTo` outside years 0000–9999** emits the tag 100 form, since RFC
  3339 full-date has a four-digit year.
- **Range errors use `ErrTimeRange`** (021) rather than 025's
  `ErrOverflow`, which isn't in package `cbor`.
- **Existing helpers keep their v0.2 errors.** `AsTime`/`AsBigInt`/
  `AsNestedCBOR` already wrap `ErrTypeMismatch` (023); also wrapping
  `ErrMalformedTag` would change the golden error classification, so
  only new helpers (and `DecodeEncodedCBOR`) use it.
- **RFC 9277 helpers** beyond the constant: `TagWrappedTo` (§2.2),
  `SequenceLabelTo`/`AsSequenceLabel` (§2.3, also accepting 55801) and
  `ContentFormatTag`/`AsContentFormat` (App. B). Emitting the label from
  `EncodeSequence` (open question) is not done.
- **Phase C.5 (`registry.TagSet`, `CoreTags`, `COSETags`) is covered by
  023**: `rfc8949.TagSet`, `TagsModeled` and `TagsWellKnown` already
  provide allow-list sets; a second set type in `registry` would
  duplicate them.
- **Root aliases** for the helpers are `var` aliases (as `corecbor.go`
  does for constructors), which also keeps the two gofumpt versions in
  use (`make fmt-check` and golangci-lint) in agreement.
- **Sibling migration.** `cose` uses the shared `TagCOSE*` constants.
  `cwt` and `eat` have no tag 61/601/602 handling yet; 031 and 032 use
  the constants when they add it.
- **Generator.** Besides frozen names, it now writes the license header
  the committed `tags_gen.go` already carried, so a no-fetch
  regeneration is byte-identical. Tag 76 (`TagReserved`, RFC 8746) is a
  registered reserved code point and keeps its v0.2.2 constant; only
  "Unassigned" rows are skipped.

### Behavior

Phases A–C are additive. Existing `TagEncodedCBOR` / `AsNestedCBOR` are
kept. `AsNestedCBOR` gains a doc note pointing to `DecodeEncodedCBOR`.
The registry refresh adds generated constants and updates the data
returned by `LookupTag`, `IsRegistered` and `AllTags`. Those functions
document that they reflect the IANA registry, so new rows are their
contract, not a semantic change. No existing generated constant is
renamed, removed or revalued (Phase C step 3).

### Failure modes

| Sentinel | When |
|---|---|
| `ErrMalformedTag` (new) | wrong tag number, wrong inner kind, wrong length (UUID ≠ 16 bytes, IPv4 > 4 bytes, …) |
| `ErrNonCanonicalTag` (new) | RFC-level canonical violations: prefix with trailing zeros or host bits; OID with leading 0x80 arc byte |
| `ErrOverflow` (025) | `DaysTo`/`AsDate`/`AsDuration`/`AsExtendedTime` outside `time.Time`/`time.Duration` range |
| `ErrTrailingBytes` (existing) | `DecodeEncodedCBOR` content has more than one item |

---

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).
This proposal adds helpers, constants and data; no existing identifier
changes signature or semantics, and no existing encode/decode/diagnostic
output changes.

| Change | Class | Contract restored | Existing identifiers in v0.30 | Selector |
|---|---|---|---|---|
| New tag helpers (UUID, dates, extended time, IP, OID, tag 24) and short constants in `cbor/tags.go` | Additive | — | unchanged | n/a |
| Existing tag helpers' errors also wrap `ErrMalformedTag` | Additive | — | `Error()` text identical; existing `errors.Is` matches unchanged | n/a |
| `registry.json` / `tags_gen.go` regenerated from the current IANA registry | Contract (data refresh) | `registry/doc.go` (package reflects the IANA CBOR tag registry) | every v0.2.2 constant keeps name and value; `LookupTag`/`IsRegistered`/`AllTags` return the refreshed rows | none |
| `registry.TagSet`, `CoreTags`, `COSETags` | Additive | — | n/a | n/a |
| Phase E Concise Diagnostic Notation (draft-ietf-cbor-edn-literals) | Draft → Additive on publication | — | `Diagnostic`/`DiagnosticValue` default output unchanged | `DiagCDN() DiagnosticOption`, opt-in, only after RFC publication |

`CompatV02()` / `CompatV02Decoding()` bundle nothing from 026. No
`...Option` parameters are appended to existing functions.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| `UUIDTo`/`AsUUID` round-trip; non-16-byte inner → `ErrMalformedTag` | `cbor/tags_test.go` | Yes |
| `DateTo` matches RFC 8943 §3 examples; `AsDate` accepts 100 and 1004 | examples from RFC 8943 | Yes |
| `AsExtendedTime` decodes RFC 9581 §3 examples; unknown keys survive round-trip in `Extra` | vectors from RFC 9581 | Yes |
| `PrefixTo`/`AsPrefix` match RFC 9164 §4 examples, including trailing-zero removal and the interface form | vectors from RFC 9164 | Yes |
| `OIDTo`/`AsOID` match RFC 9090 §2 / App. A examples (incl. tag 112) | vectors from RFC 9090 | Yes |
| `EncodeEncodedCBOR` → `DecodeEncodedCBOR` returns identical raw bytes | unit test | Yes |
| `cose`, `cwt`, `eat` reference `cbor.TagCOSE*`/`TagCWT` instead of private literals | grep in Phase A PR | Yes |
| `registry.json` record count matches IANA at refresh time; generator emits no `Unassigned` constants | generator test + committed diff | Yes |
| RFC 8943, 9090, 9164, 9277, 9581, 9781 vendored under `rfcs/` with inventory rows | `rfcs/README.md` diff | Yes |
| §4.3 table gains rows for each new tag | spec diff | Yes |
| No `AsX` helper panics on any input | `FuzzTagHelpersNeverPanic` | Yes |
| No Phase A–C change alters bytes produced or accepted by v0.2.2 for the legacy fixture set | `TestCompatV02MarshalGolden` (025) passes unchanged after 026 lands | Yes |
| No exported identifier present in v0.2.2 is removed, renamed, or retyped, and no method is added to an exported interface (034 API stability) | `apidiff` against `v0.2.2` for this module, run in `make check` | Yes |
| Existing identifiers called with no new options reproduce the v0.2.2 golden vectors, except the contract-defect fixes listed under Compatibility selection | `testdata/legacy-v0.2.2/` golden tests | Yes |
| Every constant in v0.2.2 `registry/tags_gen.go` exists after regeneration with the same name and value | `TestRegistryNamesFrozen` against `registry/names_frozen.txt` | Yes |
| `Diagnostic()` output for the diagnostic test corpus is byte-identical to v0.2.2 | `diagnostic_test.go` golden | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | Envelope constants, tag-24 constructor/decoder, sibling migration | Done | Phase A rows green |
| B | UUID, dates, extended time, IP, OID helpers | Done | Phase B rows green |
| C | Registry refresh, generator fixes, stability note, `TagSet` | Done (`TagSet` covered by 023) | Registry diff merged |
| D | RFC 8746 typed arrays | Deferred | Consumer request |
| E | CDN / EDN alignment | Deferred | `draft-ietf-cbor-edn-literals` published as RFC |

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestUUID*`, `TestDate*`, `TestExtendedTime*`, `TestIP*`, `TestOID*` | helpers vs RFC examples | `cbor/tags_test.go` |
| `TestEncodedCBORRoundTrip` | tag 24 raw-byte fidelity | `marshal_test.go` |
| `FuzzTagHelpersNeverPanic` | every `AsX` on arbitrary decoded Values — new §7.1 row | `cbor/fuzz_test.go` |
| `TestRegistryNoUnassigned` | generator output hygiene | `registry/registry_test.go` |
| Extended `FuzzTagPreservation` | new tag numbers pass through opaque when helpers aren't used | `fuzz_test.go` |

---

## Performance

Not a perf proposal. The helpers are off the hot path, and §9 benchmarks
must not regress (`make bench` against `bench-020-baseline.txt`).

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| IANA description edits push the generator toward new names | med | low | Frozen-name list (Phase C.3); test asserts every v0.2.2 constant still exists with the same value |
| RFC 9581 key space is large; partial modelling loses data | med | med | Preserve unknown keys in `Extra`; reject only fraction forms we can't represent |
| `DateTo` location semantics surprise callers (UTC vs local civil date) | med | low | Document: civil date in `t.Location()`; tests for both |
| Adding `ErrMalformedTag` wrapping to existing helpers changes error strings | low | low | Strings aren't API; `errors.Is` behavior only gains a match |
| CDN draft changes again before RFC | med | low | Phase E gated on RFC publication |

---

## Alternatives considered

- **Use the generated registry constants as the public API.** That is
  zero-effort, but derived names are long and hard to read (see
  Motivation). Rejected as the *only* API; the generated constants stay
  supported and frozen, and `cbor/tags.go` adds readable names.
- **A separate `tags` sub-package** for helpers. It would keep `cbor`
  smaller, but splits the `AsTime`/`AsBigInt` family across two
  packages. Rejected for consistency. Revisit if `cbor` grows beyond
  roughly 15 helper families.
- **Model tag 1001 completely**, including decimal and bigfloat fractions.
  That needs `big.Rat` plumbing for marginal benefit. Deferred.
- **Ship CDN alignment now.** The draft is in WGLC, but `rfcs/README.md`
  forbids anchoring contracts on I-Ds. Rejected until publication.

---

## Open questions

- Should `AsDate` on tag 0 / tag 1 inputs also succeed (truncating to
  the day)? mDL verifiers see `tdate` and `full-date` side by side.
- Should RFC 9277's `55800` magic be emitted by `EncodeSequence` behind
  an option (`WithSequenceMagic()`), and stripped by `DecodeSequence`
  the same way 55799 is stripped today?
- Do we want `uuid.UUID`-shaped convenience (a `[16]byte` named type with
  `String()`), or leave that to callers' UUID libraries?

---

## Cross-references

- Spec: §4.3, §5, §7.1, §10 Phase 3 of `encoder-decoder-spec.md`
- RFCs (to vendor): RFC 8943, RFC 9090, RFC 9164, RFC 9277, RFC 9581,
  RFC 9781; already vendored: `rfcs/rfc9562.txt` §4, `rfcs/rfc8949.txt`
  §3.4.5.1, §8, `rfcs/rfc9052.txt` §2; RFC 9711 §5 (tag 602)
- Proposals: 006 (registry codegen), 009 (diagnostic notation), 021
  (tag-1 range fixes), 023 (tag allow-list), 025 (`ErrOverflow` in `cbor`)
- External: IANA CBOR Tags registry
  (<https://www.iana.org/assignments/cbor-tags/>, updated 2026-11-13);
  `draft-ietf-cbor-edn-literals-29`; ISO/IEC 18013-5 (tag 24 / 1004 usage)

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
| 2026-11-20 | API stability (signature + semantics) per revised 034 | corecbor maintainers |
| 2026-11-21 | Phases A–C implemented; registry refreshed (+10 tags); IXDTF 10/11/13 corrected to RFC 9581 map keys; Phases D, E deferred; status In-Progress | corecbor maintainers |
