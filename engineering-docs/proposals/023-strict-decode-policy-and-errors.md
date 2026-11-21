# 023 — Strict decode policy (tag allowlist) and structured errors

## Header

| Field | Value |
|---|---|
| **Number** | 023 |
| **Tier** | 1 |
| **Status** | Draft |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001, 034 (compatibility policy) |
| **Supersedes** | none |
| **Spec sections touched** | §3.1, §3.2, §5, §7.1 |

---

## TL;DR

`StrictDecoder` cannot decode a COSE message, a CWT, or a timestamp.
`rfc8949.StrictOpts` turns on `RejectUnknownTags`, and the "known"
set contains only tag 55799 (`rfc8949/decode.go:115-117,718`). So
tags 0–3, 18, 24 and 61 all fail with `ErrUnknownTag`. This also
contradicts §3.2, which says `RejectUnknownTags` is *not* part of the
strict preset.

This proposal:

1. Replaces the boolean knob with an explicit tag allowlist
   (`WithAllowedTags`).
2. Removes tag rejection from `StrictDecoder` so it matches §3.2.
3. Adds a structured `*DecodeError` that carries the offset (and,
   optionally, a path), so callers no longer parse error strings.
4. Moves reflection's untyped mismatch errors under an
   `ErrTypeMismatch` sentinel.

Acceptance: `StrictDecoder().Decode` accepts `18([...])` and `1(1)`;
`errors.As(err, &*DecodeError)` yields the offset for every decoder
error.

---

## Motivation

Observed on `main@00e1307`:

```
StrictDecoder().Decode(c1 01)  → cbor: unknown tag ID at offset 0
StrictDecoder().Decode(d2 80)  → cbor: unknown tag ID at offset 0
```

- **The strict preset is unusable for its main audience.** §3.2 names
  "inputs feeding into AAD-bound cryptographic primitives" as the
  target. COSE (tags 16–18, 96–98), CWT (61), EAT/UCCS (601) and
  detached EAT bundles (602) are all tagged.
- **The knob can't be configured.** "Unknown" ought to mean "not in
  the caller's allowlist". Today the list is a hard-coded
  package-private map.
- **Offsets are only in strings.** Errors look like
  `fmt.Errorf("%w at offset %d", …)` (`rfc8949/decode.go`, around 40
  sites). A caller has to parse text to report the location or to
  re-sync a sequence. Downstream modules flatten causes with `%v`
  (`cose/marshal.go:60,95`; `cwt/token.go:31`), partly because there
  is no structured type worth keeping.
- **Reflection errors have no sentinel.** `typeMismatch`
  (`reflect_decode.go:363`) returns a bare `fmt.Errorf`, which breaks
  the §5 rule "every error MUST … wrap one".
  `rfc8949.ErrTypeMismatch` exists (`rfc8949/cursor.go:18`) but isn't
  in the catalog or used by reflection.

---

## Proposal

### Public API surface

```go
// WithAllowedTags restricts the tags the decoder accepts to ids (plus
// any added by later WithAllowedTags calls). A tag not in the set
// fails with ErrUnknownTag. Tag 55799 (self-describe) is always
// allowed. Calling WithAllowedTags with no arguments allows only
// 55799.
func WithAllowedTags(ids ...uint64) DecoderOption

// RejectUnknownTags rejects every tag not in the allowlist built by
// WithAllowedTags. With no WithAllowedTags option, the allowlist is
// TagsWellKnown. (Previously the allowlist was {55799} only.)
func RejectUnknownTags() DecoderOption

// TagsWellKnown is the default allowlist for RejectUnknownTags: the
// RFC 8949 §3.4 tags plus the tags of the COSE/CWT/EAT family that
// this module tree implements.
var TagsWellKnown = []uint64{
	0, 1, 2, 3, // RFC 8949 §3.4.1–3.4.3
	21, 22, 23, // expected conversion
	24,             // encoded CBOR
	32,             // URI
	16, 17, 18,     // COSE_Encrypt0, COSE_Mac0, COSE_Sign1 (RFC 9052)
	96, 97, 98,     // COSE_Encrypt, COSE_Mac, COSE_Sign
	61,             // CWT (RFC 8392)
	601,            // UCCS (RFC 9781)
	602,            // detached EAT bundle (RFC 9711 §5)
	55799,          // self-describe
}
```

`StrictDecoder` drops `RejectUnknownTags`, as §3.2 already says. The
spec's §3.2 example stays authoritative, and
`rfc8949.StrictOpts().RejectUnknownTags` becomes `false`. Callers who
want closed-world tag validation pass
`StrictDecoder(RejectUnknownTags())` or `WithAllowedTags(...)`.

`rfc8949.DecodeOpts` gains `AllowedTags map[uint64]struct{}`. A nil
map with `RejectUnknownTags` means `TagsWellKnown`. Lookup is a
single map probe per tag, the same cost as today's `knownTags`.

### Structured errors

```go
// DecodeError is the concrete type of every error returned by the
// decoder (Decode, DecodePrefix, DecodeFrom, Stream, Cursor). It
// always wraps one §5 sentinel.
type DecodeError struct {
	Offset int    // byte offset of the offending item's head in src
	Path   string // RFC 9535-style path, e.g. "$[2].foo" — only when WithErrorPath()
	Err    error  // the §5 sentinel (possibly further wrapped)
}

func (e *DecodeError) Error() string // "cbor: <sentinel text> at offset N[ (path)]"
func (e *DecodeError) Unwrap() error { return e.Err }

// WithErrorPath enables path tracking in DecodeError. Off by default:
// it costs one small allocation per container level on the error path
// only, but requires a frame stack on the success path.
func WithErrorPath() DecoderOption
```

The `Error()` text stays byte-identical to today's
`"<sentinel> at offset N"`. Anyone matching on strings keeps working,
and `errors.Is` keeps working through `Unwrap`.

Reflection errors:

```go
// ErrTypeMismatch indicates a CBOR value cannot be stored in the Go
// target type. Wrapped by *UnmarshalTypeError.
var ErrTypeMismatch = cbor.ErrTypeMismatch // moved from rfc8949; rfc8949 re-exports

// UnmarshalTypeError describes a CBOR value that was not appropriate
// for a value of a specific Go type.
type UnmarshalTypeError struct {
	CBORKind cbor.Kind
	GoType   reflect.Type
	Field    string // dotted Go field path, e.g. "Header.Alg"
	Err      error  // ErrTypeMismatch or ErrOverflow
}

func (e *UnmarshalTypeError) Error() string
func (e *UnmarshalTypeError) Unwrap() error { return e.Err }
```

`typeMismatch`, the overflow errors in `setUint`/`setNegInt`/`setFloat`,
and the tag mismatch in `decodeMapToStruct` (`reflect_decode.go:286-290`)
all return `*UnmarshalTypeError`. `ErrOverflow` stays a separate
sentinel.

The encoder's `"encode: unsupported Value kind %d"`
(`rfc8949/encode.go:171`) wraps new sentinel `ErrInvalidKind`.

### Downstream guidance

Downstream modules (cose, cwt, eat, edhoc) MUST wrap with `%w`. Use
two `%w` verbs when adding a module sentinel, for example
`fmt.Errorf("%w: %w", ErrMalformed, err)`. This is tracked in each
module's own proposal (027, 031, 032, 033), not here.

### Behavior

- **`StrictDecoder` accepts tags.** This is a behavior change and the
  intended one.
- **`RejectUnknownTags()` without `WithAllowedTags` widens** from
  {55799} to `TagsWellKnown`. Callers who relied on the old near-total
  rejection pass `WithAllowedTags()` (empty, so only 55799 is
  allowed). `StrictDecoder(RejectUnknownTags(), WithAllowedTags())`
  reproduces the v0.2 `StrictDecoder` exactly (see Compatibility
  selection).
- **Error type.** The dynamic type of decoder errors changes from
  `*fmt.wrapError` to `*DecodeError`. Code using `errors.Is` is
  unaffected.

### Failure modes

New sentinels:

- `ErrTypeMismatch`, promoted into the §5 catalog
- `ErrInvalidKind`

New concrete types: `*DecodeError` and `*UnmarshalTypeError`.

---

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).

| Change | Class | Default (v0.30) | Selector |
|---|---|---|---|
| `StrictDecoder` stops rejecting every tag (matches spec §3.2) | Defect (vs §3.2) | accepts tags | `StrictDecoder(RejectUnknownTags(), WithAllowedTags())` reproduces v0.2 — composition of existing options, no new legacy API |
| `RejectUnknownTags()` alone widens from {55799} to `TagsWellKnown` | Policy | `TagsWellKnown` | `WithAllowedTags()` (no IDs) restores {55799} |
| `TagsWellKnown` contents track the IANA registry and the tags this module tree implements | Policy (current registry) | list above | `WithAllowedTags(ids...)` pins an explicit set |
| Decoder errors become `*DecodeError` (same `Error()` text, same `errors.Is` sentinels) | Additive | n/a | n/a — callers using `errors.Is` are unaffected; type assertions on `*fmt.wrapError` were never supported |

No new `Legacy…` option is needed: the existing options compose into
the v0.2 behavior. The root decoder bundle `CompatV02Decoding()
DecoderOption` (defined in 025) does **not** apply these, because "reject
every tag" was only ever reachable through `StrictDecoder`; bundling it
would make `NewDecoder(CompatV02Decoding())` stricter than v0.2's
`NewDecoder()`.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| `StrictDecoder().Decode(c1 01)` and `(d2 80)` succeed | `TestStrictDecoderAcceptsTags` | Yes |
| `StrictDecoder(RejectUnknownTags()).Decode(d9 ffff 00)` (tag 65535) → `ErrUnknownTag` | `TestRejectUnknownTagsDefaultAllowlist` | Yes |
| `WithAllowedTags(18)` + `RejectUnknownTags()` accepts 18 and 55799, rejects 1 | `TestWithAllowedTags` | Yes |
| Every decoder error satisfies `errors.As(err, new(*DecodeError))` with correct `Offset` | `TestDecodeErrorOffsets`, table over every §5 decoder sentinel | Yes |
| `DecodeError.Error()` text unchanged from current output for the error-catalog vectors | `error_catalog_test.go` golden strings | Yes |
| `WithErrorPath()` reports `$[1].k` for a truncated value at that position | `TestDecodeErrorPath` | Yes |
| `Unmarshal("text", &int)` → `errors.Is(err, ErrTypeMismatch)` and `errors.As(err, new(*UnmarshalTypeError))` with `Field` set | `TestUnmarshalTypeError` | Yes |
| No bare `fmt.Errorf` without `%w`, and no `errors.New` outside a `var` sentinel block, in the root, `cbor`, `rfc8949`, `wire` | `make lint` rule (`forbidigo` or custom `go vet` analyzer) | Yes |
| §3.2 code sample and `rfc8949.StrictOpts` agree | `TestStrictOptsMatchesSpec` (asserts `RejectUnknownTags == false`) | Yes |
| `StrictDecoder(RejectUnknownTags(), WithAllowedTags())` rejects `c1 01` and `d2 80` exactly as v0.2.2 `StrictDecoder()` does | `TestCompatV02StrictTags` against `testdata/legacy-v0.2.2/` | Yes |
| `RejectUnknownTags()` + `WithAllowedTags()` allows only 55799 (default and selected behavior both tested) | `TestCompatRejectUnknownTagsEmptyAllowlist` | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | Tag allowlist, `StrictDecoder` fix | Pending | First three rows pass |
| 2 | `DecodeError` (offset), `UnmarshalTypeError`, `ErrInvalidKind` | Pending | Error rows pass |
| 3 | `WithErrorPath`, lint enforcement | Pending | Remaining rows pass |

Phase 1 is small and blocks 027 and 031, which need a strict decoder
that can decode COSE and CWT.

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| Tests named above | policy and error types | `decoder_test.go`, `error_catalog_test.go`, `marshal_test.go` |
| `FuzzDecodeNeverPanics` (existing) | extended: every returned error must `errors.As` to `*DecodeError` | `fuzz_test.go` |
| `FuzzTagPreservation` (existing §7.1) | extended: run under `StrictDecoder()` and `StrictDecoder(WithAllowedTags(random…))` | `fuzz_test.go` |
| `FuzzDecodeErrorOffsetInBounds` (new) | `0 <= Offset <= len(src)` for every error | `fuzz_test.go` |

---

## Performance

| Metric | Target | Test mechanism |
|---|---|---|
| Decode success path | unchanged (±2%); `*DecodeError` is allocated only on failure | `BenchmarkDecode*` |
| `WithErrorPath` success path | ≤ 5% overhead on `BenchmarkDecodeNestedMapStrict` | bench with option |
| Tag allowlist probe | 1 map lookup per tag, as today | inspection + bench |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Callers relied on `StrictDecoder` rejecting all tags as a crude "no tags" guard | low | med | Release note; `WithAllowedTags()` with no args restores it |
| `TagsWellKnown` drifts from what modules implement | med | low | Exported var, documented. Modules pass their own sets anyway |
| Changing the error's dynamic type breaks `==` comparisons | low | low | `==` against sentinels already fails today because errors are wrapped |

---

## Alternatives considered

- **Treat IANA-registered tags as "known"** (via `registry.IsRegistered`).
  Rejected: registration says nothing about whether the *caller*
  handles the tag's semantics, and it would pull a 260-entry registry
  into the decode hot path. The allowlist is the caller's statement of
  intent.
- **Keep `RejectUnknownTags` in `StrictDecoder` and fix only the
  set.** Rejected: it contradicts §3.2 and forces every caller to know
  the set.
- **A per-tag callback (`WithTagHandler(func(id uint64) error)`).**
  More flexible, but it puts an indirect call on the hot path. It may
  come later as tier-2 if a consumer needs semantic checks (for
  example, validating tag 1's inner type during decode).

---

## Open questions

1. Should `TagsWellKnown` include RFC 8943 (100, 1004), RFC 9581
   (1001–1003), RFC 9164 (52, 54) and RFC 9562 (37)? 026 adds helpers
   for those tags. The proposal here is to add each one to
   `TagsWellKnown` in the same PR that adds its helper.
2. Is RFC 9535 the right path syntax for `DecodeError.Path` (it is a
   JSONPath standard), or should we use EDN-style `[2]{"foo"}`?

---

## Cross-references

- Spec: §3.1, §3.2 (contradiction resolved), §5, §7.1
- Proposals: [021](021-core-codec-safety-fixes.md), [022](022-raw-byte-preservation.md), [024](024-serialization-profiles-alignment.md), 025 (reflection ergonomics; `DisallowUnknownFields` lives there and returns `*UnmarshalTypeError`-style `*UnknownFieldError`), 026 (tag helpers), 027/031/032/033 (downstream `%w` wrapping)
- RFCs: RFC 8949 §3.4, §5.4 (validity and tag handling); RFC 9052 §2 (COSE tags); RFC 8392 §6 (tag 61); RFC 9781 (tag 601); RFC 9711 §5 (tag 602); RFC 9535 (JSONPath) — vendor `rfc9535.txt` only if Path syntax is accepted
- Go precedent: `encoding/json.UnmarshalTypeError`, `encoding/json.SyntaxError.Offset`

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft from the 2026-11-20 codebase review | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
