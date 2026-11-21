# 035 — Caller-selected representation of text that is not valid UTF-8

## Header

| Field | Value |
|---|---|
| **Number** | 035 |
| **Tier** | 1 |
| **Status** | Accepted |
| **Filed** | 2026-11-21 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 021 (D13/D18), 023 (sentinels), 034 |
| **Supersedes** | none |
| **Spec sections touched** | §2.2 (UTF-8 bullet), §2.3, §3.1 (`RejectInvalidUTF8`), §5 |

---

## TL;DR

RFC 8949 §3.1 makes a CBOR text string (major type 3) valid UTF-8 by
definition, but Go strings carry arbitrary bytes, and many inputs
(JSON lone surrogates, legacy data, untrusted clients) produce strings
that are not valid UTF-8. Today a caller can only reject them
(default) or `AllowInvalidUTF8()`, which writes a non-conformant text
string. This proposal adds an explicit, caller-selected policy on the
encoder and decoder — **Reject**, **Allow**, **Replace**, **Lossless**
— plus per-value helpers, so each consumer chooses a representation and
records it as part of its own format. Valid UTF-8 encodes byte-
identically under every policy.

Acceptance: every policy has encode/decode tests with the vectors
below; `AllowInvalidUTF8()` output is unchanged (golden vectors);
`apicheck` clean; a fuzz target checks Lossless round-trips exactly.

---

## Motivation

A downstream storage consumer found that the same client request
stored different bytes before and after a codegen migration: the old
JSON decoder replaced invalid UTF-8 with U+FFFD, the new one preserves
the raw bytes, and corecbor (with `AllowInvalidUTF8()`) wrote whatever
it was given. The consumer needs to choose — reproduce the old stored
bytes, keep the original bytes losslessly, or keep today's output —
without writing its own UTF-8 handling around corecbor, and without
being forced into non-conformant CBOR to be lossless.

## Proposal

### Policies

```go
// InvalidUTF8 selects how text that is not valid UTF-8 is handled.
type InvalidUTF8 int

const (
	// InvalidUTF8Reject returns ErrInvalidUTF8 (encoder default).
	InvalidUTF8Reject InvalidUTF8 = iota
	// InvalidUTF8Allow writes or accepts the bytes as a text string
	// unchanged. Not conformant (RFC 8949 §3.1). Same as
	// AllowInvalidUTF8() on the encoder; the decoder's default.
	InvalidUTF8Allow
	// InvalidUTF8Replace substitutes U+FFFD for each byte that is not
	// part of a valid UTF-8 sequence, exactly as Go's range loop and
	// encoding/json do. Conformant, lossy.
	InvalidUTF8Replace
	// InvalidUTF8Lossless writes conformant CBOR that preserves the
	// exact bytes: tag 273 (WTF-8, IANA) when the string is valid
	// WTF-8 — that is, its only defect is encoded surrogate code
	// points — and otherwise a plain byte string (major type 2).
	InvalidUTF8Lossless
)

func WithInvalidUTF8(p InvalidUTF8) Option          // encoder
func WithInvalidUTF8Decoding(p InvalidUTF8) DecoderOption // decoder
```

`AllowInvalidUTF8()` stays and equals `WithInvalidUTF8(InvalidUTF8Allow)`;
`RejectInvalidUTF8()` stays and equals
`WithInvalidUTF8Decoding(InvalidUTF8Reject)`. Conflicting options on one
encoder/decoder: the last one wins, as with other options.

### Encoder behavior

| Input text | Reject | Allow | Replace | Lossless |
|---|---|---|---|---|
| valid UTF-8 `"ab"` | `626162` | `626162` | `626162` | `626162` |
| `"a\xffb"` | `ErrInvalidUTF8` | `6361ff62` | `6561efbfbd62` | `4361ff62` |
| `"a\xff\xfeb"` | `ErrInvalidUTF8` | `6461fffe62` | `6861efbfbdefbfbd62` | `4461fffe62` |
| WTF-8 lone surrogate `"x\xed\xa0\x80y"` | `ErrInvalidUTF8` | `6578eda08079` | `6b78efbfbdefbfbdefbfbd79` | `d901114578eda08079` (tag 273) |

Map keys follow the same policy. In deterministic modes, map key
ordering uses the bytes actually written. A Lossless key that becomes
a byte string, or a Replace key that becomes equal to another key,
is subject to duplicate detection (`ErrDuplicateMapKey`, 021 D15)
like any other key.

The policy applies everywhere text is encoded: `Encode`, `EncodeTo`,
`Marshal`, `StreamEncoder.WriteText` and `WriteValue`.

### Decoder behavior

- `InvalidUTF8Allow` (default): unchanged — invalid text decodes to a
  `Text` value with the raw bytes.
- `InvalidUTF8Reject`: `ErrInvalidUTF8` (as `RejectInvalidUTF8()`).
- `InvalidUTF8Replace`: invalid text decodes with U+FFFD substituted
  per byte.
- `InvalidUTF8Lossless`: as Allow for text strings; additionally,
  `Unmarshal` into a Go `string` accepts tag 273/272/274 and plain byte
  strings and stores their exact bytes. (By default, byte string →
  `string` remains a type mismatch.)

### Per-value helpers

```go
// TextLossless returns Text(s) when s is valid UTF-8 and otherwise the
// InvalidUTF8Lossless form (tag 273 or a byte string), so callers can
// opt in field by field.
func TextLossless(s string) Value

// AsText returns the string carried by v: a text string's bytes, or
// the exact bytes of tag 272/273/274 or a byte string. It returns an
// error wrapping ErrTypeMismatch for anything else. The caller's
// schema decides whether a byte string is text.
func AsText(v Value) (string, error)
```

Tag constants `TagCESU8 = 272`, `TagWTF8 = 273`, `TagMUTF8 = 274` are
added to `cbor/tags.go` (026 lists them for the tag helpers).

### Diagnostic notation

Unchanged from 021 D13 for invalid text strings. Tag 273 renders as
`273(h'…')`.

## Compatibility selection

| Change | Class | Existing identifiers | Selector |
|---|---|---|---|
| Policies, `WithInvalidUTF8`, `WithInvalidUTF8Decoding`, `TextLossless`, `AsText`, tag constants | Additive | `AllowInvalidUTF8()`, `RejectInvalidUTF8()` unchanged in output and meaning | the options are the opt-in |

Default encoder (Reject) and decoder (Allow) behavior is unchanged.

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| The encoder table above, for all four policies, in every mode | `TestInvalidUTF8EncodePolicy` | Yes |
| `AllowInvalidUTF8()` output identical to v0.2.2 (existing golden vectors and the variant-tag storage corpus unchanged) | golden vectors | Yes |
| Replace matches `[]rune`/range-loop substitution (one U+FFFD per invalid byte) for random inputs | `FuzzInvalidUTF8Replace` | Yes |
| Lossless: `AsText(decode(encode(s))) == s` for every Go string; output passes `RequireDeterministic` in deterministic modes and is valid UTF-8 everywhere it is major type 3 | `FuzzInvalidUTF8Lossless` | Yes |
| WTF-8 detection: tag 273 iff the only defects are encoded surrogates | `TestWTF8Detection` table | Yes |
| Decoder Replace / Reject / Lossless `Unmarshal` into `string` per the section above | `TestInvalidUTF8DecodePolicy` | Yes |
| StreamEncoder applies the policy | `TestStreamInvalidUTF8Policy` | Yes |
| No regression >5% on encode/decode benches (valid text takes the existing fast path) | benchstat vs main | Yes |
| `apicheck` clean | `make check` | Yes |

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Lossless byte strings are indistinguishable from real byte fields | med | med | Documented: the caller's schema decides; `AsText` is explicit |
| Replace changes map keys into duplicates | low | med | Duplicate detection applies; documented |
| Policy checks slow valid-text encoding | low | med | Validation already runs; the policy branch is only taken on failure |

## Alternatives considered

- **Unregistered/private tag for arbitrary bytes.** Rejected by
  maintainers: conformant plain byte strings avoid an unregistered code
  point; the schema already knows which fields are text.
- **Unicode maximal-subpart replacement.** Rejected by maintainers in
  favor of per-byte replacement, which matches `encoding/json` and Go
  and reproduces bytes stored by consumers that relied on them.

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-21 | Filed and accepted (maintainer decisions: plain byte string for non-WTF-8 bytes; per-byte replacement) | corecbor maintainers |
