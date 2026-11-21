# 022 — Raw byte preservation through decode

## Header

| Field | Value |
|---|---|
| **Number** | 022 |
| **Tier** | 1 |
| **Status** | Draft |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 014 (RawMessage/RawTag), 018 (Cursor, zero-copy), 020 (internal arena), 021 (D2 aliasing fix), 034 (compatibility policy) |
| **Supersedes** | amends 014 (RawMessage semantics) |
| **Spec sections touched** | §3.1 (decoder API), §4 (value model), §6.2, §7.1, §9 |

---

## TL;DR

The decoder throws away where each item sat in the source bytes. As a
result, everything that needs the *original* bytes rebuilds them by
re-encoding in Core Deterministic mode:

- `RawMessage` and `RawTag` (`raw.go:44-61`)
- every `Unmarshaler` (`reflect_decode.go:112-119`)
- every downstream protocol layer, most importantly the COSE
  protected-header check (`cose/headers.go:134`, `cose/sign.go:145`)

Re-encoding reorders maps, shortens integers and floats, and drops
indefinite lengths, so signatures over third-party bytes fail.

This proposal adds:

1. `Decoder.DecodePrefix` and `Decoder.DecodeRaw`, which return the
   exact source slice of the item they decode.
2. Pass-through of the original bytes to `RawMessage` and `RawTag`
   during reflective decode (their documented contract), and to any
   other `Unmarshaler` when the caller opts in with
   `WithVerbatimUnmarshalerInput()`.
3. Promotion of `rfc8949.Cursor` to a root-level `Cursor` type.

Acceptance: `Unmarshal` into a struct with a `RawMessage` field
preserves an unsorted, non-shortest, indefinite-length inner value
byte for byte.

---

## Motivation

Observed on `main@00e1307`:

```
input field r: a2 6162 01 6161 02      ({"b":1,"a":2})
RawMessage   : a2 6161 02 6162 01      (re-sorted)
```

Who this breaks:

- **COSE (RFC 9052 §4.4, §5.3).** `Sig_structure` and `Enc_structure`
  carry `body_protected` as the bstr *as transmitted*. Today
  `decodeProtected` parses the header into a Go map and
  `encodeProtected` rebuilds it, so any sender that isn't Core
  Deterministic fails to verify. That includes WebAuthn authenticators,
  mDL issuers and C2PA signers. The COSE-side fix is
  [027](027-cose-verification-hardening.md). It needs this proposal's
  primitives for nested raw spans, because protected headers are bstrs
  that wrap CBOR maps.
- **WebAuthn `authData`.** It contains a COSE_Key followed by
  extension bytes, with no length prefix. Callers need "decode one item
  and give me the rest". That exists only in `rfc8949.Decode`, which
  returns an int offset, and in `rfc8949.Cursor`, which isn't
  re-exported.
- **EDHOC and RFC 8742 sequence consumers** need the same prefix
  decode (proposal 033).
- **mDL (ISO 18013-5)** hashes `#6.24(bstr .cbor IssuerSignedItem)` as
  transmitted. Callers must hash the raw item, not a re-encoding.
- **`Unmarshaler` implementations** get bytes that differ from the
  input. In the worst case they validate a canonicalized form the
  sender never signed.

---

## Proposal

### Public API surface

```go
// DecodePrefix decodes the first complete CBOR data item in src and
// returns it together with the unconsumed remainder. Unlike Decode,
// trailing bytes are not an error. raw is src[:len(src)-len(rest)]
// and aliases src.
func (d *Decoder) DecodePrefix(src []byte) (v Value, rest []byte, err error)

// DecodeRaw is Decode plus the exact source bytes of the item, which
// is all of src on success. Provided for symmetry and for
// documentation: the returned raw slice is what a signature or hash
// over "the item as received" must cover.
func (d *Decoder) DecodeRaw(src []byte) (v Value, raw []byte, err error)

// Cursor is a forward-only, allocation-free reader over a CBOR byte
// slice. It is the root-level re-export of rfc8949.Cursor, configured
// with this decoder's options.
type Cursor = rfc8949.Cursor

// Cursor returns a Cursor over src that applies d's strictness knobs
// and limits.
func (d *Decoder) Cursor(src []byte) *Cursor
```

`rfc8949.Cursor` gains these methods:

```go
// Raw returns the source bytes of the item the cursor is positioned
// at, without advancing.
func (c *Cursor) Raw() ([]byte, error)

// DecodeRaw decodes the current item, returning its Value and source
// bytes, and advances past it.
func (c *Cursor) DecodeRaw() (cbor.Value, []byte, error)

// Bytes returns the contents of the current byte-string item without
// copying (aliasing src), and advances. Errors with ErrTypeMismatch if
// the item is not major type 2. Indefinite-length byte strings return
// ErrIndefiniteLength, since they have no single contiguous span.
func (c *Cursor) Bytes() ([]byte, error)
```

`Bytes()` is how COSE reaches the protected-header bstr contents
without copying.

### Reflective decode receives original bytes

- `Decoder.Unmarshal` switches from "decode a whole Value, then
  reflect" to a reflection walk over a `Cursor`. At each struct field
  or element whose target type is `RawMessage` or `RawTag`, it calls
  `Cursor.Raw()` and passes those bytes through unchanged. Everywhere
  else it decodes a `Value` and reuses today's `valueToGo`.
- **Other `Unmarshaler` implementations keep their v0.2.2 input by
  default** (the item re-encoded in Core Deterministic mode), because no
  documented contract promises them the original bytes and 034 keeps
  existing semantics where no contract or standard decides. A new
  decoder option opts them into the original bytes:

  ```go
  // WithVerbatimUnmarshalerInput passes every Unmarshaler the item's
  // bytes exactly as they appear in the input, as encoding/json does
  // for json.Unmarshaler. Without it, Unmarshalers other than
  // RawMessage and RawTag receive the item re-encoded in Core
  // Deterministic mode (the v0.2 behavior).
  func WithVerbatimUnmarshalerInput() DecoderOption
  ```
- `RawMessage.UnmarshalCBOR` already copies its input (`raw.go:28`),
  so the original bytes survive the arena reset.
- `RawTag.UnmarshalCBOR` parses only the tag head with `wire.ParseHead`
  and stores `data[h.N:]` as `Content`. It no longer decodes and
  re-encodes. It still checks that `Content` is exactly one
  well-formed item by running `Cursor.Skip` over it with the decoder's
  knobs.
- `callUnmarshaler` (`reflect_decode.go:112`) keeps its re-encoding
  path for non-raw `Unmarshaler`s without `WithVerbatimUnmarshalerInput`,
  and for `valueToGo` callers holding a bare `Value` (`UnmarshalValue`,
  see Open questions). Its godoc states that it canonicalizes.

The marshal side is symmetric: `marshalerToValue`
(`reflect_encode.go:189`) decodes `MarshalCBOR` output and re-encodes
it in the encoder's mode. A Marshaler that emits non-deterministic
bytes under a deterministic encoder still gets canonicalized, which
§2.1 requires; that is unchanged from v0.2.2 for every Marshaler. In
Permissive mode, `RawMessage` and `RawTag` bytes are spliced in verbatim
through a new internal `KindRaw`-style escape, restoring proposal 014's
"emitted directly (no re-encoding)" contract. Other Marshalers keep
their v0.2.2 Permissive behavior (decoded, then re-encoded). See Alternatives for why this isn't a public `Kind`.

### Arena and zero-copy interplay

| Decoder config | `raw` from `DecodePrefix`/`DecodeRaw`/`Cursor` | `Value` lifetime |
|---|---|---|
| default (internal arena) | aliases `src`; valid as long as `src` is | until next Decode (unchanged) |
| `WithoutInternalArena` | aliases `src` | independent |
| `WithZeroCopy` | aliases `src` | aliases `src` |

`raw` never points into the arena, because it is always a sub-slice of
the caller's `src`. Callers who keep `raw` beyond `src`'s lifetime
must copy it, the same way `bytes.Buffer.Bytes` works. `RawMessage`
always copies.

### Behavior

- **`RawMessage`/`RawTag` content.** It now exactly matches the input.
  This is a behavior change for callers who relied on canonicalization
  through `RawMessage`. Nobody should, given the type's name and godoc
  ("Passes through marshal/unmarshal without re-encoding", proposal
  014 TL;DR).
- **Unmarshaler input.** Unchanged by default: non-raw `Unmarshaler`
  implementations still receive the Core Deterministic re-encoding, as
  in v0.2.2. With `WithVerbatimUnmarshalerInput()` they receive the
  input as transmitted, and strictness knobs apply to those bytes.
- **Additive surface.** `DecodePrefix`, `DecodeRaw` and `Cursor` are
  new and don't change existing behavior.

### Failure modes

No new sentinels. The `Cursor` methods return existing ones:

- `ErrTruncated`
- `ErrIndefiniteLength` (from `Bytes()`)
- `ErrMaxNestingDepth`
- `ErrTypeMismatch`, which 023 moves into the §5 catalog.

---

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).
No exported identifier changes signature. The `RawMessage`/`RawTag`
changes are **Contract defects**; other `Unmarshaler`/`Marshaler`
implementations keep their v0.2.2 behavior unless the caller opts in.

| Change | Class | Contract restored | Existing identifiers in v0.30 | Selector |
|---|---|---|---|---|
| `RawMessage`/`RawTag` content on decode is the exact input bytes | Contract defect | proposal 014 (`014-raw-message-and-tag-wrapping.md:23-24`, `:136-143`: "captured as-is", "without modification") | original bytes | none (014's own contract; callers wanting canonical bytes decode then `Encode` with a deterministic `Encoder`) |
| `RawMessage`/`RawTag` spliced verbatim on Permissive-mode encode | Contract defect | `014-raw-message-and-tag-wrapping.md:142` ("emitted directly (no re-encoding)") | verbatim in Permissive; deterministic modes still canonicalize (§2.1) | none |
| Other `Unmarshaler`s receive original bytes | Additive (opt-in) | — (no contract; 034 precedence step 3 keeps existing behavior) | unchanged: Core Deterministic re-encode | `WithVerbatimUnmarshalerInput() DecoderOption` (recommended for signature-carrying types; not deprecated) |
| Other `Marshaler`s in Permissive mode | unchanged | — | decoded then re-encoded, as v0.2.2 | n/a |
| `DecodePrefix`, `DecodeRaw`, root `Cursor` alias, `Cursor.Raw/DecodeRaw/Bytes` | Additive | — | n/a | n/a |

No `...Option` parameters are appended to existing functions. The root
`CompatV02()` bundle includes nothing from 022.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| `RawMessage` field preserves `a2 6162 01 6161 02` exactly | `TestRawMessagePreservesUnsorted` | Yes |
| `RawMessage` preserves non-shortest ints (`18 01`) and indefinite arrays (`9f 01 ff`) | `TestRawMessagePreservesQuirks` | Yes |
| `RawTag{ID:24}` content equals the input bytes after the tag head | `TestRawTagNoReencode` | Yes |
| A `RawMessage`/`RawTag` field, and any `Unmarshaler` field under `WithVerbatimUnmarshalerInput()`, receives the exact input slice (checked by `bytes.Equal` against the field's span) | `TestUnmarshalerReceivesOriginalBytes` | Yes |
| `DecodePrefix(cose_key ‖ ext)` returns `rest == ext` | `TestDecodePrefixWebAuthnAuthData` using a real CTAP2 fixture in `testdata/` | Yes |
| `DecodeRaw` returns `raw == src` and fails with `ErrTrailingBytes` on extra bytes | `TestDecodeRaw` | Yes |
| `Cursor.Bytes()` on `h'a10126'` returns `a1 01 26` with 0 allocations | `TestCursorBytesZeroAlloc` (`testing.AllocsPerRun`) | Yes |
| Root `Cursor` honors the decoder's strictness knobs | `TestCursorAppliesKnobs` | Yes |
| No §9 decode metric regresses by more than 5% | `make bench` vs `bench-020-baseline.txt` | Yes |
| Package-level `Unmarshal` into a flat struct regresses ≤ 10% | `BenchmarkUnmarshalStruct` | Yes |
| v0.2.2 `RawMessage` outputs for the unsorted-map and non-shortest fixtures are captured in `testdata/legacy-v0.2.2/` and the migration guide shows before/after | golden test + doc review | Yes |
| No exported identifier present in v0.2.2 is removed, renamed, or retyped, and no method is added to an exported interface (034 API stability) | `apidiff` against `v0.2.2` for this module, run in `make check` | Yes |
| Existing identifiers called with no new options reproduce the v0.2.2 golden vectors, except the contract-defect fixes listed under Compatibility selection | `testdata/legacy-v0.2.2/` golden tests | Yes |
| A non-raw `Unmarshaler` receives Core-Deterministic re-encoded bytes by default and the original bytes under `WithVerbatimUnmarshalerInput()` | `TestUnmarshalerInputDefault`, `TestUnmarshalerInputVerbatim` | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | `DecodePrefix`, `DecodeRaw`, root `Cursor` with `Raw`/`DecodeRaw`/`Bytes` | Pending | API rows pass |
| 2 | Cursor-driven `Unmarshal` with raw pass-through for `RawMessage`/`RawTag`, and for `Unmarshaler` under `WithVerbatimUnmarshalerInput()` | Pending | Reflection rows pass, perf rows pass |
| 3 | Permissive-mode verbatim splice for `Marshaler` output | Pending | `TestMarshalerVerbatimPermissive` |

Phase 1 alone unblocks 027 (COSE protected headers).

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| Tests named above | API and reflection behavior | `raw_test.go`, `decoder_test.go`, `rfc8949/cursor_test.go` |
| `FuzzRawSpanRoundTrip` (new §7.1 target) | for arbitrary well-formed input, `DecodeRaw(src).raw == src`; every `Cursor.Raw()` span concatenated at one level equals the container body | `fuzz_test.go` |
| `FuzzDecodePrefixMatchesSequence` (new) | iterating `DecodePrefix` over random bytes yields the same items as `DecodeSequence` | `fuzz_test.go` |
| `FuzzUnmarshalRawMessage` (new) | struct with `RawMessage` field: decode then `Marshal` reproduces the input in Permissive mode | `fuzz_test.go` |

---

## Performance

| Metric | Target | Test mechanism |
|---|---|---|
| `Decoder.Decode` throughput | unchanged (no span tracking on this path) | `BenchmarkDecode*` |
| `DecodePrefix` | ≤ Decode + 2 ns | `BenchmarkDecodePrefix` |
| `Cursor.Raw`/`Bytes` | 0 allocs | `-benchmem` |
| Cursor-driven `Unmarshal` | within 10% of the current Value-then-reflect path | `BenchmarkUnmarshal*` |

Span tracking is implicit. `rfc8949.decodeValue` already returns
`next`, so a span is `src[off:next]`. Nothing is stored per `Value`,
and the 104-byte `Value` (proposal 020) doesn't grow.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Cursor-driven Unmarshal is a large rewrite of `reflect_decode.go` | med | med | Phase 2 keeps `valueToGo` for leaves; the cursor only drives the structure. Run differential fuzzing against the old path for one release |
| Callers depend on RawMessage canonicalization | low | low | Release note; to canonicalize, call `New(ModeCoreDeterministic).Encode` on the decoded Value |
| `raw` slices outlive `src` (use-after-free with pooled buffers) | med | med | Godoc on every method returning `raw`; `RawMessage` copies |

---

## Alternatives considered

- **Store the byte span in `Value` (`Value.Raw []byte`).** Rejected:
  it adds 24 bytes to every `Value`, reversing proposal 020's
  recovery. It also makes equality and `Clone` semantics ambiguous for
  constructed values.
- **Add a public `KindRaw` to `Value`.** It would allow
  `Value`-level splicing of pre-encoded bytes, which is useful. But it
  violates §4.1's "every Kind is a CBOR data model type" and lets
  invalid CBOR into deterministic encoders. Reconsider only together
  with an encoder-side validity check.
- **Fix COSE alone by keeping the original bstr in `cose.Headers`.**
  This is necessary but not sufficient: `RawMessage`, `RawTag`,
  `Unmarshaler`, mDL and WebAuthn all need the same primitive. 027
  does keep the bstr, using this proposal's `Cursor.Bytes()`.

---

## Open questions

1. Should `UnmarshalValue(v Value, target any) error` be exported for
   callers who already hold a `Value`? It would document the
   canonicalizing behavior for `Unmarshaler` targets.
2. Should `DecodePrefix` on a `Stream` (`stream.go:235`) expose raw
   spans too? It needs a buffered-reader span API, so it's deferred.

---

## Cross-references

- Spec: §3.1, §4.1, §6.2, §7.1, §9
- Proposals: [014](014-raw-message-and-tag-wrapping.md) (amended), [018](018-opt-in-performance-extensions.md) (Cursor, zero-copy), [020](020-default-decode-recovery.md), [021](021-core-codec-safety-fixes.md), [023](023-strict-decode-policy-and-errors.md) (`ErrTypeMismatch`), [027](027-cose-verification-hardening.md) (protected headers), 033 (EDHOC sequences)
- RFCs: RFC 9052 §3 (`empty_or_serialized_map`), §4.4, §5.3; RFC 8949 §3.4.5.1 (tag 24 encoded CBOR); RFC 8742 §2
- WebAuthn L3 §6.1 (authenticator data layout): https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft from the 2026-11-20 codebase review | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
| 2026-11-20 | API stability (signature + semantics) per revised 034 | corecbor maintainers |
