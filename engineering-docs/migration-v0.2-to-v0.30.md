# Migrating from corecbor v0.2.x to v0.30

**Status: draft.** Covers what is on `main` as of proposals 021, 022,
023, 024 and 027. Sections are added as the remaining proposals
(025–026, 028–033) land. See `release-notes-v0.30-maintainers.md` for
the release checklist.

## Summary

v0.30 keeps the exported API stable in signature *and* documented
behavior (proposal 034): no exported identifier is removed, renamed or
retyped, and `make apicheck` enforces that against v0.2.2. What changes
is that implementations which contradicted their own documentation, or
the RFC they claim to implement, are fixed, and new standards-current
behavior is available under new identifiers.

**If you use the default encoder modes on text, byte strings,
integers, booleans, null, arrays and maps with distinct keys, your
encoded bytes do not change.** This is checked by golden vectors
recorded from v0.2.2 (including a variant-tag storage corpus that
fails `make check` on any byte change) and by
`tools/consumer-check/run.sh` against downstream modules.

The changes below affect edge cases. Each lists what to do if you
depended on the old behavior; most have a deprecated `Legacy…`
selector that restores it, removed no earlier than v0.32.0.

## Upgrading

```sh
go get github.com/jahkeup/corecbor@<commit-or-tag>
go test -race ./...
```

If you persist, sign, hash or MAC encoded bytes, also compare your
encoder output across the upgrade. `tools/consumer-check/run.sh` does
this for a module checkout: it runs a probe test you supply under
v0.2.2 and under the new version and diffs the output.

## Encoding changes (output bytes)

| Change | Affects | Old behavior | Restore with |
|---|---|---|---|
| Embedded structs are flattened per `encoding/json` rules (021 D4), including exported fields of unexported embedded structs and embedded pointers | `Marshal` of structs with embedded structs | each inner field name mapped to the whole embedded struct | none (old output was not decodable by other implementations) |
| A tag that only sets options (`cbor:",omitempty"`) keeps the default field name (021 D4) | `Marshal`/`Unmarshal` | key `""` | none |
| `TimeTo` before 1970 encodes a negative integer (021 D5) | `TimeTo`, `Marshal` of `time.Time` via `TimeTo` | huge positive integer | none |
| `Simple(24)`…`Simple(31)` return `ErrReservedSimple` (021 D14) | `Encode`, `StreamEncoder` | ill-formed `f818`…`f81f` | none |
| Duplicate map keys return `ErrDuplicateMapKey` in deterministic modes (021 D15) | Core Deterministic, Canonical, CTAP2 | duplicates emitted | none (not valid CBOR, RFC 8949 §5.6) |
| Bignums use preferred serialization in deterministic modes: leading zeros stripped; values that fit major type 0/1 encode as integers (024) | tag 2/3 values, `BigIntTo`, `Marshal` of `big.Int` in deterministic modes | bytes as supplied | `WithLegacyBignumPassthrough()` (encoder `Option`) |
| CTAP2 mode writes every NaN as `fb7ff8000000000000` (024) | `ModeCTAP2` | payload and sign preserved | none |
| Permissive mode writes `RawMessage`/`RawTag` bytes verbatim (022) | `ModePermissive` `Marshal` | decoded and re-encoded | none; deterministic modes still canonicalize |
| `StreamEncoder.WriteValue` applies the mode's float rules and UTF-8 validation (021 D18) | stream encoding | input width; no UTF-8 check | none |
| `StreamEncoder` counts nested containers and rejects out-of-order map keys in deterministic modes (021 D6) | stream encoding | malformed or unsorted output | pre-sort keys, or build a `Value` and use `EncodeTo` |

## Decoding changes

| Change | Affects | Old behavior | Restore with |
|---|---|---|---|
| `StrictDecoder()` accepts tags (spec §3.2) (023) | `StrictDecoder` | rejected every tag except 55799 | `StrictDecoder(RejectUnknownTags(), WithAllowedTags())` |
| `RejectUnknownTags()` allows the spec §4.3 tags (`TagsModeled`); `WithAllowedTags(ids...)` adds more (023) | tag rejection | allowed only 55799 | `WithAllowedTags()` with no IDs |
| Map key identity is the same at every map size: keys compare in the data model (RFC 8949 §5.6.1 + erratum 8589), so `01` and `1800` are the same key, NaNs compare by payload and sign, ±0 are equal, and 1.0 at different float widths is one key (024) | duplicate handling, `RejectDuplicateMapKeys` | data-model compare up to 16 entries, encoded-byte compare above; float keys compared by kind and `==` | `WithLegacyFloatKeyEquality()` for the float rules; for byte identity use the new `WithMapKeyIdentity(KeyIdentityEncoded)` |
| A stray break byte returns `ErrUnexpectedBreak`; AI 31 on integer/tag heads returns `ErrReservedAI` (021 D16) | `Decode`, `Cursor` | `ErrTruncated`; AI 31 read as 0 | none |
| Every `Unmarshaler` (including `RawMessage`, `RawTag`) receives its item's original bytes (022) | custom `UnmarshalCBOR` | Core Deterministic re-encoding | none; canonicalize inside your `UnmarshalCBOR` if you need it |
| `DecodeFrom` reads exactly one item, in linear time (021 D10) | `DecodeFrom`, `Stream` | quadratic; discarded bytes after the item | none |
| `cbor.Value` fields filled by `Unmarshal` no longer alias the decoder's arena (021 D2) | `Unmarshal` into `cbor.Value`/`any` | overwritten by the next decode | none |
| Non-text map keys decode into `map[any]any` as `cbor.ByteKey` / `cbor.EncodedKey` (021 D3) | `Unmarshal` into `any`/`map[any]any` with byte-string, array, map or tag keys | panicked | none |
| Negative integers below `math.MinInt64` decode into `any` as `*big.Int` (021 D7) | `Unmarshal` into `any` | wrong value | none |
| `AsTime` returns `ErrTimeRange` for out-of-range or non-finite epochs (021 D5) | `AsTime` | wrapped or garbage times | none |
| `Unmarshal` into `big.Int` accepts plain integers (024) | `Unmarshal` | type mismatch | n/a (newly accepted input) |

## Text that is not valid UTF-8 (035)

- **Fixed:** the default encoder now rejects invalid UTF-8 at every
  position. v0.2 checked only top-level text and sorted multi-entry
  maps; text inside arrays and in unsorted or single-entry maps was
  written unchecked. If you relied on that, use `AllowInvalidUTF8()`
  (unchanged output) or pick a policy below.
- **New, opt-in:** `WithInvalidUTF8(p)` on the encoder and
  `WithInvalidUTF8Decoding(p)` on the decoder, with
  `InvalidUTF8Reject`, `InvalidUTF8Allow`, `InvalidUTF8Replace` (one
  U+FFFD per invalid byte, as `encoding/json` does) and
  `InvalidUTF8Lossless` (conformant and exact: tag 273 for WTF-8,
  otherwise a byte string). Per value: `TextLossless(s)` and
  `AsText(v)`. Valid UTF-8 encodes identically under every policy.
- If you persist encoded text, choose a policy deliberately and treat it
  as part of your format: Replace and Lossless write different bytes
  than Allow for the same invalid input.
- `rfc8949.DecodeTextArray` now honors `RejectInvalidUTF8`.

## Errors

- Decoder errors are `*DecodeError` (`errors.As`), with an `Offset` and,
  under `WithErrorPath()`, a location path such as `$[1].k` (023).
  Reflection errors are `*UnmarshalTypeError` (`CBORKind`, `GoType`,
  `Field`). Messages are unchanged, and every existing sentinel still
  matches with `errors.Is`.
- Reflection type errors now wrap `ErrTypeMismatch` (023).
- New sentinels: `ErrTimeRange`, `ErrNotDeterministic`,
  `ErrReservedSimple`, `ErrUnexpectedBreak`, `ErrInvalidKind`,
  `ErrInvalidOption`, `ErrNotPreferred`, and for streams
  `ErrContainerOverflow`, `ErrContainerUnderflow`, `ErrNoOpenContainer`,
  `ErrStreamMapOrder`.

## Diagnostic notation

`Diagnostic()` renders from the source bytes (021 D11–D13, D19): every
encoded map entry is shown (duplicate keys appear twice), −2^64 prints
correctly, and invalid UTF-8 text prints as `/ text, invalid UTF-8 /
h'..'`. `DiagIndicators()` now shows RFC 8949 §8.1 encoding indicators.
`DiagnosticValue(v)` still renders the decoded `Value`.

## Concurrency

Package-level `Marshal` and `Unmarshal` are safe for concurrent use
(021 D1). `New(...)` encoders and decoders with the internal arena
remain single-goroutine; use `NewShared(...)` or one decoder per
goroutine (for example from a `sync.Pool`).

## New API (additive)

- Raw bytes: `Decoder.DecodePrefix`, `Decoder.DecodeRaw`,
  `Decoder.Cursor` and `Cursor.Raw`/`DecodeRaw`/`Bytes` (022).
- Tag policy: `WithAllowedTags`, `rfc8949.TagSet`, `TagsModeled`,
  `TagsWellKnown` (023).
- Key identity and duplicates: `WithMapKeyIdentity`,
  `KeyIdentityValue`, `KeyIdentityEncoded`, `KeepDuplicateMapKeys`
  (024).
- Checking decoders: `RequireDeterministic`, `DeterministicDecoder`
  (024). Experimental (draft-ietf-cbor-serialization-13):
  `ModePreferredPlus`, `RequirePreferredPlus`.
- Bignums: `BigIntToPreferred`, `AsBigIntAny` (024).
- Map keys in `any`: `cbor.ByteKey`, `cbor.EncodedKey` (021).

## cose

| Change | Old behavior | Restore with |
|---|---|---|
| Signatures, MACs and AEAD tags are verified over the protected header bytes as received (027 H1) | re-encoded, so foreign key order failed | none |
| `VerifyMulti` returns `ErrVerification` unless its policy is met; optional `RequireAll` (027 H6) | nil error with zero verified signatures | none |
| A nil payload means detached: `Verify`, `VerifyMulti`, `VerifyMAC0`, `VerifyMACMulti` return `ErrMissingPayload`; use `VerifyDetached` (027 H11). `Sign(nil)` produces a detached message; `Sign([]byte{})` an attached empty one | nil verified as empty | none (see `ExampleVerifier_VerifyDetached`) |
| Header `alg` must match the key; an unprotected-only `alg` is accepted only when it does; `alg` in both buckets is rejected (027 H2) | `alg` ignored | `WithLegacyAlgorithmFromKey()` |
| `crit` is processed (027 H3) | ignored | `WithLegacyIgnoreCritical()` (also `WithLegacyMACHeaders()`, `WithLegacyEncryptHeaders()` for MAC/encrypt paths) |
| Duplicate header labels are rejected, including the same label in both buckets (027 H4) | last wins | `DecodeLimits.AllowDuplicateLabels` (deprecated) via `Unmarshal*With` |
| Multi-recipient MAC/decrypt require a protected, allow-listed `alg` (027 H2/H7) | header `alg` trusted, including HMAC 256/64 | `WithMACAlgorithms(...)` to allow more; legacy selectors above |
| Empty HMAC keys are rejected; PBES2 iteration count capped at 1,000,000 by default (`PBES2Key.MaxCount`) (027) | accepted / unbounded | `MaxCount: -1` disables the cap |
| `Headers.Set(1, AlgES256)` encodes the value (−7), not null; `SetChecked` returns errors; `Set` is deprecated (027 H9) | typed values became null | n/a |

Functions with appended optional parameters (existing calls compile
unchanged): `VerifyMulti(..., ...VerifyPolicy)`,
`VerifyMACMulti(..., ...MACOption)`, `DecryptMulti(..., ...EncryptOption)`.

## cwt

- `Validator.Validate` returns `ErrInvalidValidator` for a negative
  `Leeway` (021 D17); it used to tighten the validity window silently.

## edhoc (033)

The package implements RFC 9528 by default and reproduces the RFC 9529
traces byte-for-byte. v0.2 implemented a pre-RFC draft, so **a v0.30
peer does not interoperate with a v0.2 peer** unless one side passes
`WithLegacyPreRFCProtocol()`.

- **Wire and key schedule:** message_2 is one byte string with C_R
  inside PLAINTEXT_2; transcript hashes, PRKs and MACs follow RFC 9528
  and bind the credentials (CRED_x) and EAD; P-256 keys are sent as the
  x-coordinate.
- **OSCORE:** `ExportOSCORE` follows Appendix A.1. `SenderID` is now the
  peer's connection identifier and `RecipientID` your own (v0.2 had them
  swapped); `Export` is EDHOC_Exporter.
- **SUITES_I:** `InitiatorConfig.Suites` lists preferences with the
  selected suite **last** (v0.2 selected the first). Single-suite
  configurations are unaffected. After an error message with ERR_CODE 2,
  build the next value with `RetrySuites`.
- **Errors:** a Responder that can't continue returns an `*ErrorMessage`
  (send `MarshalCBOR()` to the peer); an Initiator that receives one
  returns it. Both match `ErrPeerError`, and still `ErrUnsupportedSuite`
  where v0.2 returned it.
- **Credentials:** v0.2-style configs (signer + `PeerPublic`) keep
  working: each side sends a CWT Claims Set holding its key by value,
  and the peer checks it against `PeerPublic`. New: `Credential.Raw`,
  `IDCred` and `PublicKey`; `Peers` (a `CredentialResolver`); methods 1–3
  with `DHKey`; suites 1, 3–6 and 24; EAD items; `PRKOut`, `KeyUpdate`,
  `OSCORE`, `Close`.
- **State:** any error is terminal for the session and zeroizes its
  secrets.

`NewInitiator(cfg, ...Option)` and `NewResponder(cfg, ...Option)` gain
optional parameters; existing calls compile unchanged.

## Deprecated legacy selectors

All are `// Deprecated:` on arrival and removed no earlier than v0.32.0.
Selectors that weaken verification are never included in a
`CompatV02*` bundle.

| Selector | Package | Restores |
|---|---|---|
| `CompatV02()` | root (encoder) | `WithLegacyBignumPassthrough()` |
| `CompatV02Decoding()` | root (decoder) | `WithLegacyFloatKeyEquality()` |
| `WithLegacyBignumPassthrough()` | root | bignums as supplied in deterministic modes |
| `WithLegacyFloatKeyEquality()` | root | v0.2 float key comparison |
| `WithLegacyAlgorithmFromKey()` | cose | ignore header `alg` |
| `WithLegacyIgnoreCritical()` | cose | ignore `crit` |
| `WithLegacyMACHeaders()` | cose | v0.2 MAC header handling |
| `WithLegacyEncryptHeaders()` | cose | v0.2 encrypt header handling |
| `WithLegacyPreRFCProtocol()` | edhoc | the v0.2 pre-RFC protocol (talks only to v0.2 peers; never bundled) |
