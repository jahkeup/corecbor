# Migrating from corecbor v0.2.x to v0.30

Covers proposals 020–035, the v0.30 release line. Deferred follow-ups
are tracked in proposal 036 and are not part of v0.30. See
`release-notes-v0.30-maintainers.md` for the release checklist.

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
| A tag `Value` returned by `Decoder.Decode` is valid until the next `Decode` on the same `Decoder`, like arrays and maps: its content is arena-backed (036 item 22) | keeping a tag from `Decode` across another `Decode` on the same `Decoder` | a tag around a scalar survived the next `Decode` | `v.Clone()`, a separate `Decoder`, or `WithoutInternalArena()` |
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

## Value accessors and reflection (025)

- **New on `cbor.Value`:** `Get`, `GetInt`, `GetText` (map lookup),
  `Int64`/`Uint64` (checked: `ErrOverflow`, `ErrTypeMismatch`), `Equal`
  (RFC 8949 data model + erratum 8589, the decoder's default key
  identity) and `String` (compact diagnostic notation). `Kind` has a
  `String` method, so `%v`/`%s` print names such as `map`; use `%d` if
  you need the number. `ErrOverflow` now lives in `cbor`;
  `corecbor.ErrOverflow` is the same value.
- **Fixed:** `Unmarshal` calls `encoding.TextUnmarshaler` for text
  strings and `encoding.BinaryUnmarshaler` for byte strings, matching
  what `Marshal` already did for the `*Marshaler` side (so `netip.Addr`
  and similar types round-trip). A `string`- or `[]byte`-kinded type
  that implements one of them now gets the method called instead of the
  raw value; `WithLegacyNoTextBinaryUnmarshal()` (deprecated, included
  in `CompatV02Decoding()`) restores v0.2.
- **New, opt-in:** struct-level ``_ struct{} `cbor:",toarray"` `` (array
  encoding in field order; trailing pointer fields optional on decode;
  `ErrArrayLength`), `DisallowUnknownFields()` (`ErrUnknownField`), the
  `omitzero` field option, `WithGoFieldNames()` (encoder: untagged
  fields keyed by the Go name as-is) and
  `WithCaseInsensitiveFieldNames()` (decoder). The default untagged key
  is still the lowercased field name.

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
- Tag helpers for published tag RFCs (026), all returning errors that
  wrap `ErrMalformedTag` or `ErrNonCanonicalTag`:
  - tag 24: `WrapEncodedCBOR`, `Encoder.EncodeEncodedCBOR`,
    `Decoder.DecodeEncodedCBOR` (returns the embedded bytes as
    received);
  - UUID (37): `UUIDTo`, `AsUUID`;
  - dates (100/1004, RFC 8943): `DateTo`, `DaysTo`, `AsDate`;
  - extended time and duration (1001/1002, RFC 9581):
    `ExtendedTimeTo`, `AsExtendedTime`, `DurationTo`, `AsDuration`;
  - IP addresses and prefixes (52/54, RFC 9164): `IPTo`, `PrefixTo`,
    `InterfaceTo`, `AsIP`, `AsPrefix`;
  - OIDs (110/111/112, RFC 9090): `OIDTo` (uses tag 112 under
    1.3.6.1.4.1), `RelativeOIDTo`, `AsOID`, `AsRelativeOID`;
  - stored CBOR (RFC 9277): `TagWrappedTo`, `SequenceLabelTo`,
    `AsSequenceLabel`, `ContentFormatTag`, `AsContentFormat`.
- Tag constants with stable hand-picked names (026): `TagCOSE*`,
  `TagCWT`, `TagUCCS`, `TagDetachedEATBundle`, `TagUUID`, `TagIPv4`,
  `TagIPv6`, `TagDays`, `TagFullDate`, `TagOID`, `TagRelativeOID`,
  `TagEnterpriseOID`, `TagExtendedTime`, `TagDuration`, `TagPeriod`,
  `TagCBORSequenceFile`, `TagCBORLabeledData`.
- `registry`: refreshed from IANA (2026-11-13). Every generated
  constant from v0.2.2 keeps its name and value
  (`registry/names_frozen.txt`); new tags get new constants.

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
| `SignMulti` honors its `opts` for body headers and external AAD (028) | accepted and ignored | none (calls without opts are unchanged) |
| Ed25519 signing works with any `crypto.Signer` (KMS/HSM), not only `ed25519.PrivateKey` (028) | `ErrInvalidKey` | n/a (newly accepted) |
| `NewVerifier` accepts `*rsa.PublicKey` (≥ 2048 bits): PS256/384/512 by default, RS256/384/512 only via `WithAllowedAlgorithms`; the `alg` must be protected (028) | unsupported key type | n/a (newly accepted) |
| `(*Key).PublicKey` rejects EC2 coordinates longer than the curve size (028) | silently truncated into a different point | none (short coordinates are still left-padded) |
| `*cose.Key` implements `corecbor.Marshaler`/`Unmarshaler`, so `Marshal` of a struct holding a `Key` writes the COSE_Key (028) | an empty map (only unexported fields) | n/a |
| A signed message's `Protected.Raw()` returns the bytes the signature covers (028) | nil until decoded | n/a |

New in 028 (additive): `WithProtectedHeaders`, `WithUnprotectedHeaders`,
`Signer.Sign1`/`Sign1Context`, `SignContext`, `SignDetached`,
`SignMultiDetached`, `VerifyMultiDetached`, `ContextSigner`; typed
header accessors (content type, typ, CWT Claims, x5bag/x5chain/x5t/x5u,
IV, Partial IV, kid context, kcwt, kccs, 3161-ttc/ctt), `CertHash`,
`Lookup`; COSE_Key `ParseKey`, `ParseKeyPrefix`, `MarshalCBOR`,
accessors, `Thumbprint` (RFC 9679), `Public`, `KeyDeriver`, `KeySet`,
`ParseKeySet`, `NewSignerFromKey`/`NewVerifierFromKey` (enforce
`key_ops`), `KeyFromJWK`/`JWK`; `KeyResolver`, `KeySetResolver`,
`VerifySign1`/`VerifySign1Detached`; RSA, AKP key types; X448/Ed448
curves (parse only). `ParseKey` rejects short EC2 coordinates unless
`AllowShortCoordinates()`.

Functions with appended optional parameters (existing calls compile
unchanged): `VerifyMulti(..., ...VerifyPolicy)`,
`VerifyMACMulti(..., ...MACOption)`, `DecryptMulti(..., ...EncryptOption)`.

### Algorithms and encryption (029)

| Change | Old behavior | Restore with |
|---|---|---|
| `ECDHESKey` follows RFC 9053 §6.3: `-25`/`-26` are direct key agreement (the derived key is the content key, so the recipient must be the only one), `-29`/`-30`/`-31` (`Alg: AlgECDH_ES_A128KW`, …) wrap the content key with AES-KW; the ephemeral key is a COSE_Key map; the KDF context is `COSE_KDF_Context` | `-25` labelled an AES-KW wrap with a raw-point ephemeral key and a private KDF context; no other implementation could read it | `WithLegacyECDHES()` (or `CompatV02Encryption()`) to read and write v0.2 messages; to mix ECDH with other recipients, set `Alg: cose.AlgECDH_ES_A128KW` |
| `PBES2Key` uses private-use identifiers: alg `AlgPrivatePBES2_HS256_A128KW` (−65601), iteration count in label −65602. `PBES2Key.Algorithm()` returns the new value; `AlgPBES2_HS256_A128KW` is still −11 | −11 and −21, which IANA registers for direct+HKDF-SHA-512 and PartyU identity | `WithLegacyPBES2Labels()` (encrypt), `WithLegacyMACPBES2Labels()` (MAC); without them a −11 recipient is `ErrUnsupportedAlgorithm` |
| `NewSigner` accepts RSA keys and signs PS256 (a protected `alg` or COSE_Key `alg` selects PS384/512 or RS256/384/512) | `ErrInvalidKey` | n/a (newly accepted) |
| v0.2 ECDH-ES `COSE_Mac` recipients | discarded the MAC key; never verified | none (nothing to restore) |

`NewSigner` with no options still emits ES256 (−7), ES384, ES512 and
EdDSA (−8), and verifiers accept both those and the fully-specified
RFC 9864 identifiers. Those polymorphic constants (`AlgES256`,
`AlgES384`, `AlgES512`, `AlgEdDSA`) are marked deprecated, as IANA
marks them, but keep their values; `WithFullySpecifiedAlgorithms()`
emits ESP256 (−9), ESP384, ESP512 or Ed25519 (−19) instead. A verifier
binds whichever identifier the message names, and
`WithAllowedAlgorithms` matches identifiers exactly, so allow both forms
during a migration.

New in 029 (additive): `AlgESP256`, `AlgESP384`, `AlgESP512`,
`AlgEd25519`, `AlgEd448` (constant only), `AlgESB256`–`AlgESB512`
(constants only), `AlgMLDSA44`/`65`/`87` (RFC 9964, AKP keys with
32-byte seeds; needs Go 1.27, otherwise `ErrUnsupportedAlgorithm`), the
AES-CCM content algorithms (10–13, 30–33), `AlgChaCha20Poly1305`
(constant only), `AlgECDH_ES_HKDF_512`, `AlgECDH_ES_A128KW`/`192`/`256`,
`AlgPrivatePBES2_HS256_A128KW`; `Algorithm.Deprecated`, `FullySpecified`,
`WithFullySpecifiedAlgorithms`; `ECDHESKey.Alg`, `ECDHESKey.KDF`
(`ECDHKDFContext`, `PartyInfo`), `KeyAgreer`; `Encrypt0Seal` and
`Encrypt0Open` (random IV carried in header 5, or `WithPartialIV`; AES-GCM
and, via `WithEncryptAlgorithms`, AES-CCM), `WithNonce`.

Deprecated in 029 (behavior unchanged for the v0.x line):
`EncryptEncrypt0`/`DecryptEncrypt0` (use `Encrypt0Seal`/`Encrypt0Open`,
which carry the IV in the message) and `HPKEKey` (corecbor's pre-draft
HPKE format; use `HPKERecipient`).

Experimental in 029 (draft-ietf-cose-hpke-27, behind `WithDraftHPKE27()`;
code points are the draft's assumed values and will change when IANA
assigns them): `HPKESeal`/`HPKEOpen` (integrated encryption,
`WithHPKEInfo`), `HPKERecipient` (key encryption for
`EncryptMulti`/`DecryptMulti`), `HPKESuite` (`HPKE0`…`HPKE7`). mode_psk
and the X448 suites return `ErrUnsupportedAlgorithm`.

### Hash envelopes, receipts and SCITT (030)

All additive; nothing existing changes.

- Hash envelopes (RFC 9995), in `cose`:
  - header labels `HeaderPayloadHashAlg` (258),
    `HeaderPreimageContentType` (259) and `HeaderPayloadLocation` (260);
  - the `HashEnvelope` type and `HashEnvelopeFrom`;
  - `Signer.SignHashEnvelope`, `SignHashEnvelopeDigest` and
    `SignHashEnvelopeMessage`;
  - `Verifier.VerifyHashEnvelope` and `VerifySign1HashEnvelope`.

  Envelopes reject content type (label 3) and accept 258–260 only in the
  protected bucket.
- New package `cose/receipt` (RFC 9942 receipts over RFC 9162 Merkle
  trees):
  - `Parse`;
  - `Receipt.VerifyInclusion`, `VerifyInclusionHash` and
    `VerifyConsistencyFrom`;
  - `VerifyConsistency`;
  - `Attach` and `Receipts`, which manage label 394;
  - experimental `Issue`, `IssueConsistency` and `Tree`, for log
    operators and tests.
- New module `github.com/jahkeup/corecbor/scitt` (RFC 9943 signed and
  transparent statements):
  - `Issue`, `ParseStatement`, `Entry`, `ReceiptHeaders`, `Verify` and
    `VerifyTransparent`;
  - sentinels `ErrInvalidStatement` (wraps `cose.ErrMalformed`) and
    `ErrInsufficientReceipts` (wraps `cose.ErrVerification`).

## cwt

- Integer claim handling uses corecbor's checked `Value.Int64` /
  `Uint64` accessors (036 item 3). Behavior is unchanged from the
  031 rules: integers beyond int64 never wrap onto other claim keys,
  private-claim values or times.
- `Validator.Validate` returns `ErrInvalidValidator` for a negative
  `Leeway` (021 D17); it used to tighten the validity window silently.

Existing identifiers keep their meaning (034). Changes to them (031):

| Change | Old behavior | Restore with |
|---|---|---|
| A token is rejected **on or after** `exp` (RFC 8392 §3.1.4) by every `Validator` | `now == exp` accepted | none (`Leeway` covers clock skew) |
| `nil.Validate(c)` returns `ErrInvalidValidator` | panicked | none |
| `DecodeClaimsSet` never panics; claims keyed by a byte string, array, map or an integer outside int64 go to the new `PrivateClaims` only | panicked; an out-of-range negint key decoded as `iss` | none |
| Duplicate claim keys are rejected (RFC 8392 §7.2); decode memory is bounded (8 MiB) | last one won | `DecodeClaimsSetWith(data, DecodeOptions{AllowDuplicateClaims: true})` (deprecated) |
| NumericDates beyond int64, NaN or ±Inf are rejected | wrapped to unrelated times (`nbf` failed open) | none |
| `Verify`, `VerifyMAC`, `Decrypt` accept an outer CWT tag 61 | rejected | n/a |
| `aud` may be an array (RFC 9200); it decodes into `Audiences` (`Audience` stays the single-string form) | rejected | n/a |
| `cnf`: one method per claim (RFC 8747 §3.1); OKP keys need `crv` (X25519 is no longer read as Ed25519); oversize EC2 coordinates rejected; symmetric keys and COSE_Encrypt0/COSE_Encrypt in member 2 accepted | several methods kept; OKP assumed Ed25519; oversize truncated | none |
| `Encode` rejects a claim set twice with different values (e.g. `Issuer` and `Private[int64(1)]`) | emitted duplicate keys | n/a |

New, recommended:

- `cwt.NewValidator()` — exp required, future `iat` rejected, 60 s
  leeway; plus `Issuers`, `MaxAge`, `RequireIssuedAt`,
  `RejectFutureIssuedAt` on `Validator`.
- `VerifyToken(ctx, data, VerifyOptions{Keys: …})`, `VerifyMACToken`,
  `OpenToken`: verify, decode strictly and validate in one call;
  `typ`/`cty` checks; nested CWTs. `VerifyMACToken`/`OpenToken` accept
  only full-length HMACs / AES-GCM unless `AllowedAlgorithms` lists
  more (HMAC 256/64 must be listed explicitly).
- `Seal` (IV written to the IV header) replaces the deprecated
  `Encrypt`/`Decrypt`, whose caller-supplied nonce isn't transmitted.
- `ClaimKey`, `PrivateClaims` (prefer over `Private`), `NumericDate`,
  `Scope`/`ACEProfile`/`CNonce`/`Exi` (RFC 9200), `ClaimsFromHeaders` /
  `SetClaimsHeader` (RFC 9597, label 15), `DecodeUCCS` (RFC 9781),
  `Confirmation.EncryptedKey` (deprecates `Encrypted`) and `Match`.

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
- **X.509 credentials:** set `Peers: edhoc.X509Resolver(policy)` to
  accept x5chain (by value) and x5t (by reference, via
  `X509Policy.Certificates`) verified against `X509Policy.Roots` (required;
  system roots are never used implicitly). Build your own with
  `X509Credential(chain, byReference)`. CRED_x is the DER leaf as a CBOR
  byte string. `edhoc.X5T` is now `cose.CertHash`.
- **CoAP transport (RFC 9528 Appendix A.2, RFC 9668):** `CoAPMessage1`,
  `CoAPMessageWithCID` and `SplitCoAPPrefix` frame and dispatch requests;
  `CombinedPayload` / `SplitCombinedPayload` handle the EDHOC + OSCORE
  request (C_R is the OSCORE 'kid'); `ConnectionID` / `PeerConnectionID`
  on both endpoints. Constants for the well-known path, media types,
  Content-Formats 64/65 and the EDHOC option 21.
- **New sentinels:** `ErrCredentialRejected` (resolver errors),
  `ErrConnectionIDCollision` (C_I == C_R), `ErrCriticalEAD`. Each also
  matches the sentinel returned before (`ErrAuthentication`,
  `ErrMessageFormat` or `ErrStateViolation`).

`NewInitiator(cfg, ...Option)` and `NewResponder(cfg, ...Option)` gain
optional parameters; existing calls compile unchanged.

## eat (032)

Integer claim handling (claim keys, oemid PEN, detached-digest
algorithm, PSA integers) uses corecbor's checked `Value.Int64` /
`Uint64` accessors (036 item 3); behavior is unchanged from 032.

The package now uses the IANA CWT claim keys (RFC 9711). v0.2 used
draft-era keys for four claims, so **v0.2-issued tokens carrying
uptime, sw-components or submods decode differently** unless you pass
`eat.WithLegacyDraftClaimKeys()` (or `eat.CompatV02()`) to
`DecodeClaims`, `Encode`, `Sign` and `Verify`. Under the selector,
`Encode` is byte-identical to v0.2.2. Numbering is never auto-detected.

| Claim | v0.2 key | v0.30 key |
|---|---|---|
| security level (not in RFC 9711) | 261 | none (legacy selector only) |
| uptime | 266 | 261 |
| sw-components → `psa-software-components` (RFC 9783) | 267 | 2399 |
| submods | 268 | 266 |

Existing identifiers keep their meaning (034). Changes to them:

| Change | Old behavior | Restore with |
|---|---|---|
| Claim keys per the table above | draft keys | `WithLegacyDraftClaimKeys()` (deprecated) |
| `Encode` of a non-zero `SecurityLevel` returns `ErrClaimNumbering` without the selector | encoded at 261 (now `uptime`) | `WithLegacyDraftClaimKeys()` |
| With `SubmodPolicy` set, a nested-token submod without `SubmodVerify`/`SubmodVerifier` returns `ErrSubmodUnverified` | decoded unverified and passed to the policy as trusted | none; pass a `SubmodVerify` that decodes without verifying to make that choice explicit |
| Submodules are appraised in sorted name order | map order | n/a |
| `cnf`, private and unknown claims are preserved (embedded `cwt.ClaimsSet`, `PrivateClaims`) | dropped | n/a |
| Duplicate claim keys are rejected (via `cwt`, 031) | last one won | none |
| `eat_profile` may be an OID (`ProfileOID`) | bstr form rejected | n/a |
| A negative `SecurityLevel` or `Debug` encodes as a CBOR negative integer | wrapped to a large uint | none |

`DecodeClaims` accepts the same values as before. The RFC 9711 value
rules (nonce 8–64 bytes, UEID form, dbgstat 0–4, profile URI or OID)
are opt-in: `Claims.Validate()`, or `NewAppraiser()`, which also sets
`cwt.NewValidator()`. A zero-value `Appraiser{}` behaves as in v0.2.

New, additive:

- Claims: `SUEIDs`, `HWModel`, `HWVersion`, `Location`, `BootCount`,
  `BootSeed`, `DLOAs`, `SWName`, `SWVersion`, `Manifests`,
  `Measurements`, `MeasRes`, `IntUse`, `DbgStat` (encodes 0 explicitly),
  `OEMIDPEN`, `ProfileOID`; `DebugDisabledFullyAndPermanently`;
  `UEID.Validate()`.
- Submodules: `Submod.JSON` and `Submod.Detached`; `Appraiser.SubmodVerify`,
  `SubmodDetached`, `NonceVerifier`, `MinDebugStatus`,
  `RequireProfileOID`, `MeasurementPolicy`, `AppraiseContext`.
- Detached EAT bundles (tag 602): `DecodeDetachedBundle`.
- RFC 9782 media types and content-formats (`MediaTypeEAT*`,
  `ContentFormatEAT*`).
- `eat/psa`: RFC 9783 PSA claims (`FromEAT`, `ToEAT`, lifecycle
  constants); `psa.SoftwareComponent` is `eat.SWComponent`.
- New sentinels: `ErrSubmodUnverified`, `ErrInvalidUEID`,
  `ErrInvalidNonce`, `ErrDebugStatus`, `ErrUnknownDebugStatus`,
  `ErrInvalidProfile`, `ErrClaimNumbering`.

Deprecated: `Claims.SecurityLevel`, `Appraiser.RequireSecurityLevel`
(the claim isn't in RFC 9711).

`DecodeClaims`, `(*Claims).Encode`, `Sign` and `Verify` gain
`...Option`; existing calls compile unchanged.

## Deprecated legacy selectors

All are `// Deprecated:` on arrival and removed no earlier than v0.32.0.
Selectors that weaken verification are never included in a
`CompatV02*` bundle.

| Selector | Package | Restores |
|---|---|---|
| `CompatV02()` | root (encoder) | `WithLegacyBignumPassthrough()` |
| `CompatV02Decoding()` | root (decoder) | `WithLegacyFloatKeyEquality()`, `WithLegacyNoTextBinaryUnmarshal()` |
| `WithLegacyBignumPassthrough()` | root | bignums as supplied in deterministic modes |
| `WithLegacyFloatKeyEquality()` | root | v0.2 float key comparison |
| `WithLegacyNoTextBinaryUnmarshal()` | root | no Text/BinaryUnmarshaler calls on decode |
| `WithLegacyAlgorithmFromKey()` | cose | ignore header `alg` |
| `WithLegacyIgnoreCritical()` | cose | ignore `crit` |
| `WithLegacyMACHeaders()` | cose | v0.2 MAC header handling |
| `WithLegacyEncryptHeaders()` | cose | v0.2 encrypt header handling |
| `CompatV02Encryption()` | cose | `WithLegacyPBES2Labels()` + `WithLegacyECDHES()` |
| `WithLegacyPBES2Labels()` | cose | PBES2 recipients as −11 / count −21 (encrypt) |
| `WithLegacyMACPBES2Labels()` | cose | the same for `COSE_Mac` recipients |
| `WithLegacyECDHES()` | cose | the v0.2 ECDH-ES encoding (talks only to v0.2 peers) |
| `WithLegacyPreRFCProtocol()` | edhoc | the v0.2 pre-RFC protocol (talks only to v0.2 peers; never bundled) |
| `CompatV02()` | eat | `WithLegacyDraftClaimKeys()` |
| `WithLegacyDraftClaimKeys()` | eat | v0.2 draft claim keys (261/266/267/268), all at once |
