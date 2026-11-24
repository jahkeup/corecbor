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
| `Cursor.EnterArray`/`EnterMap` check the container head as `Decode` does: reserved AI, `RejectIndefiniteLength`, `RejectNonShortest`, `MaxArrayLength`, `MaxNestingDepth`, and a count the input can't hold; the cursor doesn't move on error. `Cursor.Decode` counts the containers the cursor is in toward `MaxNestingDepth`. `Cursor.FindMapKey` returns an error for a text key whose length doesn't fit an `int`; `Cursor.Skip` reports `ErrMaxArrayLength` before `ErrMaxNestingDepth`, as `Decode` does (036 item 25) | `Cursor` | heads unchecked (a count ≥ 2⁶³ read as -1, indefinite); nesting restarted at the cursor; `FindMapKey` panicked; `Skip` reported the depth error first | none (safety defect, 034) |
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
- Errors for data that can't be re-encoded as received (036 item 25):
  `cwt.ErrAmbiguousClaimKey`, `cwt.ErrNonCanonicalNaN`,
  `cose.ErrNonFiniteKeyParam`, `cose.KeyParamError`; and opt-ins that
  keep such data byte for byte instead: `cwt.DecodeOptions.KeepAsReceived`
  with `cwt.ClaimsSet.ReceivedClaims`, `eat.WithKeepAsReceived()`,
  `cose.KeepParamsAsReceived()` with `(*Key).ReceivedParams` and
  `(*Key).DeleteReceivedParam`. Data kept this way is written back
  verbatim, so it is the one exception to Core Deterministic output.
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
| `ParseKey`, `ParseKeyPrefix`, `ParseKeySet` and `(*Key).UnmarshalCBOR` reject a parameter whose value is or contains a NaN or infinite float: `errors.Is(err, ErrNonFiniteKeyParam)` (also `ErrMalformed`), and `*KeyParamError` gives the label (036 item 25) | parsed, then `MarshalCBOR` failed | `KeepParamsAsReceived()` keeps the parameter verbatim (`ReceivedParams`, `DeleteReceivedParam`; labels -12..5 are always checked) (safety defect, 034) |
| `*cose.Key` implements `corecbor.Marshaler`/`Unmarshaler`, so `Marshal` of a struct holding a `Key` writes the COSE_Key (028) | an empty map (only unexported fields) | n/a |
| A signed message's `Protected.Raw()` returns the bytes the signature covers (028) | nil until decoded | n/a |
| A direct recipient (`DirectKey`, any deriver whose `Algorithm()` is `AlgDirect`, `(*Key).KeyDeriver(AlgDirect)`) supplies the content or MAC key and must be the only recipient (`ErrInvalidKey` otherwise); its COSE_recipient has an empty protected bucket, `alg` unprotected and an empty ciphertext (RFC 9052 §8.5.1). `ComputeMACMulti` with a `DirectKey` takes a nil key or that key. `(*Key).KeyDeriver(AlgDirect)` accepts a key whose `alg` is the content algorithm (and binds it), and checks `key_ops` encrypt/decrypt or MAC create/verify, not wrapKey/unwrapKey (037 S1) | a random content key was used and dropped, so nothing decrypted or verified; direct could be mixed with other recipients; a custom `AlgDirect` deriver could carry a ciphertext | none (safety defect, 034); a deriver that wraps a key needs its own algorithm identifier |
| `NewVerifierFromKey` (and so `KeySetResolver`): a COSE_Key's `alg` restricts the Verifier even with `WithAllowedAlgorithms`; the allow-list can narrow it, and one that excludes the key's `alg` is `ErrInvalidKey` (RFC 9052 §7.1) (037 S4) | `WithAllowedAlgorithms` replaced the key's `alg`, so a PS256 key verified RS256 | none (safety defect, 034) |
| `ComputeMAC0`, `VerifyMAC0`, `ComputeMACMulti`, `VerifyMACMulti` reject an HMAC key shorter than the hash output (32 bytes for HMAC 256/64 and 256/256, 48 for 384, 64 for 512) with `ErrInvalidKey` (RFC 9053 §3.1); `WithStrictMACKeyLength()` is now the default and changes nothing. This also applies through `cwt`'s MAC paths (037 S6) | any non-empty key, even 1 byte | `InsecureAllowShortMACKeys()` (cose only) |
| `PBES2Key` seals with 600,000 iterations when `Count` is 0; `WrapKey` requires a non-empty password, `Count` ≥ 1,000 and a `Salt` ≥ 16 bytes (`ErrInvalidKey`); `UnwrapKey` requires a non-empty password, a count ≥ 1,000 and a salt ≥ 8 bytes in the message (`ErrDecryption`) (RFC 7518 §4.8.1, NIST SP 800-132) (037 S7) | default count 10,000; any count ≥ 1, any non-empty salt and an empty password accepted | sealing: none (safety defect, 034); opening old messages: `PBES2Key.InsecureAllowWeakParams` |
| `Unmarshal*` and `Unmarshal*With(…, DecodeLimits{})` decode under `RecommendedDecodeLimits`: a 1 MiB budget, nesting depth 16, at most 32 signatures (`MaxSignatures`) and 64 recipients (`MaxRecipients`); too many is `ErrLimitExceeded` (with `ErrMalformed`). A zero field is its default and a negative one removes it (037 S8) | no budget, depth 256, any number of signatures (so `VerifyMulti` did signatures × verifiers work) and recipients | raise a field (e.g. `DecodeLimits{MemoryBudget: 16 << 20}` for large payloads), or `InsecureUnboundedDecodeLimits` for trusted input |
| AES-KW and PBES2 recipients (`EncryptMulti`, `ComputeMACMulti`) are written with an empty protected bucket and `alg` unprotected (RFC 9052 §8.5.2); `DecryptMulti`/`VerifyMACMulti` reject a direct, AES-KW or PBES2 recipient whose protected bucket isn't empty with `ErrMalformed` (§5.4). PBES2 under `WithLegacyPBES2Labels` keeps the v0.2 layout (037 S2) | `alg` in the protected bucket, accepted either way | reading v0.2 messages: `AllowProtectedRecipientHeaders()` / `AllowMACProtectedRecipientHeaders()` |
| `UnmarshalEncrypt`/`UnmarshalMac` parse a COSE_recipient with nested recipients (four elements, RFC 9052 §5.1) into the new `Recipient.Recipients` field, and `MarshalEncrypt`/`MarshalMac` write it back; nested recipients count toward `MaxRecipients`, and a present but empty nested array is `ErrMalformed`. `DecryptMulti`/`VerifyMACMulti` still open only the top-level recipient given (037 S3) | the whole message failed to parse (`ErrMalformed`) | n/a (newly accepted) |
| `typ` (16) in an unprotected bucket: `NewSigner`/`SignMulti` with `WithUnprotectedHeaders` holding it return `ErrUnsupportedHeader`, and `Unmarshal*` reject it in any layer with `ErrMalformed` (RFC 9596 §2) (037 S5) | emitted and accepted | received messages: `DecodeLimits{AllowUnprotectedTyp: true}` |
| `DecryptMulti`/`VerifyMACMulti` reject a recipient with no `alg` header with `ErrAlgorithmMismatch` (RFC 9052 §8.5: every recipient class carries `alg`). Message layers (`Verify`, `VerifyMAC0`, `Encrypt0Open`) still accept a missing `alg` and use the key's or caller's, which §3.1 permits when the algorithm is supplied externally (037 S9) | processed as the deriver's algorithm | `WithLegacyEncryptHeaders()` / `WithLegacyMACHeaders()` (existing) skip the check |
| An ECDH-ES ephemeral key (header −1) that carries a private key parameter (`d`) is `ErrMalformed` (037 S11) | the private part was ignored | none (the sender exposed the message key) |
| `(*Key).KeyDeriver(A128KW…)` needs `key_ops` wrapKey or unwrapKey, and the deriver wraps only with wrapKey and unwraps only with unwrapKey (RFC 9053 §6.2.1); a direct deriver seals only with encrypt/MAC create and opens only with decrypt/MAC verify (037 S12) | any of wrapKey, unwrapKey, encrypt, decrypt allowed both directions | none (`key_ops` is the key owner's restriction) |
| `VerifyHashEnvelope` and `VerifySign1HashEnvelope` process labels 258–260, so a `crit` listing them is satisfied there (RFC 9052 §3.1, RFC 9995); `Verify` still rejects it (037 S13) | `ErrCriticalHeader` unless the caller declared them with `WithKnownCriticalHeaders` | n/a (newly accepted) |
| `Marshal*` of a decoded message writes an empty protected bucket received as `h'a0'` back as `h'a0'`. Verification and decryption still compute over the zero-length string (RFC 9052 §3, cose-wg sign-pass-01) (037 S14) | rewritten to `h''` | senders that signed, MACed or encrypted over `h'a0'`: `AllowEmptyProtectedAsReceived()`, `AllowMACEmptyProtectedAsReceived()`, `AllowEncryptEmptyProtectedAsReceived()` |
| New `(*Headers).X5ChainLenient()` reads a one-element `x5chain` array, which `X5Chain` rejects (RFC 9360 §2: one certificate is a bstr); the `X5Chain` error now says so (037 S15) | no way to read one | n/a (additive) |
| `KeyFromJWK` rejects duplicate `key_ops` values (`ErrMalformed`) and `use` inconsistent with `key_ops` (`ErrInvalidKey`), and checks `use` when `key_ops` is present (RFC 7517 §4.3); `(*Key).JWK` returns `ErrInvalidKey` for a kid that isn't UTF-8 (RFC 7517 §4.5) (037 S16) | duplicates kept, `use` ignored beside `key_ops`; a non-UTF-8 kid written base64url-encoded, which reads back as a different kid | none (028 API; set a UTF-8 kid before converting) |
| `EncryptMulti`/`DecryptMulti` with `WithDraftHPKE27()` refuse the deprecated `HPKEKey` (`ErrUnsupportedAlgorithm`): it labels its recipients alg 35, which draft-27 assigns to HPKE-0. Without the selector `HPKEKey` works as documented (037 S18) | both meanings of 35 could meet in one call | none (use `HPKERecipient` with the draft) |

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
  - `Attach` and `Receipts`, which manage label 394. `Receipts`
    rejects an empty receipts array and an attached receipt that
    doesn't begin with tag 18 (a self-describe prefix included), per
    RFC 9942 §4.3's `[+ bstr .cbor Receipt]`; `Attach` with no receipts
    writes nothing (037);
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
| `DecodeClaimsSet` rejects a claim key that is a bignum (tag 2/3) with an integer value, e.g. `c24101`, with `ErrAmbiguousClaimKey` inside a `*ClaimError` whose `Key.Raw` is the key as received; claim keys are integers or text (RFC 8392 §7.1), and deterministic encoding writes such a bignum as the integer, so it re-encoded as another claim (bignum 1 as `iss`). Larger bignums are still private claims | kept as a private claim | `DecodeOptions{KeepAsReceived: true}` keeps it verbatim in `ReceivedClaims` (safety defect, 034) |
| `DecodeClaimsSet` rejects a claim whose key or value holds a NaN other than `f97e00` (a payload or the sign bit), with `ErrNonCanonicalNaN` in a `*ClaimError`; `Encode` returns the same for such a value set by a caller (Go's `math.NaN()` has a payload bit) (036 item 25) | decoded; `Encode` rejected every NaN | `DecodeOptions{KeepAsReceived: true}` keeps unmodeled claims verbatim in `ReceivedClaims` |
| `Encode` accepts ±Inf and the quiet NaN `f97e00` in claim values, which it writes exactly (036 item 25) | error, though decoding accepted them | n/a (newly accepted) |
| Every `Validator` (zero value included) rejects a token carrying `aud` unless `Audience` or the new `Audiences` holds one of its audiences (RFC 7519 §4.1.3), with `ErrAudienceMismatch` in a `*ClaimError` for `aud`; `Audiences` accepts several audiences (037 W1) | with `Audience` unset, any `aud` was accepted | none (safety defect, 034); `Validator.IgnoreAudience` for applications that don't use `aud` |
| `RequireConfirmation` needs a `cnf` with an understood proof-of-possession method (COSE_Key, Encrypted_COSE_Key or a non-empty kid; RFC 8747 §3.1); `{8:{}}` or a `cnf` of only unknown members fails with `ErrMissingConfirmation` in a `*ClaimError` for `cnf` (037 W2) | any `cnf` map passed, even empty | none (safety defect, 034) |
| A symmetric `cnf` COSE_Key by value in a CWT that isn't encrypted (RFC 8747 §3.2) is refused with the new `ErrSymmetricKeyNotEncrypted` in a `*ClaimError` for `cnf` by `Sign`, `MAC`, `SetClaimsHeader`, `Verify`, `VerifyMAC`, `VerifyToken` and `VerifyMACToken`; `Seal`/`OpenToken` and `Encrypt`/`Decrypt` still carry it (037 W7) | emitted and accepted in plaintext | none (safety defect, 034): use `Confirmation.EncryptedKey` or `Seal` |
| `Verify`, `VerifyMAC` and `Decrypt` decode the COSE envelope with an 8 MiB memory budget, the claims decoder's (037 W8) | no limit | none (safety defect, 034); `VerifyToken`/`VerifyMACToken`/`OpenToken` use `cose.RecommendedDecodeLimits` |
| An `exp`, `nbf` or `iat` of −62135596800 (0001-01-01T00:00:00Z, the zero `time.Time` that means "absent") is rejected with `ErrMalformedClaims` in a `*ClaimError` (037 W10) | decoded as absent, so that `exp` was never checked | none (safety defect, 034) |
| An outer tag 61 must be followed by a COSE tag (RFC 8392 §7.2 step 2) in every entry point; `61([...])` is `ErrMalformedClaims` (037 W16) | `VerifyToken`, `VerifyMACToken`, `OpenToken`, `Verify`, `VerifyMAC`, `Decrypt` accepted it | none (v0.2.2 rejected tag 61 altogether) |
| `VerifyToken` treats a payload that begins with a CBOR tag as a nested CWT, with or without `cty` (RFC 8392 §7.2 step 6); `VerifyMACToken`/`OpenToken` reject one with `ErrUnexpectedType` (037 W17) | only `cty` marked nesting; a tagged payload failed as malformed claims | n/a |
| New `VerifyOptions.Types` (accepted `typ` values, e.g. `"application/eat+cwt"`, `uint64(263)`) and `RequireType` (explicit typing, RFC 8725 §3.11) (037 W12) | only `application/cwt`/61 accepted; `typ` optional | n/a (additive) |
| A claim key that is not an integer or a text string (byte string, array, map, float, simple value, a tag including bignums beyond int64) is rejected with `ErrMalformedClaims` in a `*ClaimError` whose `Key.Raw` is the key; `Encode` refuses such a key in `Private`/`PrivateClaims` (RFC 8392 §3; 037 W15). Integers beyond int64 stay private claims; `KeepAsReceived` still keeps bignums with an integer value | kept in `PrivateClaims` (031) or panicked (v0.2.2) | none |
| An ill-typed RFC 9200 claim (`scope` not text/bytes, `ace_profile` not an int64, `cnonce` not bytes, `exi` not an unsigned integer) is rejected with `ErrMalformedClaims` in a `*ClaimError` for it (037 W21) | kept as a private claim with the typed field nil, so it was silently not applied | none |
| A token carrying `exi` (RFC 9200 §5.10.3) is checked against the new `Validator.ExiFirstSeen` (expired once first receipt + `exi` has passed: `ErrTokenExpired`); without that hook it is rejected with the new `ErrExiNotTracked`, and without a `cti` as malformed, each in a `*ClaimError` for `exi` (037 W20) | `exi` ignored (a private claim in v0.2.2, decoded only in 031) | none (safety defect, 034); set `ExiFirstSeen`, or `Validator.IgnoreExi` for stateless verifiers (exclusive with `ExiFirstSeen`) |
| `cnf` may carry a kid beside a COSE_Key or Encrypted_COSE_Key (RFC 8747 §3.1 limits only COSE_Key vs Encrypted_COSE_Key); `Confirmation.Match` lets the key decide when one is present (same thumbprint, and the same kid when both carry one) (037 W22) | COSE_Key + kid rejected as two methods (031); `Match` accepted a different key carrying the same kid | n/a |
| `VerifyToken` verifies a tagged COSE_Sign (multi-signer) CWT: keys resolved per signature, one verifying signature suffices unless the new `VerifyOptions.RequireAllSignatures` (037 W18) | `ErrMalformedClaims` (unexpected tag 98) | n/a (additive) |
| `VerifyMACToken` and `OpenToken` accept a tagged COSE_Mac (97) or COSE_Encrypt (96) with several recipients, using the new `VerifyOptions.Recipient` (a `cose.KeyDeriver`); each recipient is tried, the content algorithm stays on the allow-list, and without a `Recipient` the token fails with `ErrKeyResolution` (037 W18) | `ErrMalformedClaims` (unexpected tag) | n/a (additive) |
| A float NumericDate decodes to the nearest nanosecond, so it re-encodes unchanged (037 W30) | truncated: 2.675 decoded as 2.674999999 and re-encoded as a different float | none |

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

Behavior changes from the pre-v0.3.0 review (proposal 037). They apply
to the RFC 9528 protocol; under `WithLegacyPreRFCProtocol` only the CWT
claims validation applies:

| Change | Old behavior | Restore with |
|---|---|---|
| `PeerCredential()` and `PeerEAD()` return nil until the peer's Signature_or_MAC verifies, and after any failure (EAD_1 stays visible after `ProcessMessage1`, documented as unverified) | the resolved credential and decoded EAD were returned even when verification then failed | none (safety defect, 034) |
| A CWT sent by value (kcwt) is validated after its signature verifies, with `CWTValidator` (default `cwt.NewValidator()`: exp required, exp/nbf checked, 60 s leeway); a CCS sent by value (kccs) has its exp/nbf/iat checked when present. Errors wrap `ErrAuthentication` and the `cwt` sentinel (`cwt.ErrTokenExpired`, …) | signature checked only; an expired CWT completed the handshake | none (safety defect, 034); set `CWTValidator` for audience, issuer, clock or leeway |
| Under `WithLegacyPreRFCProtocol`, a peer's CWT credential is also validated with `CWTValidator` (default `cwt.NewValidator()`, exp required); errors wrap `ErrAuthentication` and the `cwt` sentinel. The legacy wire format is unchanged | signature checked only | none (safety defect, 034); set `CWTValidator` for clock, leeway, audience or issuer |
| Static DH methods (1–3) require `DHKey` for the party that authenticates with DH (checked by `NewInitiator`/`NewResponder` when the method is fixed); an authentication key whose credential restricts it to the other use (COSE_Key `alg`/`key_ops` in a CCS or CWT, X.509 keyUsage) is rejected, peer (`ErrAuthentication`) and own (`ErrStateViolation`). Unrestricted P-curve keys are accepted for either use, as RFC 9529's CCSs require | an `*ecdsa.PrivateKey` `PrivateKey` was silently used as the static DH key, and the peer's signing key accepted as its DH key | none (safety defect, 034). Static DH methods are new in v0.30, so no v0.2 caller relied on it; a caller who decides to reuse one P-curve key can pass `k.ECDH()` as `DHKey` explicitly |
| `X509Resolver` requires `X509Policy.VerifyPeer` (the identity check) and fails closed without it; the leaf's keyUsage must allow the method (digitalSignature for signatures, keyAgreement for static DH; no extension means unrestricted). `KeyUsages` (extended key usage) still defaults to any, now documented | any leaf chaining to `Roots` was accepted, keyUsage unchecked | `X509Policy.AllowAnyPeerUnderRoots` accepts any leaf under `Roots` without an identity check; keyUsage: none (safety defect, 034) |
| An automatic C_I/C_R (nil `ConnectionID`) avoids the peer's identifier and every identifier held by a live endpoint in the process (released on `Close`, failure or garbage collection), preferring one-byte integers and growing to longer identifiers when those are taken. The new `AllocateConnectionID` hook chooses it instead; callers running many sessions or keeping OSCORE contexts after `Close` must supply one (RFC 9668 §4.1.1–4.1.2) | random among 48 values, avoiding only the peer's | none (safety defect, 034); `AllocateConnectionID` is the caller-owned allocator |
| Methods on a zero-value or nil `*Initiator`/`*Responder` return `ErrStateViolation` (accessors return nil) | nil pointer panic | none (safety defect, 034) |
| An error message received in place of message_3 (`ProcessMessage3`) or message_4 (`ProcessMessage4`) is returned as the peer's `*ErrorMessage` (matches `ErrPeerError`) | reported as `ErrMessageFormat` | none (contract defect: RFC 9528 §6) |
| A received error message must follow RFC 9528 §6: ERR_INFO present, ERR_CODE 0 never sent, ERR_CODE 1 text, 2 SUITES_R, 3 `true`; otherwise `ErrMessageFormat` (no `*ErrorMessage`). `MarshalCBOR` refuses ERR_CODE 0 | missing or mistyped ERR_INFO accepted; ERR_CODE 0 accepted and emitted | none (contract defect: RFC 9528 §6) |
| New `ErrorMessageFor(err)`: the error message to send after any failure, with fixed ERR_INFO texts ("message rejected", "session aborted") that don't reveal which check failed; ERR_CODE 3 for an unresolvable kid/x5t reference; nil for received error messages. Such reference failures also match the new `ErrUnknownCredential` (resolvers may wrap it) | only suite and method rejections produced an error message | n/a (additive) |
| An ID_CRED map with several parameters, or ones the package doesn't model (kid context, text labels), is accepted: modeled ones fill their fields, the rest go to the new `IDCred.Other`, and the received map is kept in the new `IDCred.Raw` and used byte-for-byte in the transcript (labels need not be sorted, RFC 9528 §3.5.3). `ParseIDCred` accepts the same. A pinned `PeerCredential` matches by kid, x5t or leaf | rejected unless exactly one parameter; the transcript used a re-encoding | none (contract defect: RFC 9528 §3.5.3) |
| An x5chain holding one certificate in an array is rejected with `ErrMessageFormat` (RFC 9360 §2: a single certificate is a byte string) | accepted, then re-encoded as a byte string in the transcript | `AllowSingleCertX5ChainArray` (config field) accepts it, using the received bytes in the transcript |
| A CWT sent with the CWT tag (61) in kcwt, or configured that way in `CWTBytes`, enters the transcript untagged as CRED_x (RFC 9528 §3.5.2); `IDCred.KCWT` keeps the bytes as sent | the tagged bytes were used as CRED_x, so the MAC differed from a conforming peer's | none (contract defect: RFC 9528 §3.5.2) |
| Received messages (and error messages) must be deterministically encoded CBOR; ID_CRED maps need only preferred serialization (labels unsorted is fine, §3.5.3). Duplicate map keys are always rejected | non-shortest heads and unsorted maps accepted | `AcceptNonDeterministicEncoding` (RFC 9528 §9 RECOMMENDs aborting) |
| A received C_I, C_R or compact kid that is a one-byte CBOR integer encoding sent as a byte string (`41 01` for `01`) is rejected with `ErrMessageFormat` (RFC 9528 §3.3.2) | accepted, though the docs said such identifiers are sent as integers | `AcceptNonDeterministicEncoding` |
| `ExportOSCORE`/`OSCORE` fail with `ErrStateViolation` when C_I or C_R is longer than an OSCORE Sender/Recipient ID may be for the suite's AEAD (nonce length − 6: 7 bytes for AES-CCM, 6 for GCM/ChaCha20, RFC 8613 §3.3) | a context with unusable IDs was returned | none (contract defect: RFC 8613 §3.3) |
| PLAINTEXT_2 longer than 255 hash lengths (8160 bytes for SHA-256, RFC 9528 Appendix G) fails up front, naming PLAINTEXT_2: `ErrStateViolation` when building message_2, `ErrMessageFormat` when receiving it | an `ErrMessageFormat` from EDHOC_KDF after the key schedule had run | none (contract defect) |
| Intermediate values (ephemeral keys, PRK_2e/3e2m/4e3m, TH_2–TH_4, H(message_1)) are zeroized as soon as nothing derives from them; a completed session keeps only PRK_out, PRK_exporter and, until message_4, K_4/IV_4 | kept until `Close` or failure | none (safety defect, 034; RFC 9528 §9) |
| `Rand` is documented as INSECURE and for tests only (its bytes become the ephemeral private key); behavior unchanged | documented only as "deterministic tests" | n/a (documentation) |
| New `AcceptCriticalEADInMessage(message, item)` gives the critical-EAD decision the message number (1–4); it takes precedence over `AcceptCriticalEAD`, which is unchanged. `ErrCriticalEAD` errors now name the EAD field | the callback could not tell EAD_1 from EAD_3 | n/a (additive) |
| Received messages are bounded by the new `Limits` config field: `MaxMessageSize` (default 64 KiB), `MaxEADItems` per message (default 32), `MaxCertificates` in an x5chain (default 8); over-limit input fails with `ErrMessageFormat` naming the limit, before decoding where possible | unbounded apart from the decoder's nesting depth | `Limits` (raise any bound; zero selects the default) (safety defect, 034) |

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
| A claim key that is a bignum with an integer value is rejected, in submodules too (same reason as in `cwt`: bignum 10 re-encoded as `nonce`), with `cwt.ErrAmbiguousClaimKey` and `ErrMalformedEAT` in a `*cwt.ClaimError` naming the key as received; inside a submodule it is the innermost `*cwt.ClaimError` | kept as an unknown claim | `WithKeepAsReceived()` keeps it verbatim in `ReceivedClaims` (safety defect, 034) |
| A claim whose key or value holds a NaN other than `f97e00` is rejected with `cwt.ErrNonCanonicalNaN`, in submodules too; `Encode` returns the same for a typed field such as `Location` holding one (036 item 25) | decoded, then re-encoded as `f97e00` | `WithKeepAsReceived()` for unmodeled claims; a modeled claim such as `location` is always checked |
| `eat_profile` may be an OID (`ProfileOID`) | bstr form rejected | n/a |
| A negative `SecurityLevel` or `Debug` encodes as a CBOR negative integer | wrapped to a large uint | none |
| `Verify` accepts an outer CWT tag 61 followed by a COSE tag (RFC 9711 §3) and decodes the envelope with an 8 MiB memory budget, the claims decoder's (037 W8) | tag 61 rejected; envelope decoded with no limit | none (safety defect, 034); use the new `VerifyToken` for `cose.RecommendedDecodeLimits` |
| `Sign`, `Verify` and `VerifyToken` refuse a symmetric `cnf` COSE_Key by value, in inline submodules too, with `cwt.ErrSymmetricKeyNotEncrypted` in a `*cwt.ClaimError` for `cnf` (RFC 8747 §3.2; 037 W7) | emitted and accepted in plaintext | none (safety defect, 034): use `Confirmation.EncryptedKey` |
| `DecodeClaims` rejects a nonce array of fewer than 2 nonces (`[ 2* nonce-type ]`, RFC 9711 §4.1) and an empty `sueids` map (§4.2.2), which `Encode` would rewrite (037 W14) | `[]` decoded as no nonce; `[n]` re-encoded as `n` | none |
| `Claims.Validate` (run by `NewAppraiser` and `VerifyToken`) also checks oemid size/PEN, hwmodel size, the hwmodel→oemid, hwversion→hwmodel, oemboot→oemid and swversion→swname dependencies, DLOA registrar URIs, Content-Format identification of manifests/measurements, and measres results, with the new `ErrInvalidClaimValue` in a `*cwt.ClaimError` (037 W14) | not checked | none; the zero `Appraiser{}` still skips value checks (documented v0.2.2 entry point) |
| A byte-string submodule must be one tagged CBOR data item (`bstr .cbor $CBOR-Tagged-Token`), and a text submodule a JSON-Selector `[type, token]` whose type is not `"DIGEST"` (RFC 9711 §4.2.18), on decode and `Encode`, under RFC 9711 numbering (037 W23, W24) | any bytes or text accepted | none |
| `Encode` returns a `*cwt.ClaimError` (`ErrMalformedEAT`, `cwt.ErrMalformedClaims`) for a claim set in `PrivateClaims` and by a typed field with different values, as `cwt` does (037 W27) | the `PrivateClaims` entry was silently dropped | none |
| `DecodeDetachedBundle` requires a CBOR main token to be one tagged item and not a bundle, and each detached set to be a byte string wrapping one CBOR map (RFC 9711 §5); new `DetachedBundle.CheckDetached` checks a digest (SHA-256/384/512, SHA-512/256) and plugs into `Appraiser.SubmodDetached` (037 W25) | text (JSON-wrapped) sets and any main-token bytes accepted; no digest checker | none |
| New `Appraiser.AllowNonceInsteadOfExpiration`: with `RequireNonce` or `NonceVerifier` set, a token without `exp` passes `NewAppraiser`'s `RequireExpiration` (PSA, RFC 9783, has no `exp`) (037 W13) | `NewAppraiser` rejected every token without `exp` | n/a (opt-in) |
| With `SubmodPolicy` set, the submodules of an inline submodule and of a verified nested token are appraised too, fail-closed, to 16 levels (deeper is `ErrMalformedEAT`) (RFC 9711 §4.2.18; 037 W3) | only the top level was appraised; nested tokens below an inline submodule were never verified | none (safety defect, 034) |
| A nested token verified with `SubmodVerifier` is decoded with `cose.RecommendedDecodeLimits` and the new `Appraiser.Options`, its `typ` checked, and validated with `CWTValidator` (when set) and, with `ValidateValues`, `Claims.Validate` (037 W4) | `Verify` only: no limits, no claims validation, RFC 9711 numbering regardless | none (safety defect, 034) |

`DecodeClaims` accepts the same values as before, apart from the
shapes listed above that `Encode` would rewrite. The RFC 9711 value
rules (nonce 8–64 bytes, UEID form, sizes and dependencies, dbgstat
0–4, profile URI or OID, ...) are applied by `Claims.Validate()`, which
the recommended entry points run: `VerifyToken`, and `NewAppraiser()`,
which also sets `cwt.NewValidator()`. A zero-value `Appraiser{}` skips
them as in v0.2, but fails closed on submodules (032, 037 W3/W4).

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
- RFC 10013 measured components (037 W29): `MeasuredComponent`,
  `ComponentDigest`, `ParseMeasuredComponent`, `Encode`,
  `TypedBytes.MeasuredComponent`, and the media types / Content-Formats
  295 and 296. The JSON form: `ParseMeasuredComponentJSON` and
  `EncodeJSON`; in a CBOR EAT it is a text string, decoded into the new
  `TypedBytes.Text` (a measurements body carried as text; `Encode`
  writes it back as text). `Claims.Validate` checks measurements
  identified by 295 or 296, and that a body's kind fits its format.
- `VerifyToken(ctx, data, VerifyOptions{Keys: …})` (037 W9), the
  recommended entry point for a signed EAT: tag 61 (followed by a COSE
  tag) or a bare COSE_Sign1; `cose.RecommendedDecodeLimits`; `typ`
  `application/eat+cwt` (with or without parameters), 263,
  `application/cwt` or 61; nested tokens up to `MaxNesting`; claims
  validated with `cwt.NewValidator()` (or `VerifyOptions.Validator`)
  and `Claims.Validate`. Returns a `Token`. `VerifyMACToken(ctx, data,
  key, opts)` is its COSE_Mac0 counterpart (PSA with a symmetric key,
  RFC 9783 §5.1.1): same bounds, `typ` and validation; full-length
  HMACs unless `AllowedAlgorithms` lists more.
- RFC 9782 media types and content-formats (`MediaTypeEAT*`,
  `ContentFormatEAT*`).
- `eat/psa`: RFC 9783 PSA claims (`FromEAT`, `ToEAT`, lifecycle
  constants); `psa.SoftwareComponent` is `eat.SWComponent`.
  `(*psa.Claims).Validate` (037 W26) checks the profile's mandatory
  claims and value rules (one 32/48/64-byte nonce, client ID, 33-byte
  RAND instance ID, 32-byte implementation ID, lifecycle, PSA
  `eat_profile`, boot seed and certification reference forms,
  software-component hash sizes), with `psa.ErrInvalidPSA` in a
  `*cwt.ClaimError`.
- New sentinels: `ErrSubmodUnverified`, `ErrInvalidUEID`,
  `ErrInvalidNonce`, `ErrDebugStatus`, `ErrUnknownDebugStatus`,
  `ErrInvalidProfile`, `ErrClaimNumbering`.

Deprecated: `Claims.SecurityLevel`, `Appraiser.RequireSecurityLevel`
(the claim isn't in RFC 9711).

`DecodeClaims`, `(*Claims).Encode`, `Sign` and `Verify` gain
`...Option`; existing calls compile unchanged.

## scitt

The module is new in v0.30 (030), so nothing here changes v0.2.2
behavior; these rows change the 030 release candidate (037).

| Change | Old behavior | Restore with |
|---|---|---|
| `MinReceipts` (and `VerifyTransparent`'s `minReceipts`) counts distinct transparency services, identified by the receipt's protected CWT `iss`: a receipt attached twice, or several from one service, count once (037 W5) | every verifying receipt counted, duplicates included | none (safety defect, 034); `ServiceKeys` should resolve a key only for its own issuer |
| `Verify` and `VerifyTransparent` check the statement's `exp` and `nbf` (RFC 9943 §7.1) with the new `DefaultValidator()` (60 s leeway, `exp` optional; a statement carrying `aud` is rejected unless the validator lists it), or `VerifyOptions.Validator` (037 W11) | validity period ignored | none (safety defect, 034); set `Validator.Now` to check a statement as of another time |
| A receipt counts only if it carries a protected `kid`, or protected x5t/x5chain with an X.509-suitable `iss`, as for signed statements (RFC 9943 §6; 037 W28). CWT Claims in both buckets were already malformed COSE | receipts without any key identifier counted | none |
| A receipt's own protected CWT Claims are validated with the same `VerifyOptions.Validator` (default `DefaultValidator()`): an expired or not-yet-valid receipt doesn't count toward `MinReceipts` (037) | receipt `exp`/`nbf` ignored | none; set `Validator.Now` to check as of another time |

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
