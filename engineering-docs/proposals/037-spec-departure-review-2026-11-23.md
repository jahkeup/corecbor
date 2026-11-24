# 037 — Specification-departure review before v0.3.0

## Header

| Field | Value |
|---|---|
| **Number** | 037 |
| **Tier** | 1 |
| **Status** | Closed |
| **Filed** | 2026-11-23 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 034, 036 |
| **Supersedes** | none |
| **Spec sections touched** | §14 when items are picked up |

---

## TL;DR

A review of HEAD `73bb56e` (all modules) against the RFCs each module
implements, and against secure practice. The rule applied:

- (a) the **correct** behavior (RFC plus secure practice) is selectable,
  and is the default;
- (b) an **insecure or permissive** behavior is selectable when a caller
  needs it;
- (c) the **legacy** (v0.2.2) behavior is selectable.

Per 034, safety defects (crashes, unbounded work, fail-open
authentication, silent data loss) get a fixed default and no (b)/(c)
selector. Items marked **B** block v0.3.0 as proposed below. The rest
are scheduled for v0.3.x/v0.4 under the same rule.

"Verified" means it was reproduced with a test against `73bb56e`.
CWT #6 (a kept bignum key standing for a modeled claim) is already
fixed in `cd2a71a`.

## Root module (CBOR core)

| # | B | Finding | Spec | Today | Needed |
|---|---|---|---|---|---|
| C1 | B | A chain of self-describe tags (`d9d9f7…`, ~6 MB) overflows the stack: a fatal error, not recoverable (`rfc8949/decode.go:828`, `cursor.go:509`, `diagnostic.go:294`). Verified | RFC 8949 §5.2 | crash | count stripped 55799 tags toward the depth limit, or loop |
| C2 | B | Duplicate check in indefinite-length maps is quadratic (`decode.go:770`): 40k entries take 0.5 s, 1M about 6 min. Verified | §5.2 | DoS | use the hashed set |
| C3 | B | `rfc8949.DecodeBytesArray`/`DecodeTextArray` panic on huge lengths; `DecodeUintArray` accepts AI 28–31; all ignore limits and strictness (`homogeneous.go`). Verified | §3, §5.2 | panic | bound lengths; apply opts |
| C4 | B | `DecodeFrom`/`Stream` buffer without bound before any budget (400 MB read with a 1 MiB budget) (`stream_decode.go:186`). Verified | §5.2 | DoS | charge budget while reading, or a `MaxItemSize` |
| C5 | B | `WithMemoryBudget` doesn't charge indefinite containers or strings, scalars, or sequences; per-item charges understate (`decode.go:326,398,462,626,682,763`). Verified | §5.2 | budget bypass | charge real sizes |
| C6 | B | `Stream.Next` ends cleanly on a truncated last item; a wrong chunk type is reported as truncation (`stream.go:567`). Verified | RFC 8742 §2, §3.2.3 | silent data loss | error on partial item; distinct well-formedness error |
| C7 | B | `Cursor.FindMapKey` takes the first duplicate where `Decode` takes the last; strict cursors don't reject duplicates; raw key compare ignores non-shortest/indefinite keys (`cursor.go:320`). Verified | §5.6 | parser differential | honor duplicate policy and key identity |
| C8 | B | A `RawMessage`/`Marshaler` with duplicate keys is silently merged in deterministic modes (`a2616101616102` → `a1616102`). Verified | §4.2, documented `ErrDuplicateMapKey` | silent data loss | reject |
| C9 | B | `DeterministicDecoder` accepts NaN payloads that re-encoding can't reproduce, contradicting its doc (`check.go:125`); Core Deterministic writes every NaN as `f97e00` | §4.2.1 | doc contradiction | reject in the checking decoder; optional RFC-exact NaN mode |
| C10 | | Tag content never validated (tag 2 around text, tag 0 around int) on encode or decode | §3.4 | (b) only | `RejectInvalidTagContent` (a) |
| C11 | | Permissive/PreferredPlus encoders emit duplicate keys | §5.6 | (b) only | opt-in reject (a) |
| C12 | | UTF-8 split across indefinite-text chunks accepted under `RejectInvalidUTF8` | §3.2.3 | (b) only | (a) under the reject policy |
| C13 | | Stream encoder `WriteFloat32/64` ignore deterministic mode | §4.2.1 | wrong in det. mode | honor mode |
| C14 | | Permissive re-encoding widens half floats (no float16 kind) | §4.1 | doc | document, or keep width |
| C15–C17 | | Unknown tags dropped when unmarshalling into scalars; `undefined` vs `null`; lenient package-level `Unmarshal` with no strict helper | §3.4, §5.3 | (b)/(c) | strict helpers; docs |
| C18 | | RFC 8746 typed arrays not implemented | RFC 8746 | gap | 036 item 4 |
| C19–C22 | | Doc-only: sequence error offsets; RawMessage bypasses UTF-8 policy in Permissive; `AsNestedCBOR` doesn't require exactly one item; float32 overflow message | — | — | fix docs / small checks |

## cose

| # | B | Finding | Spec | Today | Needed |
|---|---|---|---|---|---|
| S1 | B | `DirectKey` recipients drop the CEK: `EncryptMulti` succeeds and nothing decrypts; may be mixed with other recipients (`keyderiver.go:44`, `recipients.go:40`). Verified | RFC 9052 §8.5.1 | silent data loss | use the key as CEK; reject mixing |
| S2 | | Key-wrap recipients put `alg` in protected (must be empty) (`recipients.go:19`). Verified | §8.5.2 | wrong bytes | correct default + `WithLegacy…` |
| S3 | | Nested recipients (4-element `COSE_recipient`) fail the whole parse (`marshal.go:487,820`). Verified | §5.1, §8.5.2 | interop | parse or skip |
| S4 | B | A COSE_Key's `alg` no longer restricts it once `WithAllowedAlgorithms` is passed (PS256 key accepts RS256) (`key_ctor.go:74,84`). Verified | §7.1 | downgrade | intersect allow-list with key alg |
| S5 | | `typ` (16) allowed in unprotected headers, emitted and accepted. Verified | RFC 9596 §2 | wrong | reject (a), opt-in permissive (b) |
| S6 | B | Any non-empty HMAC key accepted (1 byte); strict length is opt-in (`mac.go:81`). Verified | RFC 9053 §3.1 | weak default | strict default; `WithLegacy…` for short keys |
| S7 | B | PBES2: no minimum count/salt/password; default count 10,000 (`pbes2_deriver.go`). Verified | RFC 7518 §4.8.1, RFC 8018 | weak default | floors + higher default; opt-out |
| S8 | B | `Unmarshal*` unbounded by default; `VerifyMulti` signature × verifier work and recipient counts uncapped | §5.2 practice | DoS | bounded defaults (`RecommendedDecodeLimits`), count caps; opt-out |
| S9–S12 | | Recipient/message with no `alg` processed as the key's; unprotected-only `alg` accepted when equal; ECDH-ES ephemeral key may carry `d`; `KeyDeriver` ignores `key_ops` direction | §8.5, RFC 9053 §6 | lenient | strict options / defaults |
| S13 | | Hash envelope labels 258–260 not "understood" for `crit` | RFC 9052 §3.1 | interop | add |
| S14 | | Empty protected always `h''` even when received `h'a0'` | §3 | interop | opt-in "as received" |
| S15 | | 1-element `x5chain` array rejected (correct) | RFC 9360 §2 | (a) only | (b) lenient option |
| S16–S19 | | JWK conversion gaps (non-UTF-8 kid, `use`/`key_ops` consistency, duplicates); `Lookup` exact alg match across ES256/ESP256; legacy `HPKEKey` on by default (alg 35 collision with draft-27); empty `recipients` accepted | RFC 7517 §4.3, RFC 9864 | various | per item |
| S20–S21 | | Countersignatures (RFC 9338) not implemented; ES256 with non-P-256 key rejected (stricter than SHOULD) | RFC 9338, RFC 9053 §2.1 | gap | doc / (b) |

## cwt, eat, scitt

| # | B | Finding | Spec | Today | Needed |
|---|---|---|---|---|---|
| W1 | B | `aud` not enforced unless configured; one audience only (`validate.go:107`). Verified | RFC 7519 §4.1.3 | fail-open | reject unexpected `aud` by default (`Audiences []string`); opt-out |
| W2 | B | Empty `cnf` satisfies `RequireConfirmation`. Verified | RFC 8747 §3.1 | fail-open | require one understood method |
| W3 | B | Nested tokens inside inline submodules never appraised. Verified | RFC 9711 §4.2.18.3 | fail-open | recurse |
| W4 | B | `SubmodVerifier` path skips claims validation, drops options and limits. Verified | 032 intent | fail-open | validate nested claims; pass options |
| W5 | B | SCITT `MinReceipts` counts duplicate receipts. Verified | RFC 9943 §7.1 | fail-open | dedupe |
| W6 | — | (fixed in `cd2a71a`) | | | |
| W7 | B | Symmetric `cnf` key accepted and emitted in a plaintext CWT. Verified | RFC 8747 §3.2 | key exposure | reject on Sign/MAC/verify; opt-out |
| W8–W9 | B | Legacy verify paths decode with no limits; eat has no limited, validating `VerifyToken`; rejects tag-61 EAT | RFC 9711 | DoS / gap | `eat.VerifyToken` with limits and `typ` |
| W10 | | `exp` at year 1 read as absent | RFC 8392 | edge | presence flags |
| W11 | B | SCITT `Verify` ignores statement `exp`/`nbf`. Verified | RFC 9943 §7.1 | fail-open | validator hook, on by default |
| W12 | | No expected-`typ` option; EAT `typ` rejected by `cwt.VerifyToken` | RFC 9596, RFC 8725 §3.11 | gap | option |
| W13–W33 | | `NewAppraiser` requires `exp` (PSA has none); RFC 9711 value checks opt-in and incomplete (nonce array size, oemid/hwmodel sizes and dependencies, ranges); non-int/text claim keys accepted; tag 61 + untagged COSE accepted; nesting by `cty` only; multi-signer CWTs unsupported; eat duplicate claims have no (b)/(c); `exi` ignored; ill-typed ACE claims silently private; `cnf` COSE_Key + kid rejected (stricter); nested-token bytes not checked as tagged; JSON submodule DIGEST rule; detached bundle checks; PSA profile validation; eat `Encode` drops a colliding private claim (cwt errors); SCITT receipt bucket/kid looseness; RFC 10013 not implemented; NumericDate truncation | RFC 8392, 9200, 9711, 9783, 9943 | various | per item, (a)/(b)/(c) |

## edhoc

| # | B | Finding | Spec | Today | Needed |
|---|---|---|---|---|---|
| E1 | B | A CWT credential is only signature-checked: an expired CWT completes the handshake (`credential.go:56`). Verified | RFC 9528 §9.8 | fail-open | `cwt.Validator` hook, `NewValidator()` by default |
| E2 | B | ECDSA signing keys reused as static DH keys, both sides (`primitives.go:122`) | §3.5.1 | key misuse | strict default (key type/usage); opt-in permissive |
| E3 | B | `PeerCredential`/`PeerEAD` return values after verification failed. Verified | §5.3.3, §5.4.3 | identity confusion | nil after failure |
| E4 | B | X.509: empty `KeyUsages` = any; keyUsage bits unchecked; any leaf under `Roots` accepted without `VerifyPeer` | §9.8, App. D.2 | weak default | method-matched keyUsage; identity check required or prominent |
| E5 | B | Automatic C_I/C_R picks from 48 values without avoiding live sessions/OSCORE IDs | RFC 9668 §4.1.1 | MUST violated | allocator callback |
| E6–E7 | | Error messages produced only for method/suite; an error in place of message_3/4 reads as format error. Verified | §5.2.3, §6 | interop | `ErrorMessageFor(err)` without oracle detail; recognize received errors |
| E8–E20 | | ID_CRED with other/multiple params rejected and re-encoded; non-deterministic input accepted; bstr CIDs accepted (doc claims otherwise); error-message field rules; OSCORE ID length; PLAINTEXT_2 size; 1-element x5chain; tagged kcwt as CRED_x; intermediate keys kept until Close; `Rand` not flagged as insecure; `AcceptCriticalEAD` lacks message number; zero-value endpoint panics; no size/count limits | §3–§9, RFC 9668 | various | per item |

## Already complete under the rule

The reviews confirmed (a)/(b)/(c) for, among others: duplicate keys on
decode; UTF-8 policy; bignum preferred form; strict tag policy;
non-finite floats; COSE `alg` binding, `crit`, duplicate labels, ECDH-ES
and PBES2 code points, Encrypt0 IVs, algorithm identifiers, RSA, short
EC2 coordinates, detached payloads, HPKE; CWT time validation, verify
paths, truncated HMAC, duplicate claims, bignum keys and NaN payloads;
EAT appraisal and claim numbering; EDHOC method negotiation, peer
authentication, critical EAD, OSCORE export; and downgrade protection
(correct by design, no permissive option).

## Proposal

Fix every **B** item before tagging v0.3.0, as safety defects or
fail-open defaults under 034. Where a default changes and a caller may
depend on the old behavior, add the (b) option, and a (c) `Legacy…`
selector when v0.2.2 behaved that way. Verification-weakening
selectors stay out of `CompatV02` bundles. Schedule the rest for
v0.3.x/v0.4 with the same rule.

## Results (2026-11-23)

Every row above is handled on local main, one commit per item, each
starting from a failing test (`*037*_test.go` in each module). No
`Legacy…` or `CompatV02` selector was added. Where a default moved to
the correct behavior and callers may need the old one, a plainly named
opt-in exists (`Allow…`, `Insecure…`, `Ignore…`); crashes, unbounded
work and fail-open checks have none. The migration guide has a row
per change.

- **Root (C1–C22):** all fixed. Beyond the rows:
  - quadratic map-key comparison and `Value.Equal` on large maps
    (`internal/pairmatch`);
  - keyed per-process hashing against hash flooding
    (`internal/seedhash`);
  - `DefaultMaxItemSize` (64 MiB) for reader-based decoding;
  - RFC 8746 complete: typed, float16/128, multi-dimensional and
    homogeneous arrays;
  - `UnmarshalStrict`.
  Benchmarks are within ±3% apart from `CursorFindMapKey` on a middle
  key (+61%, the cost of last-wins); large-map decode −4–5%.
  Golden change: `root/stream/scalars` (C13).
- **cose (S1–S21):** all fixed, plus:
  - RFC 9338 countersignatures on all six message types, on
    COSE_Signature and COSE_recipient, and on detached content (RFC
    vendored; Appendix A vectors pass);
  - decryption and MAC verification through nested recipients (RFC
    9052 Appendix B decrypts);
  - `RequireProtectedAlgorithm` (S10 opt-in).
  Golden changes: `cose/multi/mac-direct` (S1), `cose/mac0/short-key`
  (S6).
- **cwt/eat/scitt (W1–W33):** all fixed, plus:
  - COSE_Sign/COSE_Mac/COSE_Encrypt CWTs;
  - `eat.VerifyToken`, `eat.VerifyMACToken` (PSA over COSE_Mac0);
  - RFC 10013 CBOR and JSON forms;
  - PSA profile validation;
  - receipt framing and validity.
  Golden change: `cwt/validate/audience-unset-token-has-aud` (W1).
- **edhoc (E1–E20):** all fixed. E1 also applies under
  `WithLegacyPreRFCProtocol`. The RFC 9529 traces are unchanged.
- **Integration:** `cwt.MAC`/`VerifyMAC` take `...cose.MACOption`
  (allowlisted). `VerifyOptions.MACOptions` and `DecodeLimits` in cwt
  and eat, and `Appraiser.DecodeLimits`, carry the cose opt-ins
  through.

Checks on the integrated tree:
- `make check` passes, apicheck included;
- the Go 1.26 vet is clean in every module;
- the full fuzz sweep passes;
- the consumer format-stability test and suite pass.

### Maintainer decisions (2026-11-23)

1. **W30 — decided:** eat `Encode` now writes NumericDates as RFC
   8392 §2 allows (integer for whole seconds, float otherwise) instead
   of truncating.
2. **Default bounds — accepted:**
   - `DefaultMaxItemSize` 64 MiB (reader decoding);
   - cose 1 MiB / depth 16 / 32 signatures / 64 recipients;
   - edhoc 64 KiB messages / 32 EAD items / 8 certificates.
3. **Strength defaults — accepted:**
   - PBES2 seal count 600,000 (OWASP);
   - minimum HMAC key length per RFC 9053;
   - strict decoders reject invalid tag content (no opt-out other than
     composing the old preset).
4. **edhoc — decided:** the process-wide default connection-ID
   allocator stays (documented). `ErrorMessageFor` never sends
   ERR_CODE 3: an unknown credential gets the generic ERR_CODE 1, so an
   active attacker can't probe which credentials exist.
5. **RFC 9711 Appendix A.2.2** has oemboot without oemid, which the
   normative text forbids; `Validate` follows the text. No erratum will
   be filed.

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-23 | Filed from the four module reviews | corecbor maintainers |
| 2026-11-23 | All rows implemented; status Implemented pending five decisions | corecbor maintainers |
| 2026-11-23 | Decisions recorded (W30 floats, no ERR_CODE 3, bounds and strength accepted); Closed | corecbor maintainers |
