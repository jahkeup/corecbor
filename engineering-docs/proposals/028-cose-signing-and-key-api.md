# 028 — COSE signing headers, detached payloads, and COSE_Key API

## Header

| Field | Value |
|---|---|
| **Number** | 028 |
| **Tier** | 3 |
| **Status** | Closed |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 002, 011, 027 (verification policy, `Headers.SetChecked`), 034 (compatibility policy) |
| **Supersedes** | none (fills the `Key`/`KeySet` surface promised in 002:347) |
| **Spec sections touched** | none in `encoder-decoder-spec.md`; cose module contract only |

---

## TL;DR

The signer can only ever emit `{1: alg}` as protected headers, and
`COSE_Key` cannot be parsed or serialized. Together these block every
non-toy consumer: SCITT, mDL, C2PA, WebAuthn and KMS-backed signing.

This proposal adds:

1. caller-controlled protected and unprotected headers on all signing paths;
2. explicit detached-payload sign and verify;
3. typed header accessors for the registered labels consumers actually use;
4. a complete `COSE_Key` API (parse, prefix-parse, marshal, `KeySet`
   lookup, `key_ops` enforcement, RFC 9679 thumbprint, JWK interop);
5. key resolution with `context.Context` and KMS-friendly signing.

Acceptance: each consumer flow in Motivation has an end-to-end test using
published vectors where available.

---

## Motivation

### Current surface (confirmed)

| Gap | Evidence |
|---|---|
| Protected headers are fixed to `alg` | `NewSigner` pre-encodes `{1: alg}` (`cose/sign.go:49-51`); `Sign` sets only alg (`sign.go:62`); `computeSignature` likewise (`sign_multi.go:86`) |
| `SignMulti` ignores its options | `opts ...SignerOption` is never read (`sign_multi.go:12-36`); body protected is always empty (`sign_multi.go:22`) |
| No detached signing | `Sign` always embeds `payload` (`sign.go:58-61`) |
| Header accessors exist only for `alg` and `kid` | `headers.go:43-79` |
| `COSE_Key` is opaque | `Key{params map[int64]any}` (`key_types.go:41-43`); constructors only from Go keys (`key.go:13-62`); no decode, encode, kid, alg, or `key_ops` accessors; `KeySet` absent despite 002:347 |
| Key types | Only OKP/Ed25519 and EC2 P-256/384/521 (`key.go:64-106`). The RSA constant is absent; `KeyTypeSymmetric` is declared (`key_types.go:27`) but unused. No AKP (kty 7, RFC 9964). No X25519/X448 OKP path, although `CurveX25519` is declared (`key_types.go:36`). |
| Oversize coordinates are truncated | `padLeft` returns inputs ≥ size unchanged (`key_types.go:99-106`), then `copy` into a fixed-size point silently truncates (`key.go:95-96`). `ParseUncompressedPublicKey` probably rejects the result as off-curve; still, exact length must be required (RFC 9053 §7.1.1). |
| `alg` never set on keys | `NewKeyFromPublic` sets kty, crv, x and y only (`key.go:13-41`) |
| Ed25519 must be an in-memory key | `signBytes` type-asserts `ed25519.PrivateKey` (`sign.go:80`), so an Ed25519 `crypto.Signer` backed by a KMS or HSM fails |
| No `context.Context` | No signer, verifier or key lookup takes a `ctx`; remote KMS calls cannot be cancelled |
| No key resolution | The caller must pick the `Verifier`; `DecryptMulti` and `VerifyMACMulti` select recipients by index only (`encrypt_multi.go:96`, `mac_multi.go:80`) |

### Consumers that are blocked

- **SCITT signed statements (RFC 9943; RFC 9597; RFC 9596).** Protected
  headers must carry `alg`, `kid` or `x5chain`, `typ` (16), and CWT Claims
  (15) with `iss` and `sub`. Payloads are often detached.
- **mDL / ISO 18013-5 MSO.** COSE_Sign1 with `x5chain` (33) in the
  unprotected bucket and the MSO as payload. DeviceAuth uses detached
  payloads over DeviceAuthentication bytes.
- **C2PA claim signatures.** COSE_Sign1 with `x5chain` and RFC 3161
  timestamp headers (RFC 9921 labels 269 and 270), with a detached payload.
- **WebAuthn verifiers.** The authenticator data contains a COSE_Key
  followed by extension bytes, so we need `ParseKeyPrefix`. Algorithms in
  practice are −7, −8, −257, and now −9 and −19 (see 029). This requires
  the RSA kty 3 key type.
- **KMS/HSM signers.** These are `crypto.Signer` for ECDSA and Ed25519,
  sometimes with a context-aware API.

---

## Proposal

### Header labels (verified against IANA COSE registry, fetched 2026-11-20)

| Label | Name | Ref | Accessor |
|---|---|---|---|
| 1 | alg | RFC 9052 | `Algorithm()` (exists) |
| 2 | crit | RFC 9052 | `Critical() []any` |
| 3 | content type | RFC 9052 | `ContentType() (uint64, string, bool)` |
| 4 | kid | RFC 9052 | `KeyID()` (exists) |
| 5 | IV | RFC 9052 | `IV() []byte` |
| 6 | Partial IV | RFC 9052 | `PartialIV() []byte` |
| 10 | kid context | RFC 8613 | `KeyIDContext() []byte` |
| 13 | kcwt | RFC 9528 | raw `corecbor.Value` |
| 14 | kccs | RFC 9528 | raw `corecbor.Value` |
| 15 | CWT Claims | RFC 9597 | `CWTClaims() (corecbor.Value, bool)` |
| 16 | typ | RFC 9596 | `Type() (uint64, string, bool)` |
| 32 | x5bag | RFC 9360 | `X5Bag() ([][]byte, error)` |
| 33 | x5chain | RFC 9360 | `X5Chain() ([][]byte, error)` |
| 34 | x5t | RFC 9360 | `X5T() (CertHash, bool, error)` |
| 35 | x5u | RFC 9360 | `X5U() (string, bool)` |
| 269 | 3161-ttc | RFC 9921 | `TimestampTTC() []byte` |
| 270 | 3161-ctt | RFC 9921 | `TimestampCTT() []byte` |

Labels 258–260 (hash envelope) and 394–396 (receipts) belong to 030.
COSE_X509 is `bstr / [2* bstr]` (RFC 9360 §2). `X5Chain` normalizes it to
`[][]byte`, and `SetX5Chain` emits a single bstr for a one-certificate
chain.

### Public API surface

```go
// ---- header construction (new methods; all return error, following 027's SetChecked)
func (h *Headers) SetContentType(ct any) error  // uint64 or string
func (h *Headers) SetType(typ any) error        // RFC 9596
func (h *Headers) SetCWTClaims(claims corecbor.Value) error // RFC 9597; must be a map
func (h *Headers) SetX5Chain(der ...[]byte) error
func (h *Headers) SetX5T(alg Algorithm, hash []byte) error
func (h *Headers) SetCritical(labels ...any) error

type CertHash struct {
	Alg  Algorithm // e.g. -16 SHA-256
	Hash []byte
}
// Matches reports whether cert (DER) hashes to h. Unsupported hash → false.
func (h CertHash) Matches(cert []byte) bool

// Lookup across buckets honoring 027's no-duplicate rule. Protected first.
func Lookup(protected, unprotected *Headers, label any) (any, bool)

// ---- signing with headers
func WithProtectedHeaders(h Headers) SignerOption   // alg is always overwritten by the Signer
func WithUnprotectedHeaders(h Headers) SignerOption

// SignDetached produces a Sign1 with Payload == nil; the signature covers payload.
func (s *Signer) SignDetached(payload []byte) (*Sign1, error)

// SignContext is Sign with cancellation for context-aware signers.
func (s *Signer) SignContext(ctx context.Context, payload []byte) (*Sign1, error)

// ContextSigner is detected at runtime; crypto.Signer remains the baseline.
type ContextSigner interface {
	crypto.Signer
	SignContext(ctx context.Context, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// SignMulti (signature unchanged from v0.2.2) starts honoring its
// existing opts parameter for body headers. v0.2.2 accepted and ignored
// it, so calls that pass no options are unchanged.
func SignMulti(payload []byte, signers []*Signer, opts ...SignerOption) (*Sign, error)

// ---- COSE_Key
type KeyOp int

const (
	KeyOpSign KeyOp = 1 + iota
	KeyOpVerify
	KeyOpEncrypt
	KeyOpDecrypt
	KeyOpWrapKey
	KeyOpUnwrapKey
	KeyOpDeriveKey
	KeyOpDeriveBits
	KeyOpMACCreate
	KeyOpMACVerify
)

const (
	KeyTypeRSA KeyType = 3 // RFC 8230
	KeyTypeAKP KeyType = 7 // RFC 9964
)

const CurveX448, CurveEd448 Curve = 5, 7

func ParseKey(data []byte, opts ...KeyOption) (*Key, error)
// ParseKeyPrefix decodes one COSE_Key from the front of data and returns
// the remainder (WebAuthn authData attestedCredentialData).
func ParseKeyPrefix(data []byte, opts ...KeyOption) (k *Key, rest []byte, err error)

// KeyOption adjusts COSE_Key parsing.
type KeyOption func(*keyParseConfig)

// AllowShortCoordinates makes ParseKey/ParseKeyPrefix left-pad EC2
// coordinates shorter than the curve size instead of rejecting them,
// for peers that strip leading zeros. RFC 9053 §7.1.1 requires the
// zeros to be preserved, so the new parsers reject short coordinates by
// default. The existing (*Key).PublicKey keeps left-padding, as in
// v0.2.2.
func AllowShortCoordinates() KeyOption
func (k *Key) MarshalCBOR() ([]byte, error) // CoreDeterministic
func (k *Key) UnmarshalCBOR(data []byte) error

func (k *Key) ID() []byte
func (k *Key) SetID(kid []byte)
func (k *Key) Algorithm() (Algorithm, bool)
func (k *Key) SetAlgorithm(Algorithm)
func (k *Key) Ops() []KeyOp
func (k *Key) Permits(op KeyOp) bool // absent key_ops → true (RFC 9052 §7.1)
func (k *Key) BaseIV() []byte
func (k *Key) Public() (*Key, error) // strip private parameters
// Thumbprint per RFC 9679: hash of the deterministic encoding of the
// required public parameters for kty.
func (k *Key) Thumbprint(h crypto.Hash) ([]byte, error)
// SymmetricKey returns the k parameter for kty 4.
func (k *Key) SymmetricKey() ([]byte, error)
// KeyDeriver adapts a key to the encryption KeyDeriver interface (kty 4 → DirectKey/AESKWKey, EC2/OKP → ECDH-ES per 029).
func (k *Key) KeyDeriver(alg Algorithm) (KeyDeriver, error)

// JWK interop (RFC 7517 / RFC 8037). Private members are included only if present.
func KeyFromJWK(jwk []byte) (*Key, error)
func (k *Key) JWK() ([]byte, error)

type KeySet []*Key
func ParseKeySet(data []byte) (KeySet, error)
func (ks KeySet) MarshalCBOR() ([]byte, error)
// Lookup returns keys matching kid (if non-nil) and alg (if non-zero) whose
// key_ops permit op.
func (ks KeySet) Lookup(kid []byte, alg Algorithm, op KeyOp) []*Key

// ---- resolution
// KeyResolver selects verification keys from message headers. Implementations
// MUST treat unprotected headers as untrusted hints.
type KeyResolver interface {
	ResolveKey(ctx context.Context, protected, unprotected *Headers) ([]crypto.PublicKey, error)
}

// KeySetResolver adapts a KeySet (kid + alg match).
func KeySetResolver(ks KeySet) KeyResolver

// VerifySign1 resolves, then verifies under 027 policy; first success wins.
func VerifySign1(ctx context.Context, msg *Sign1, r KeyResolver, opts ...VerifierOption) error
```

### Behavior

1. **Caller headers.**
   - `WithProtectedHeaders` copies the caller map. The `Signer` sets `alg`
     last, so a caller cannot produce `alg` mismatched to the key. A
     caller-supplied `alg` that differs from the key returns
     `ErrAlgorithmMismatch` at construction.
   - Protected bytes are encoded once per `Signer` (as `sign.go:51` does
     today), so headers stay invariant per `Signer`.
   - Per-message headers go through `(*Signer).Sign1(msg *Sign1) error`,
     which signs whatever `msg.Protected` holds (after enforcing `alg`) and
     stores the bytes in `msg.Protected.raw`.
2. **Detached payloads.** `SignDetached` leaves `Payload` nil, and
   `MarshalSign1` emits `null` (`marshal.go:36-37`). Verification uses
   027's `VerifyDetached`.
3. **KMS signing.**
   - `signBytes` calls `s.key.Sign(rand.Reader, data, crypto.Hash(0))`
     for EdDSA and Ed25519 instead of type-asserting (`sign.go:80`), which
     makes it compatible with any `crypto.Signer` whose `Public()` is
     `ed25519.PublicKey`.
   - When `s.key` implements `ContextSigner`, `SignContext` forwards `ctx`.
4. **COSE_Key parsing.**
   - Parsing goes through the 027 decode limits, rejects duplicate labels,
     and requires `kty`.
   - In the new `ParseKey`/`ParseKeyPrefix`, coordinates must be exactly
     the curve size (RFC 9053 §7.1.1); `AllowShortCoordinates()` left-pads
     short ones.
   - Oversize coordinates are rejected everywhere, including the existing
     `(*Key).PublicKey` (v0.2.2 silently truncated them via `padLeft` +
     `copy`, `key.go:95-96`, producing a different point — a Safety
     defect). Short coordinates keep being left-padded by
     `(*Key).PublicKey`, as in v0.2.2.
   - EC2 point compression (`y` as bool, RFC 9053 §7.1.1) is decompressed
     via `crypto/ecdh` or `elliptic`, then validated as on-curve.
   - Private keys are validated against their public part when both are
     present.
5. **`key_ops`.**
   - `NewSigner` and `NewVerifier` are unchanged. New `FromKey` variants:
     `NewSignerFromKey(*Key)` and `NewVerifierFromKey(*Key)`.
   - These check `Permits(KeyOpSign)` or `Permits(KeyOpVerify)`, and the
     key's `alg` when present. A failed check returns `ErrInvalidKey`.
6. **RSA (kty 3).** Verify-only in Phase 2, for RS256 and PS256–PS512.
   The modulus must be at least 2048 bits (RFC 8230 §6). RS256 is accepted
   only when listed in `WithAllowedAlgorithms` (it is RSASSA-PKCS1-v1_5,
   which is not Recommended in IANA). Signing follows in Phase 3.
7. **AKP (kty 7).** Parsing and marshaling land here. Signing and
   verifying are in 029 (ML-DSA).

### Failure modes

No new sentinels beyond 027. `ErrInvalidKey` gains these cases:
- wrong coordinate length
- `key_ops` denies the requested operation
- unknown `kty`
- RSA modulus below 2048 bits

`ErrMalformed` covers a COSE_Key that is not a map and duplicate labels.

### Implementation notes (2026-11-21)

Decisions taken while implementing, for review:

- **Open questions resolved.** `KeyResolver` returns `[]*Key`, so each
  key's `alg` and `key_ops` apply (via `NewVerifierFromKey`).
  `Sign1(msg)` merges the message's headers over the Signer's defaults
  (message values win); `Sign1Context` is its context variant.
- **Header labels** were re-verified against the IANA COSE registry
  (fetched 2026-11-21); all match the table above. Hash and RSA
  algorithm identifiers (`AlgSHA*`, `AlgPS*`, `AlgRS*`) were verified the
  same way and added, because x5t matching and RSA verification need
  them.
- **RSA keys** don't imply one algorithm, so an RSA `Verifier` takes the
  `alg` from the protected bucket only and accepts it if allowed:
  PS256/384/512 by default, RS256/384/512 only via
  `WithAllowedAlgorithms` (or a COSE_Key `alg`). `NewVerifier` now accepts
  `*rsa.PublicKey` of at least 2048 bits (input v0.2.2 rejected).
- **Signed messages carry their protected bytes.** `Sign` reuses the
  Signer's pre-encoded bucket as the message's `Raw()`, so marshaling
  writes exactly the signed bytes. `Raw()`'s doc was updated (it was
  added in 027, after v0.2.2).
- **`SignMulti` opts:** `WithProtectedHeaders`/`WithUnprotectedHeaders`
  set the body headers; `WithSignerExternalData` sets the external AAD
  for every signature, overriding each signer's own.
- **COSE_Key parsing** also rejects text that isn't valid UTF-8 (found by
  `FuzzParseKey`: such keys couldn't be re-encoded). Compressed EC2
  points are stored decompressed, so `MarshalCBOR` writes the
  uncompressed form. Text-labeled parameters are kept for round trips.
- **`KeyDeriver`** covers symmetric keys (direct, AES-KW). ECDH-ES from
  EC2/OKP keys is left to 029.
- **JWK:** a JWK `use` member becomes the equivalent `key_ops`, so a
  usage restriction survives conversion; oct `sign`/`verify` mean MAC
  create/verify; a kid that isn't UTF-8 is written base64url; an unknown
  JOSE `alg` is `ErrUnsupportedAlgorithm`.

Vectors used: RFC 9679 §6 (thumbprint), W3C WebAuthn L3 §16.7 packed
ES256 (`ParseKeyPrefix`; the parsed key verifies the vector's assertion
signature), RFC 7517 Appendix A and RFC 8037 Appendix A (JWK),
cose-wg/Examples `x509-examples/signed-01..05` and
`rsa-pss-examples/rsa-pss-01..03`.

Not done in this pass:

- **RSA signing.** It's verify-only; `NewSigner` with an RSA key returns
  `ErrUnsupportedAlgorithm`.
- **Ed448 and X448.** They parse and marshal, but have no stdlib
  implementation, so there's no sign/verify or ECDH.
- **`TestMDLIssuerAuth`** (non-gating; the vector's license is unconfirmed).
- **Legacy v0.2.2 key fixtures.** Short-coordinate behavior is tested
  directly, not against `testdata/legacy-v0.2.2/` files.
- **`BenchmarkParseKeyEC2` misses its ≤10 allocs target:** it measures
  20 allocs, 2.1 KB, ~0.84 µs (Apple M4 Pro). About half are the
  mandatory on-curve check (`ecdsa.ParseUncompressedPublicKey`
  internals). Getting there took a shared arena-free decoder (the first
  version built a decoder with its 40 KB internal arena per call:
  29 allocs, 42 KB, 13.9 µs), no redundant `Clone`, and unboxed labels.
  `BenchmarkSign1ES256` with extra protected headers is +1 alloc over
  alg-only, meeting its target.

---

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).
Almost all of this proposal is new API. Existing identifiers
(`NewSigner`, `NewVerifier`, `SignMulti`, `(*Key).PublicKey`,
`(*Key).Signer`, `Headers` accessors) keep their v0.2.2 signatures and
semantics except for the defect rows below. Signing-algorithm emission
is owned by 029.

| Change | Class | Contract restored | Existing identifiers in v0.30 | Selector |
|---|---|---|---|---|
| `(*Key).PublicKey` rejects EC2 coordinates longer than the curve size | Safety defect (silent truncation to a different point, `key.go:95-96`) | — | error | none |
| `(*Key).PublicKey` short coordinates | unchanged | — | left-padded, as v0.2.2 | n/a |
| New `ParseKey`/`ParseKeyPrefix` reject short coordinates | Additive (new identifier at current standard, RFC 9053 §7.1.1) | — | n/a | `AllowShortCoordinates() KeyOption` (interop, not deprecated) |
| New parsers reject duplicate labels and require `kty` | Additive (RFC 9052 §7) | — | n/a | none |
| `SignMulti` honors its existing `opts` for body headers | Contract defect | `cose/sign_multi.go:12` signature accepts `opts ...SignerOption` but v0.2.2 ignored them | no-option calls unchanged | none |
| Ed25519 `crypto.Signer` that isn't `ed25519.PrivateKey` (KMS) | Contract defect | `NewSigner(key crypto.Signer, …)` (`sign.go:35`) accepts any `crypto.Signer`; v0.2.2 failed at `sign.go:80` | supported (v0.2.2 errored; now succeeds) | none |
| `(*Key).MarshalCBOR`/`UnmarshalCBOR` | Additive | — | changes reflection output for a struct embedding `cose.Key` from `{}` (v0.2.2: only unexported fields, so an empty map) to the real COSE_Key. Listed in the migration guide | n/a |
| `key_ops` / key `alg` enforced | Additive — only through new `NewSignerFromKey`/`NewVerifierFromKey` | — | existing constructors unchanged | n/a |
| RS256 verify only when listed in `WithAllowedAlgorithms` | Additive (new algorithm) | — | n/a | `WithAllowedAlgorithms(AlgRS256)` |
| Caller-supplied protected `alg` mismatching the key → `ErrAlgorithmMismatch` | Additive (new option) | — | n/a | n/a |
| Headers, detached signing, KeySet, resolvers, JWK, thumbprint, RSA/AKP key types | Additive | — | n/a | n/a |

No `CompatV02Keys` bundle is needed: existing key identifiers keep their
v0.2.2 acceptance, and the stricter behavior lives only in new parsers.
No `...Option` parameters are appended to existing functions.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| Sign1 with protected `{1,4,15,16}` and unprotected `{33}` round-trips and verifies; bytes match a fixture | `TestSignWithHeadersSCITT` | Yes |
| `SignMulti` honors body protected headers | `TestSignMultiBodyHeaders` | Yes |
| `SignDetached` emits `null` payload; verifies only with `VerifyDetached` | `TestSignDetached` | Yes |
| Ed25519 `crypto.Signer` wrapper (non-`ed25519.PrivateKey`) signs | `TestKMSEd25519Signer` | Yes |
| `ContextSigner` receives a cancelled ctx and returns `ctx.Err()` | `TestSignContextCancel` | Yes |
| `ParseKeyPrefix` on WebAuthn packed attestation authData (W3C WebAuthn L3 test vector) returns key + extensions remainder | `TestParseKeyPrefixWebAuthn` | Yes |
| COSE_Key round-trip for EC2 P-256/384/521, OKP Ed25519/X25519, Symmetric, RSA, AKP | `TestKeyRoundTrip` | Yes |
| Oversize or short `x` → `ErrInvalidKey` | `TestKeyCoordinateLength` | Yes |
| Compressed EC2 point parses and matches uncompressed | `TestKeyCompressedPoint` | Yes |
| RFC 9679 thumbprint matches the RFC's example vector | `TestThumbprintRFC9679` | Yes |
| JWK ↔ COSE_Key round-trip for RFC 7517 Appendix A keys | `TestJWKInterop` | Yes |
| `KeySet.Lookup` by kid + alg + op | `TestKeySetLookup` | Yes |
| `VerifySign1` with `KeySetResolver` picks the right key by kid | `TestVerifyWithResolver` | Yes |
| `key_ops: [verify]` key cannot construct a Signer | `TestKeyOpsEnforced` | Yes |
| X5Chain accepts single-bstr and array forms | `TestX5ChainForms` | Yes |
| RFC 9360, 9596, 9597, 9679, 9921 vendored under `engineering-docs/rfcs/` | files present + README rows | Yes |
| mDL MSO vector (ISO 18013-5 Annex D) verifies | `TestMDLIssuerAuth` | No (license of the vector to be confirmed) |
| A v0.2.2-accepted COSE_Key with a 31-byte P-256 `x` fails `ParseKey` by default and parses with `AllowShortCoordinates()` to the same public key v0.2.2 produced | `TestParseKeyShortCoordinates` vs `testdata/legacy-v0.2.2/` | Yes |
| `(*Key).PublicKey` left-pads a 31-byte EC2 `x` exactly as v0.2.2 and rejects a 33-byte one; `ParseKey` rejects the 31-byte one unless `AllowShortCoordinates()` | `TestKeyCoordinatesLegacy`, `TestParseKeyCoordinates` | Yes |
| No exported identifier present in v0.2.2 is removed, renamed, or retyped, and no method is added to an exported interface (034 API stability) | `apidiff` against `v0.2.2` for this module, run in `make check` | Yes |
| Existing identifiers called with no new options reproduce the v0.2.2 golden vectors, except the contract-defect fixes listed under Compatibility selection | `testdata/legacy-v0.2.2/` golden tests | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | Header options, `Sign1(msg)`, detached, typed accessors, Ed25519 `crypto.Signer` | Done | header and detached rows green |
| 2 | COSE_Key parse/marshal/prefix, KeySet, key_ops, thumbprint, RSA verify, AKP parse | Done | key rows green |
| 3 | KeyResolver, `VerifySign1`, ContextSigner, JWK, RSA sign | Done | remaining rows green |

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestSignWithHeaders*` | header plumbing | `cose/sign_headers_test.go` |
| `TestKey*`, `TestKeySet*` | COSE_Key API | `cose/key_test.go` |
| `FuzzParseKey` | arbitrary bytes → `ParseKey` / `ParseKeyPrefix` never panic | `cose/fuzz_test.go` |
| WebAuthn and RFC 9679 vectors | interop | `cose/testdata/` |

---

## Performance

| Metric | Target | Test mechanism |
|---|---|---|
| `BenchmarkSign1ES256` with extra headers | protected bytes pre-encoded; ≤ baseline + 1 alloc | `go test -bench Sign1 ./cose` |
| `BenchmarkParseKeyEC2` | ≤ 10 allocs | new bench |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Callers trust unprotected `kid` or `x5chain` for key selection without verifying the chain | high | high | `KeyResolver` doc and the `Lookup` doc mark the unprotected bucket as hints; x5chain path validation is the caller's job (we expose DER only) |
| JWK interop drifts from JOSE fully-specified changes (RFC 9864) | med | low | track alongside 029; map polymorphic `EdDSA` to `crv` |
| RSA sign adds a large surface | low | med | Phase 3, verify-first |

---

## Alternatives considered

- **Generic `Headers.Get(label) any` only, no typed accessors.** This is
  the status quo, and it pushes RFC 9360's `bstr / [2* bstr]`
  normalization and the RFC 9596 `uint / tstr` union onto every consumer.
  Rejected.
- **x509 chain validation inside cose.** Rejected because trust anchors and
  policy are application concerns. We provide `CertHash.Matches` and the
  DER only.
- **A separate `cose/key` package.** Deferred. `Key` is used by
  signer/verifier constructors, and splitting it now would create an
  import cycle.

---

## Open questions

- Should `Signer` carry per-instance default headers *and* allow
  per-message headers? The proposal says yes: options set defaults and
  `Sign1(msg)` handles per-message headers.
- Should `KeyResolver` return `crypto.PublicKey` or `*Key`? Returning
  `*Key` keeps `alg` and `key_ops` visible to policy. Leaning towards
  `*Key`.
- Ed448 has no Go stdlib implementation (checked against Go 1.27.4 on
  2026-11-20). Do we take an x/crypto or third-party dependency, or leave
  it unsupported?

---

## Cross-references

- RFCs: RFC 9052 §3.1, §7; RFC 9053 §7; RFC 8230; RFC 9360; RFC 9596;
  RFC 9597; RFC 9679; RFC 9921; RFC 9964 (AKP); RFC 7517 / RFC 8037 (JWK);
  RFC 9943 (SCITT)
- Sibling proposals: 002, 011, 027, 029, 030, 031 (CWT; consumes
  `SetCWTClaims` / `CWTClaims`)
- External: IANA COSE registries (fetched 2026-11-20); W3C WebAuthn
  Level 3 §6.5; ISO/IEC 18013-5 §9.1.2

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
| 2026-11-20 | API stability (signature + semantics) per revised 034 | corecbor maintainers |
| 2026-11-21 | Phases 1–3 implemented (RSA signing, mDL vector, benchmarks remain); implementation notes; status In-Progress | corecbor maintainers |
| 2026-11-22 | Status: Closed (acceptance met) | corecbor maintainers |
