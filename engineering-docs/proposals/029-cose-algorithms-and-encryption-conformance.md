# 029 — COSE algorithm registry alignment and encryption conformance

## Header

| Field | Value |
|---|---|
| **Number** | 029 |
| **Tier** | 3 |
| **Status** | Draft |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 002, 027 (alg binding + policy), 028 (COSE_Key, AKP kty), 034 (compatibility policy) |
| **Supersedes** | none (corrects 002 Phase C/D identifiers) |
| **Spec sections touched** | none in `encoder-decoder-spec.md`; cose module contract only |

---

## TL;DR

The algorithm table in `cose/algorithm.go` predates four upstream changes:

- RFC 9864 (Oct 2025) deprecates the polymorphic `ES256`, `ES384`,
  `ES512` and `EdDSA` in favor of fully-specified identifiers.
- RFC 9964 (May 2026) registers ML-DSA.
- `draft-ietf-cose-hpke-27` (Waiting for AD Go-Ahead) fixes the HPKE
  layout.
- IANA now marks RFC 9459 AES-CTR and AES-CBC as Deprecated.

Separately, three of our encryption paths are not interoperable:

- ECDH-ES `-25` uses `-29` semantics.
- The PBES2 identifier collides with a registered algorithm.
- Encrypt0 makes the caller manage nonces and never transmits the IV.

This proposal aligns the identifiers with the registry and makes every
key-establishment path wire-compatible with RFC 9053. It also gates
draft-only identifiers behind an explicit `WithDraftHPKE27()` selector
(proposal 034, Draft class). Per 034, no exported constant changes
value and existing identifiers keep their semantics: `NewSigner` still
emits −7/−8 (fully-specified emission is the recommended opt-in), and
`HPKEKey`/`EncryptEncrypt0` keep their v0.2.2 formats as deprecated
identifiers. Where an existing identifier contradicts the RFC it names
(ECDH-ES −25, PBES2's colliding code points), it is fixed in place and
the v0.2 wire format stays reachable through a named, deprecated legacy
selector.

Acceptance: RFC 9052/9053 COSE WG example vectors decrypt and verify for
every supported algorithm, and IANA registry values are asserted by a
table test generated from the registry snapshot.

---

## Motivation

All registry values below were checked against the IANA COSE registry,
fetched 2026-11-20 (`https://www.iana.org/assignments/cose/cose.xml`).

### M1. Polymorphic signature identifiers only (RFC 9864)

`algorithm.go:11-20` defines only `EdDSA` (−8), `ES256` (−7), `ES384`
(−35) and `ES512` (−36). IANA now lists all four as **Deprecated** and
registers:

| Name | Value | Recommended |
|---|---|---|
| ESP256 | −9 | Yes |
| ESP384 | −51 | Yes |
| ESP512 | −52 | Yes |
| Ed25519 | −19 | Yes |
| Ed448 | −53 | Yes |
| ESB256 / ESB320 / ESB384 / ESB512 | −265 / −266 / −267 / −268 | No |

`algForPublicKey` (`sign.go:222-240`) maps a P-256 key to `ES256`, so we
can neither emit nor accept the new identifiers. WebAuthn relying parties
and SCITT issuers have started advertising `-9` and `-19`.

### M2. No post-quantum signatures (RFC 9964)

ML-DSA-44, ML-DSA-65 and ML-DSA-87 are −48, −49 and −50, all Recommended.
They use the new key type AKP (kty 7) with parameters `pub` (−1) and
`priv` (−2). `priv` is the 32-byte seed. The ML-DSA `ctx` MUST be empty.
The local Go 1.27.4 toolchain ships `crypto/mldsa` (`GenerateKey`,
`NewPrivateKey(params, seed)`, `Verify`), so this needs no third-party
dependency. See Open questions for the go-directive impact.

### M3. ECDH-ES is mislabeled and not RFC 9053 compatible

| Finding | Evidence |
|---|---|
| `ECDHESKey.Algorithm()` returns `-25` (ECDH-ES + HKDF-256, *direct* key agreement) | `ecdh_deriver.go:26` |
| `EncryptMulti` special-cases it and AES-KW-wraps the CEK under the derived key, which is `-29` (ECDH-ES + A128KW) semantics | `encrypt_multi.go:63-78` |
| `ECDHESKey.WrapKey` discards both `cek` and `derived` and returns a nil ciphertext, so `ComputeMACMulti` with an ECDH recipient yields a message whose verifier unwraps to the derived key rather than the CEK | `ecdh_deriver.go:53-63`, `mac_multi.go:66` |
| The ephemeral key header (−1) carries raw SEC1 point bytes; RFC 9053 §6.3.1 requires a COSE_Key map | `ecdh_deriver.go:59,131` |
| `COSE_KDF_Context` is wrong: PartyU and PartyV are encoded as bstr instead of `[identity, nonce, other]`, and SuppPubInfo omits the required `protected` bstr. The AlgorithmID for `-29` must be the key-wrap alg, not the content alg (RFC 9053 §5.2). | `ecdh_deriver.go:153-164` |
| No HKDF salt and no PartyU/PartyV header support (labels −20 to −26 registered) | `ecdh_deriver.go:53` passes nil salt |
| Only P-curves via `crypto/ecdh`; X25519 (OKP crv 4) is not wired up even though `CurveX25519` is declared | `key_types.go:36` |

### M4. PBES2 identifiers collide with registered values

PBES2 is a JOSE algorithm and is not registered in COSE at all.

- `AlgPBES2_HS256_A128KW = -11` (`algorithm.go:45`) is IANA's
  `direct+HKDF-SHA-512`.
- The iteration-count header label −21 (`pbes2_deriver.go:16`) is IANA's
  `PartyU identity`.

A standards-compliant peer would misinterpret every PBES2 message.
Proposal 002 originally specified −100 (002:304). That value is also
unassigned rather than private-use; the private-use range is < −65536.

### M5. HPKE does not follow `draft-ietf-cose-hpke-27`

Our implementation diverges from the draft:

- `AlgHPKEBaseP256SHA256AES128GCM` and `AlgHPKE_Base_P256_SHA256_AES128GCM`
  both define 35 (`algorithm.go:48`, `hpke_deriver.go:14`). `String()`
  returns `"unknown"` for it (`algorithm.go:86-88`).
- We use 35 as a **recipient (key-encryption)** algorithm. The draft
  assigns 35 to **HPKE-0 integrated encryption** (COSE_Encrypt0). The
  key-encryption variant is HPKE-0-KE (assumed 46).
- The draft carries the encapsulated key in the `ek` unprotected header
  (assumed label −4). We return `enc ‖ ct` as one blob from single-shot
  `hpke.Seal` (`hpke_deriver.go:41`).
- `info` is an ad-hoc string `"COSE-HPKE-CEK-%d"` (`hpke_deriver.go:40`).
  The draft uses the deterministic encoding of `Recipient_structure` for
  key encryption, and Enc_structure as `aad` for integrated mode.
- `psk_id` (assumed −5, protected) is not supported.

None of the HPKE values are in the IANA registry yet; the 2026-11-20
snapshot lists nothing above 34 in the positive range. Shipping them as if
final will create interop debt.

The stdlib `crypto/hpke` exposes `NewSender` and `NewRecipient`, which
return `enc` separately with an aad-capable `Seal`/`Open`. That gives us
everything the draft layout needs.

### M6. Encrypt0 nonce handling

`EncryptEncrypt0(plaintext, key, nonce, alg, …)` requires a caller nonce
and does not write the IV header (label 5) (`encrypt.go:24-57`).
`DecryptEncrypt0` likewise needs the nonce out of band (`encrypt.go:60`).
The result is not interoperable, and nonce reuse becomes the caller's
problem. `EncryptMulti` already generates a random nonce and writes label 5
(`encrypt_multi.go:46-50`). The two APIs are inconsistent.

### M7. Missing content algorithms needed by known consumers

- **AES-CCM (10–13, 30–33).** OSCORE and EDHOC suites 0–3 use
  AES-CCM-16-64-128 (alg 10). An implementation already exists at
  `edhoc/internal/aesccm`. Because `edhoc` imports `cose` (`edhoc/go.mod:7`),
  it can move to `cose/internal/aesccm` and be shared.
- **ChaCha20/Poly1305 (24).** Used by EDHOC suites 4 and 5. Go 1.27 does
  not export `crypto/chacha20poly1305` (it isn't in std), so this needs
  `golang.org/x/crypto`.
- **Partial IV (6) and Base IV (key param 5).** RFC 9052 §3.1 nonce
  construction from Partial IV XOR Base IV, which OSCORE uses.
- **RFC 9054 hash algorithms (−16 SHA-256, −43 SHA-384, −44 SHA-512, …).**
  Needed by 028 (`x5t`) and 030 (hash envelope).
- **RSA.** PS256–PS512 (−37 to −39) and RS256/RS384/RS512
  (−257 to −259, RFC 8812), for verification. Key type in 028.

### M8. Deprecated and draft algorithms to avoid

- RFC 9459 A128CTR–A256CBC (−65534 to −65529) are now **Deprecated** in
  IANA. Do not implement them.
- Watch items, with no implementation until they reach RFC:
  - `draft-ietf-cose-sphincs-plus-11` (SLH-DSA; IETF LC ends 2026-12-03)
  - `draft-ietf-cose-falcon-05`
  - `draft-ietf-cose-cmac-01`
  - `draft-ietf-cose-pqc-kem-00`
  - `draft-ietf-cose-hpke-pq-pqt-01`
  - `draft-ietf-jose-pq-composite-sigs-06`
  - `draft-ietf-cose-split-signing-algs-02`

---

## Proposal

### Public API surface

```go
// algorithm.go — registry-aligned constants (values from IANA 2026-11-20)
const (
	// RFC 9864 fully-specified
	AlgESP256  Algorithm = -9
	AlgESP384  Algorithm = -51
	AlgESP512  Algorithm = -52
	AlgEd25519 Algorithm = -19
	AlgEd448   Algorithm = -53 // constant only; see Open questions

	// RFC 9964
	AlgMLDSA44 Algorithm = -48
	AlgMLDSA65 Algorithm = -49
	AlgMLDSA87 Algorithm = -50

	// RFC 8230 / RFC 8812
	AlgPS256 Algorithm = -37
	AlgPS384 Algorithm = -38
	AlgPS512 Algorithm = -39
	AlgRS256 Algorithm = -257
	AlgRS384 Algorithm = -258
	AlgRS512 Algorithm = -259

	// RFC 9053 key agreement
	AlgECDH_ES_HKDF_512 Algorithm = -26
	AlgECDH_ES_A128KW   Algorithm = -29
	AlgECDH_ES_A192KW   Algorithm = -30
	AlgECDH_ES_A256KW   Algorithm = -31

	// RFC 9053 content
	AlgAESCCM_16_64_128  Algorithm = 10
	AlgAESCCM_16_64_256  Algorithm = 11
	AlgAESCCM_64_64_128  Algorithm = 12
	AlgAESCCM_64_64_256  Algorithm = 13
	AlgChaCha20Poly1305  Algorithm = 24
	AlgAESCCM_16_128_128 Algorithm = 30
	AlgAESCCM_16_128_256 Algorithm = 31
	AlgAESCCM_64_128_128 Algorithm = 32
	AlgAESCCM_64_128_256 Algorithm = 33

	// RFC 9054 hashes
	AlgSHA256 Algorithm = -16
	AlgSHA384 Algorithm = -43
	AlgSHA512 Algorithm = -44

	// PBES2 in the private-use range (PBES2 is not registered in COSE).
	// PBES2Key now emits this value.
	AlgPrivatePBES2_HS256_A128KW Algorithm = -65601
)

// Existing constants keep their names and values (proposal 034):
//
//   AlgES256 = -7, AlgES384 = -35, AlgES512 = -36, AlgEdDSA = -8
//     Deprecated: polymorphic identifiers, deprecated by RFC 9864; use
//     AlgESP256/AlgESP384/AlgESP512/AlgEd25519 and
//     WithFullySpecifiedAlgorithms. Still emitted by NewSigner by default
//     and still verified.
//
//   AlgPBES2_HS256_A128KW = -11
//     Deprecated: -11 is registered as direct+HKDF-SHA-512; use
//     AlgPrivatePBES2_HS256_A128KW. Emitted only under
//     WithLegacyPBES2Labels.
//
//   AlgHPKEBaseP256SHA256AES128GCM = 35, AlgHPKE_Base_P256_SHA256_AES128GCM = 35
//     Deprecated: corecbor's pre-draft HPKE key-encryption format; see
//     HPKEKey. Not related to draft-ietf-cose-hpke's HPKE-0.

// Deprecated reports whether IANA marks the algorithm Deprecated.
func (a Algorithm) Deprecated() bool
// FullySpecified returns the RFC 9864 replacement for a polymorphic alg
// given the key (ES256+P-256 → ESP256, EdDSA+Ed25519 → Ed25519).
func FullySpecified(a Algorithm, pub crypto.PublicKey) (Algorithm, bool)

// Signer emits fully-specified identifiers when asked.
func WithFullySpecifiedAlgorithms() SignerOption

// Encrypt0: IV generated and carried in header 5 by default.
func Encrypt0Seal(plaintext, key []byte, alg Algorithm, opts ...EncryptOption) (*Encrypt0, error)
func Encrypt0Open(msg *Encrypt0, key []byte, opts ...EncryptOption) ([]byte, error)
func WithNonce(nonce []byte) EncryptOption               // tests / deterministic vectors only
func WithPartialIV(baseIV, partialIV []byte) EncryptOption // RFC 9052 §3.1 construction

// ECDH-ES, RFC 9053 §6.3 conformant.
type PartyInfo struct {
	Identity []byte
	Nonce    []byte
	Other    []byte
}
// ECDHESKey keeps its v0.2.2 fields; the new ones are appended and their
// zero values select RFC 9053 behavior for the algorithm its name and
// Algorithm() already claim (-25, ECDH-ES + HKDF-256, direct).
type ECDHESKey struct {
	Alg        Algorithm // zero → -25; or -26, -29, -30, -31
	PrivateKey *ecdh.PrivateKey
	PeerPublic *ecdh.PublicKey
	PartyU     PartyInfo
	PartyV     PartyInfo
	Salt       []byte
}

// HPKE (draft-ietf-cose-hpke-27). Every HPKE entry point below returns
// ErrUnsupportedAlgorithm unless WithDraftHPKE27() is passed.
//
// WithDraftHPKE27 is Experimental: it implements draft-ietf-cose-hpke-27.
// Code points are assigned by IANA on publication and WILL change; the
// selector is renamed (not aliased) then, per proposal 034.
func WithDraftHPKE27() EncryptOption

// WithLegacyPBES2Labels uses the v0.2 PBES2 identifiers (alg -11,
// iteration-count label -21) for both seal and open. Both collide with
// registered COSE values.
//
// Deprecated: colliding code points; removed no earlier than v0.32.0.
func WithLegacyPBES2Labels() EncryptOption

// WithLegacyECDHES accepts the v0.2 ECDH-ES encoding: -25 carrying
// -29 (AES-KW) semantics and a raw-point ephemeral key in label -1.
//
// Deprecated: non-conformant to RFC 9053 §6.3; removed no earlier than v0.32.0.
func WithLegacyECDHES() EncryptOption

// CompatV02Encryption bundles WithLegacyPBES2Labels and WithLegacyECDHES.
//
// Deprecated: migrate to explicit selectors; removed no earlier than v0.32.0.
func CompatV02Encryption() EncryptOption

// HPKEKey (v0.2.2) is unchanged: it keeps producing and reading
// corecbor's pre-draft format (alg 35 as a recipient algorithm, ad-hoc
// info string), which only corecbor understands.
//
// Deprecated: non-interoperable; use HPKERecipient with WithDraftHPKE27
// (and its RFC successor once published).
type HPKEKey struct{ /* unchanged */ }

type HPKESuite int // HPKE-0 … HPKE-7
func HPKESeal(plaintext []byte, recipient *Key, suite HPKESuite, opts ...EncryptOption) (*Encrypt0, error)
func HPKEOpen(msg *Encrypt0, recipient *Key, opts ...EncryptOption) ([]byte, error)
type HPKERecipient struct { // key-encryption mode for COSE_Encrypt
	Suite      HPKESuite
	PublicKey  *Key
	PrivateKey *Key
	PSK, PSKID []byte
	ExtraInfo  []byte // recipient_extra_info (not transmitted)
}
```

`EncryptEncrypt0` and `DecryptEncrypt0` keep their v0.2.2 signatures and
behavior (caller-supplied nonce, no label 5 written), per proposal 034.
They are marked `// Deprecated:` in favor of `Encrypt0Seal`/`Encrypt0Open`
and keep working for the life of the v0.x line.

### Behavior

1. **Fully-specified algorithms (RFC 9864).**
   - **Verify** accepts both families. ESP256 requires a P-256 key and
     SHA-256, and so on. A polymorphic `ES256` is accepted only with a
     P-256 key, which matches current behavior. The allow-list from 027
     applies to both.
   - **Sign.** `NewSigner` keeps emitting the polymorphic identifiers it
     documents today (−7/−8), per proposal 034: existing identifiers
     keep their semantics. The current-standards path is
     `WithFullySpecifiedAlgorithms()`, which emits RFC 9864 identifiers
     and is the recommended option in `NewSigner`'s godoc. The
     polymorphic constants are marked `// Deprecated:` (see constants
     above). Callers that need −7/−8 for WebAuthn/mDL peers keep the
     default.
2. **ML-DSA.**
   - Signs the ToBeSigned bytes directly with an empty context.
   - AKP keys come from 028.
   - A signer built from a seed validates that its public key matches the
     `pub` parameter when both are present.
3. **ECDH-ES.**
   - `-25`/`-26` are direct key agreement: the derived key is the CEK, the
     recipient ciphertext is empty, and the recipient must be the only
     one (RFC 9052 §8.5.4).
   - `-29`/`-30`/`-31` derive a KEK and AES-KW-wrap the CEK.
   - Ephemeral key: `-1` is encoded as COSE_Key with
     `{1: kty, -1: crv, -2: x, -3: y}`, and EC2 points may be compressed
     (RFC 9053 §6.3.1).
   - KDF context: `COSE_KDF_Context` is built per RFC 9053 §5.2, with the
     recipient protected bstr in SuppPubInfo.
   - The `EncryptMulti`/`DecryptMulti` special case
     (`encrypt_multi.go:63-78,113-121`) is deleted from the default path.
     Its wire format stays readable under `WithLegacyECDHES()`. Dispatch goes only
     through `KeyDeriver`, using a new optional interface:
     ```go
     type KeyAgreer interface { AgreeKey(opts KeyWrapOpts) (cek []byte, h Headers, err error) }
     ```
4. **PBES2.**
   - Moves to a private-use identifier (`< -65536`).
   - The iteration count moves to a private-use header label, also
     `< -65536`.
   - `PBES2Key.Algorithm()` returns `AlgPrivatePBES2_HS256_A128KW`. The
     old −11/−21 pair is used (seal) and recognized (open) only under
     `WithLegacyPBES2Labels()`. Without it, the pair is rejected, because
     −11 means `direct+HKDF-SHA-512` to everyone else. The
     `AlgPBES2_HS256_A128KW` constant keeps the value −11 and is
     deprecated.
   - The bounds from 027 H8 apply.
5. **HPKE.**
   - The implementation follows draft-27 exactly:
     - Integrated mode uses COSE_Encrypt0, the `ek` header, and
       Enc_structure as aad.
     - Key-encryption mode uses the `Recipient_structure` info and an
       empty aad.
   - It is reachable only with `WithDraftHPKE27()` until IANA assigns
     values. Then the selector is renamed, the values are pinned, and the
     RFC behavior becomes the default per proposal 034.
   - The existing `HPKEKey` (35-as-recipient) keeps its v0.2.2 format and
     is deprecated. The draft-27 implementation lives in new identifiers
     (`HPKERecipient`, `HPKESeal`, `HPKEOpen`), so no legacy selector is
     needed.
6. **Encrypt0** (new `Encrypt0Seal`/`Encrypt0Open` only; the existing
   functions are unchanged).
   - The nonce defaults to `crypto/rand`, sized for the AEAD.
   - The nonce is written to unprotected label 5. `Encrypt0Open` reads
     label 5, or reconstructs the nonce from label 6 plus a Base IV.
   - Supplying both 5 and 6 is rejected (RFC 9052 §3.1).
   - `Encrypt0Open` reads `alg` from the protected bucket under the 027
     policy.
7. **AES-CCM / ChaCha20-Poly1305.**
   - AES-CCM: move `edhoc/internal/aesccm` to `cose/internal/aesccm`, and
     have edhoc consume `cose` AEADs (see the EDHOC proposal).
   - ChaCha20/Poly1305 requires a `golang.org/x/crypto` dependency, the
     cose module's first non-std dependency. See Open questions.

### Failure modes

No new sentinels. Existing sentinels in new cases:

- `ErrUnsupportedAlgorithm`:
  - a Deprecated RFC 9459 algorithm;
  - a draft-27 HPKE id without `WithDraftHPKE27()`;
  - legacy PBES2 (−11/−21) without `WithLegacyPBES2Labels()`;
  - raw-point ECDH-ES ephemeral key without `WithLegacyECDHES()`.
- `ErrMalformed`:
  - a raw-bytes ephemeral key;
  - both IV and Partial IV present.
- `ErrInvalidKey`: ESP256 used with a non-P-256 key.

---

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).
No exported constant changes value and no exported identifier changes
signature. `ECDHESKey` gains fields whose zero values select the RFC
behavior its existing name claims.

| Change | Class | Contract restored | Existing identifiers in v0.30 | Selector |
|---|---|---|---|---|
| Polymorphic `-7`/`-8` emission | Superseded contract (RFC 9864) | — | `NewSigner` emits `-7`/`-8` as in v0.2.2; `AlgES256`/`AlgES384`/`AlgES512`/`AlgEdDSA` deprecated; verify accepts both families | `WithFullySpecifiedAlgorithms() SignerOption` (recommended), `AlgESP256`, `AlgESP384`, `AlgESP512`, `AlgEd25519` |
| ML-DSA, RSA/PS, AES-CCM, ChaCha20-Poly1305, SHA-2 constants | Additive | — | n/a | n/a |
| `ECDHESKey` (−25) performs direct key agreement; `-29..-31` KEK + AES-KW; COSE_Key ephemeral | Contract defect | `AlgECDH_ES_HKDF_256 = -25` and `ECDHESKey.Algorithm()` (`ecdh_deriver.go:26`) claim RFC 9053 §6.3 −25 (direct), but v0.2.2 did AES-KW (−29 semantics) with a raw-point ephemeral key | RFC 9053 | `func WithLegacyECDHES() EncryptOption` — Deprecated |
| ECDH-ES MAC recipient (`WrapKey` returned nil) | Safety defect (message nobody can verify) | — | works | none |
| `PBES2Key` emits a private-use alg and iteration-count label | Contract defect | RFC 9053 / IANA registry: −11 and −21 are registered with other meanings | `AlgPBES2_HS256_A128KW` keeps −11 and is deprecated; `AlgPrivatePBES2_HS256_A128KW` = −65601 | `func WithLegacyPBES2Labels() EncryptOption` — Deprecated (seal + open) |
| HPKE per draft-ietf-cose-hpke-27 | Draft | — | n/a | `WithDraftHPKE27() EncryptOption` — Experimental, on new `HPKERecipient`/`HPKESeal`/`HPKEOpen` |
| v0.2 HPKE format (`HPKEKey`, alg 35 as recipient) | Superseded contract | — | `HPKEKey` unchanged and deprecated; both alg-35 constants deprecated | new HPKE identifiers above |
| Encrypt0 random IV in label 5; Partial IV; 5+6 rejected | Additive (new `Encrypt0Seal`/`Encrypt0Open`) | — | `EncryptEncrypt0`/`DecryptEncrypt0` unchanged (caller nonce, no label 5) and deprecated | `Encrypt0Seal`/`Encrypt0Open` (recommended) |
| `KeyAgreer` optional interface | Additive (new interface; `KeyDeriver` unchanged) | — | n/a | n/a |
| Ed448 / X448 / RFC 9459 | not implemented | — | n/a | n/a |

Bundle: `cose.CompatV02Encryption() EncryptOption` = `WithLegacyPBES2Labels()`
+ `WithLegacyECDHES()`. These are interop-only, so they're eligible for
bundling under 027's rule. `WithFullySpecifiedAlgorithms()` is not a
legacy selector and is never bundled. No `...Option` parameters are
appended to existing functions.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| Every `Algorithm` constant equals the IANA value in `cose/testdata/iana-cose-2026-11-20.xml` | generated table test `TestAlgorithmRegistry` | Yes |
| `String()` covers every constant; no duplicate values | `TestAlgorithmString` | Yes |
| ESP256/384/512, Ed25519 sign and verify; ESP256 with P-384 key → `ErrInvalidKey` | `TestFullySpecified*` | Yes |
| Polymorphic ES256/EdDSA vectors from cose-wg/Examples still verify | `TestCOSEWGSign1Vectors` | Yes |
| ML-DSA-44/65/87 round-trip; RFC 9964 Appendix examples verify | `TestMLDSA*` | Yes |
| cose-wg/Examples `ecdh-direct-examples` (-25) and `ecdh-wrap-examples` (-29) decrypt | `TestCOSEWGECDH*` | Yes |
| Ephemeral key emitted as COSE_Key map; raw-bytes form rejected | `TestECDHEphemeralCOSEKey` | Yes |
| `ComputeMACMulti` with ECDH-ES+A128KW recipient verifies | `TestMACMultiECDH` | Yes |
| PBES2 default ids are in private-use range; −11 without `WithLegacyPBES2Labels` rejected | `TestPBES2Identifiers` | Yes |
| HPKE draft-27 test vectors (Appendix) pass with `WithDraftHPKE27()`; without it every HPKE entry point returns `ErrUnsupportedAlgorithm` | `TestHPKEDraft27`, `TestHPKERequiresDraftSelector` | Yes |
| `Encrypt0Seal` writes label 5; two seals of the same plaintext differ; `Encrypt0Open` needs no nonce argument | `TestEncrypt0IV` | Yes |
| Partial IV + Base IV reconstructs the OSCORE nonce (RFC 8613 §5.2 vector) | `TestPartialIV` | Yes |
| AES-CCM-16-64-128 matches RFC 9053 / cose-wg vectors; edhoc tests still pass after the move | `TestAESCCM*`, `cd edhoc && go test ./...` | Yes |
| RFC 9053, 9864, 9964 vendored under `engineering-docs/rfcs/` | files + README rows | Yes |
| Default signer emits `-7` for P-256 and `-8` for Ed25519 keys; `WithFullySpecifiedAlgorithms()` emits `-9`/`-19`; verify accepts all four | `TestCompatAlgorithmEmission` | Yes |
| v0.2.2-produced PBES2 and ECDH-ES (`-25`) messages decrypt only under `WithLegacyPBES2Labels()` / `WithLegacyECDHES()` respectively, and under `CompatV02Encryption()`; v0.2.2 HPKE (alg 35) messages decrypt with `HPKEKey` and no selector | `TestCompatLegacyEncryption*` vs `testdata/legacy-v0.2.2/` | Yes |
| Legacy selectors and `CompatV02Encryption` carry `// Deprecated:` with removal floor v0.32.0; `WithDraftHPKE27` carries `Experimental:` naming draft-ietf-cose-hpke-27 | staticcheck SA1019 fixture + doc review | Yes |
| No exported identifier present in v0.2.2 is removed, renamed, or retyped, and no method is added to an exported interface (034 API stability) | `apidiff` against `v0.2.2` for this module, run in `make check` | Yes |
| Existing identifiers called with no new options reproduce the v0.2.2 golden vectors, except the contract-defect fixes listed under Compatibility selection | `testdata/legacy-v0.2.2/` golden tests | Yes |
| `NewSigner` with no options emits `-7` for P-256 and `-8` for Ed25519 (v0.2.2 bytes); with `WithFullySpecifiedAlgorithms()` it emits `-9` / `-19` | `TestSignerAlgEmissionDefault`, `TestSignerFullySpecified` | Yes |
| `AlgPBES2_HS256_A128KW == -11` and both alg-35 constants still equal 35 | `TestConstantsFrozen` | Yes |
| `HPKEKey` and `EncryptEncrypt0` reproduce v0.2.2 golden messages | golden tests | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | Registry constants, `String`, `Deprecated`, RFC 9864 verify + opt-in emit, PBES2 renumber | Pending | registry + RFC 9864 rows green |
| 2 | ECDH-ES rewrite (-25/-26/-29/-30/-31), Encrypt0 IV, Partial IV | Pending | ECDH + IV rows green |
| 3 | AES-CCM move, ChaCha20-Poly1305, RFC 9054 hashes, RSA verify | Pending | content-alg rows green |
| 4 | ML-DSA | Pending | ML-DSA rows green |
| 5 | HPKE draft-27 behind tag; pin on RFC publication | Pending | HPKE row green; then retag |

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestAlgorithmRegistry` | constants vs IANA snapshot | `cose/algorithm_test.go` |
| `TestCOSEWG*` | interop vectors (github.com/cose-wg/Examples, vendored JSON) | `cose/interop_test.go`, `cose/testdata/cose-wg/` |
| `FuzzEncrypt0Open` | adversarial Encrypt0 → typed error | `cose/fuzz_test.go` |
| `FuzzECDHRecipient` | adversarial ephemeral key header | same |

---

## Performance

| Metric | Target | Test mechanism |
|---|---|---|
| `BenchmarkSign1ES256` vs `ESP256` | identical within noise | `go test -bench Sign1 ./cose` |
| `BenchmarkEncrypt0Seal` | ≤ current `EncryptEncrypt0` + 1 alloc (IV) | new bench |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| HPKE values change before RFC | med | med | `WithDraftHPKE27()` selector named per revision; pinned test vectors per draft revision |
| Callers keep using deprecated `HPKEKey` and never interoperate | med | low | Deprecation pointer to `HPKERecipient`; migration notes |
| `x/crypto` dependency for ChaCha20 is unwelcome in cose | med | low | isolate in `cose/chacha` subpackage, or defer until EDHOC suites 4/5 are needed |
| ML-DSA requires a newer `go` directive than 1.26.0 | med | med | build-tagged file `mldsa_go127.go`; see Open questions |
| `NewSigner` keeps emitting deprecated ids by default | high | low | Superseded contract under 034: `NewSigner` godoc and staticcheck SA1019 on `AlgES256`/`AlgEdDSA` steer callers to `WithFullySpecifiedAlgorithms()`; changing `NewSigner`'s default would be a semantic break |

---

## Alternatives considered

- **Emit fully-specified identifiers by default now.** Rejected for this
  release: WebAuthn authenticators and many verifiers still list only
  −7/−8, and verifier-side acceptance is the interop-critical half.
- **Keep PBES2 at −11 for compatibility.** Rejected, because −11 is
  registered as `direct+HKDF-SHA-512`. Any compliant peer would misparse.
- **Implement RFC 9459 CTR/CBC for completeness.** Rejected: IANA lists
  them as Deprecated, and they are unauthenticated.
- **Wrap `crypto/hpke` single-shot `Seal`.** This is what we do today. It
  cannot produce the draft's `ek` header or the aad binding, so it was
  rejected in favor of `NewSender`/`NewRecipient`.

---

## Open questions

- Does `crypto/mldsa` exist at the module's `go 1.26.0` directive? It was
  confirmed present in the Go 1.27.4 toolchain on 2026-11-20. If it is
  1.27+, either bump the cose `go` directive or use a build-tagged file.
- Ed448 and X448 have no stdlib implementation. Options: take a
  dependency, or register the constants and return
  `ErrUnsupportedAlgorithm`. Recommendation: constants only.
- At v1.0 (a major version, where 034's semantic-stability rule allows
  it), should `NewSigner`'s default flip to fully-specified identifiers?
- Should PBES2 stay in this module at all, given it is not a COSE
  algorithm? An alternative is moving it to `cose/x/pbes2`.

---

## Cross-references

- RFCs:
  - RFC 9052 §3.1 (IV, Partial IV), §8.5
  - RFC 9053 §5.2 (COSE_KDF_Context), §6.3, §7 (keys)
  - RFC 9054; RFC 9864; RFC 9964
  - RFC 8230 / RFC 8812 (RSA)
  - RFC 9459 (deprecated)
  - RFC 8613 §5.2 (OSCORE nonce)
- Drafts:
  - `draft-ietf-cose-hpke-27`
  - `draft-ietf-cose-sphincs-plus-11`
  - `draft-ietf-cose-falcon-05`
  - `draft-ietf-cose-cmac-01`
  - `draft-ietf-cose-pqc-kem-00`
  - `draft-ietf-cose-hpke-pq-pqt-01`
  - `draft-ietf-jose-pq-composite-sigs-06`
  - `draft-ietf-cose-split-signing-algs-02`
- Sibling proposals: 002, 027, 028, 030, EDHOC conformance proposal
  (AEAD sharing)
- External: IANA COSE registries (fetched 2026-11-20); cose-wg/Examples

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
| 2026-11-20 | API stability (signature + semantics) per revised 034 | corecbor maintainers |
