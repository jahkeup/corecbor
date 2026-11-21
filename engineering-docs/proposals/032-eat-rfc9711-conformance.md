# 032 — EAT: RFC 9711 conformance

## Header

| Field | Value |
|---|---|
| **Number** | 032 |
| **Tier** | 3 |
| **Status** | Draft |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 005 (EAT), 031 (CWT hardening), 022 (raw-byte preservation), 027 (COSE verification hardening), 034 (compatibility policy) |
| **Supersedes** | none (amends 005) |
| **Spec sections touched** | none — sibling module `eat/` |

---

## TL;DR

The `eat` module uses **draft-era claim keys** that don't match the
IANA CWT registry RFC 9711 populated. Four of its claim numbers belong
to different claims:

| Code key | Code reads it as | IANA meaning |
|---|---|---|
| 261 | security level (no longer in RFC 9711) | `uptime` |
| 266 | uptime | `submods` |
| 267 | software components | `bootcount` |
| 268 | submods | `bootseed` |

As a result, a conformant token carrying `submods`, `bootcount` or
`bootseed` either fails to decode or is misread. Tokens produced by
this module are misread by every other implementation.

There are three other problems:

- Nested submodule tokens are appraised **without signature
  verification** when no verifier is configured.
- Unknown claims, plus `cnf` and private claims, are dropped on decode.
- Several RFC 9711 value constraints aren't enforced: nonce length,
  UEID type and length, the `dbgstat` range, and the `eat_profile` OID
  form.

This proposal renumbers to the registry, adds the missing claims, makes
submodule appraisal fail closed, and preserves unknown claims. Per
proposal 034 (Conformance class), the RFC 9711 numbering is the default
and the v0.2 numbering stays selectable through the deprecated
`WithLegacyDraftClaimKeys()`. Selection is always explicit and never
auto-detected. It also
moves the PSA-shaped software-components structure to an `eat/psa`
package under its real claim key, 2399 (RFC 9783).

Acceptance:

- Golden tests decode the RFC 9711 Appendix A examples, corrected per
  the verified errata.
- Golden tests decode an RFC 9783 PSA token example.
- An unverified nested submodule makes `Appraise` fail.
- Unknown claims round-trip byte-for-byte.

---

## Motivation

### Claim-key mismatch (confirmed)

`eat/claims.go:14-24`, compared with the IANA "CBOR Web Token (CWT)
Claims" registry (fetched 2026-11-20, registry updated 2026-11-13):

| Key | Code constant | IANA (RFC 9711) | Status |
|---|---|---|---|
| 10 | `claimNonce` | Nonce (`eat_nonce`) | ✓ |
| 256 | `claimUEID` | UEID | ✓ |
| 257 | — | SUEIDs | missing |
| 258 | `claimOEMId` | Hardware OEM ID | ✓ (type rules incomplete) |
| 259 | — | Hardware Model | missing |
| 260 | — | Hardware Version | missing |
| 261 | `claimSecurityLevel` | **Uptime** | **wrong** |
| 262 | `claimSecureBoot` | OEM Authorized Boot (`oemboot`) | key ✓, name stale |
| 263 | `claimDebug` | Debug Status (`dbgstat`) | ✓ (value 4 missing) |
| 264 | — | Location | missing |
| 265 | `claimProfile` | EAT Profile | key ✓ (OID form rejected) |
| 266 | `claimUptime` | **Submodules** | **wrong** |
| 267 | `claimSWComponents` | **Boot Count** | **wrong** |
| 268 | `claimSubmods` | **Boot Seed** | **wrong** |
| 269 | — | DLOAs | missing |
| 270 | — | Software Name | missing |
| 271 | — | Software Version | missing |
| 272 | — | Software Manifests | missing |
| 273 | — | Measurements | missing |
| 274 | — | Software Measurement Results | missing |
| 275 | — | Intended Use | missing |

### What "SWComponents" actually is

The software-component map keys in the code are 1 = type, 2 =
measurement value, 4 = version, 5 = signer ID, 6 = measurement
description (`eat/claims.go:26-30`, `:53-60`). That is the shape of
**PSA software components** (RFC 9783, claim **2399**
`psa-software-components`). RFC 9711 has no such claim. Its equivalent
role is split between `measurements` (273, a list of
`[content-type, bstr]` pairs, which can carry RFC 10013 measured
components) and `manifests` (272).

So the struct isn't wrong, it is misplaced. The "security level" claim
(code key 261) is the draft-era `security-level`, which RFC 9711 dropped.
Its closest successors are PSA's `psa-security-lifecycle` (2395) and
EAT's `dloas`.

### Other confirmed defects

| # | Defect | Evidence |
|---|---|---|
| 1 | **Submodules fail open.** With `SubmodVerifier == nil`, a nested token is `UnmarshalSign1`'d and its payload decoded **without signature verification**, then handed to `SubmodPolicy` as trusted. | `eat/appraiser.go:83-91` |
| 2 | **Submodule forms are missing.** Detached-digest submodules (array form, RFC 9711 §4.2.18) are rejected, and so are JSON-encoded nested tokens. | `eat/claims.go:380-396` |
| 3 | **Claims are lost on decode.** Non-integer claim keys are skipped, unknown integer claims are silently dropped, and `cnf` (8) / `Private` from the embedded `cwt.ClaimsSet` are never decoded or encoded. | `eat/claims.go:216-220`, `:222-399` (no `default:` case), `:89-199` |
| 4 | **`dbgstat` is ambiguous and incomplete.** `Debug == 0` ("enabled") is omitted on encode, so it can't be told apart from absent. Value 4 (`disabled-fully-and-permanently`) is undefined. `RequireDebugDisabled` rejects only `== 0`, so unknown values such as 99 pass. | `eat/claims.go:43-51`, `:137`; `eat/appraiser.go:48-52` |
| 5 | **Nonce constraints aren't enforced.** RFC 9711 §4.1 requires each nonce to be 8–64 bytes (CBOR). The code accepts any length, and `Appraiser` has no "nonce required" mode beyond equality. | `eat/claims.go:404-421`, `eat/appraiser.go:30-34` |
| 6 | **UEID isn't validated.** RFC 9711 §4.2.1 requires a first type byte of 0x01 RAND, 0x02 EUI or 0x03 IMEI, and a total length of 7–33. The code accepts any bstr. | `eat/claims.go:275-281` |
| 7 | **`eat_profile` is text only.** RFC 9711 §4.3.2 allows a URI (text) or an OID (bstr). | `eat/claims.go:315-321` |
| 8 | **Numeric dates are broken in both directions.** Encode wraps pre-1970 times (`Uint(uint64(t.Unix()))`). Decode has no float support and uses an unchecked `int64` cast. | `eat/claims.go:101-108`, `:443-452` |
| 9 | **Underlying errors are flattened with `%v`.** | `eat/claims.go:206`, `:272`, `:387`, `:391`; `eat/token.go:31`; `eat/appraiser.go:88` |
| 10 | **Submodule appraisal order varies.** It iterates a Go map, so which failure gets reported differs between runs. | `eat/appraiser.go:79` |
| 11 | **Decoding is lenient.** It accepts duplicate claims (last wins) and sets no budget. | `eat/claims.go:203` |
| 12 | **Inline submodules lose their original bytes.** They are re-encoded before recursive decode, so the original bytes can't be used for digest comparison. | `eat/claims.go:384-389` |

### Consumers

- **RATS verifiers and relying parties (RFC 9334).** They must decode
  conformant tokens from any attester.
- **PSA / Arm CCA (RFC 9783; `draft-ffm-rats-cca-token`).** These
  carry PSA claims 2394–2400 alongside EAT claims.
- **EAR producers (`draft-ietf-rats-ear`).** They emit EAT-shaped
  attestation results.
- **EDHOC remote attestation (`draft-ietf-lake-ra`).** It carries EAT
  inside EDHOC EAD items.

---

## Proposal

### Public API surface

```go
// Registered EAT claim keys (RFC 9711 §10.2 / IANA CWT Claims).
const (
	ClaimNonce        int64 = 10
	ClaimUEID         int64 = 256
	ClaimSUEIDs       int64 = 257
	ClaimOEMID        int64 = 258
	ClaimHWModel      int64 = 259
	ClaimHWVersion    int64 = 260
	ClaimUptime       int64 = 261
	ClaimOEMBoot      int64 = 262
	ClaimDbgStat      int64 = 263
	ClaimLocation     int64 = 264
	ClaimProfile      int64 = 265
	ClaimSubmods      int64 = 266
	ClaimBootCount    int64 = 267
	ClaimBootSeed     int64 = 268
	ClaimDLOAs        int64 = 269
	ClaimSWName       int64 = 270
	ClaimSWVersion    int64 = 271
	ClaimManifests    int64 = 272
	ClaimMeasurements int64 = 273
	ClaimMeasRes      int64 = 274
	ClaimIntUse       int64 = 275
)

type Claims struct {
	cwt.ClaimsSet // decoded and encoded via cwt (proposal 031), incl. cnf + Private

	Nonce        [][]byte          // 10; each 8..64 bytes
	UEID         UEID              // 256
	SUEIDs       map[string]UEID   // 257
	OEMID        OEMID             // 258
	HWModel      []byte            // 259
	HWVersion    *Version          // 260
	Uptime       *uint64           // 261, seconds
	OEMBoot      *bool             // 262 (was SecureBoot)
	DbgStat      *DebugStatus      // 263; nil = absent (was DebugStatus, 0 = absent)
	Location     *Location         // 264
	Profile      *Profile          // 265
	Submods      map[string]Submod // 266
	BootCount    *uint64           // 267
	BootSeed     []byte            // 268
	DLOAs        []DLOA            // 269
	SWName       string            // 270
	SWVersion    *Version          // 271
	Manifests    []TypedBytes      // 272: [content-format, bstr]
	Measurements []TypedBytes      // 273: [content-format, bstr]
	MeasRes      []MeasResGroup    // 274
	IntUse       *IntendedUse      // 275
}

// UEID is a Universal Entity ID (RFC 9711 §4.2.1).
type UEID []byte

type UEIDType uint8

const (
	UEIDTypeRAND UEIDType = 0x01
	UEIDTypeEUI  UEIDType = 0x02
	UEIDTypeIMEI UEIDType = 0x03
)

func (u UEID) Type() UEIDType
func (u UEID) Validate() error // type byte + length 7..33

type DebugStatus uint8

const (
	DebugEnabled                     DebugStatus = 0
	DebugDisabled                    DebugStatus = 1
	DebugDisabledSinceBoot           DebugStatus = 2
	DebugDisabledPermanently         DebugStatus = 3
	DebugDisabledFullyAndPermanently DebugStatus = 4
)

// Profile is eat_profile: a URI or an OID (RFC 9711 §4.3.2).
type Profile struct {
	URI string
	OID []byte // DER-encoded OID content octets, no tag/length
}

// TypedBytes is a [content-format, bstr] pair used by manifests
// and measurements. CoAP content-format numbers are integers;
// media-type strings are text.
type TypedBytes struct {
	ContentFormat *uint64
	MediaType     string
	Value         []byte
}

// Submod is one entry of the submods claim (RFC 9711 §4.2.18).
// Exactly one of Claims, Token, or Detached is set.
type Submod struct {
	Claims   *Claims          // inline Claims-Set
	Token    []byte           // nested CBOR token (COSE-protected EAT), raw bytes
	JSON     []byte           // nested JSON token (opaque; not decoded here)
	Detached *DetachedDigest  // [hash-alg, digest]
}

type DetachedDigest struct {
	Alg    cose.Algorithm // hash alg (RFC 9054 identifiers)
	Digest []byte
}
```

#### Unknown claims

Any claim this package doesn't model stays in the embedded
`cwt.ClaimsSet.Private`, as `map[cwt.ClaimKey]corecbor.Value` per
proposal 031. That covers PSA claims when `eat/psa` isn't used,
`cmw` (299), and vendor claims. Encode writes them back out.
`DecodeClaims` → `Encode` is byte-identical for a deterministic input,
which `TestRoundTrip_Unknown` checks.

#### Appraiser (fail closed)

```go
type Appraiser struct {
	// Freshness
	RequireNonce []byte // constant-time compare; MUST be 8..64 bytes
	NonceVerifier func(nonces [][]byte) error

	RequireOEMBoot       bool
	MinDebugStatus       *DebugStatus // replaces RequireDebugDisabled; unknown values fail
	RequireProfile       *Profile
	CWTValidator         *cwt.Validator // nil: cwt.DefaultValidator() (proposal 031)

	// Submodules. When the token contains a nested Token submodule
	// and SubmodVerify is nil, Appraise returns ErrSubmodUnverified.
	SubmodVerify   func(ctx context.Context, name string, token []byte) (*Claims, error)
	SubmodDetached func(ctx context.Context, name string, d DetachedDigest) error
	SubmodPolicy   func(name string, claims *Claims) error

	MeasurementPolicy func(ms []TypedBytes) error
	Custom            []func(*Claims) error
}

func (a *Appraiser) Appraise(ctx context.Context, claims *Claims) error
```

Changes from today:

- A nested `Token` submodule without `SubmodVerify` → `ErrSubmodUnverified`.
- Submodules are visited in sorted name order.
- `SecurityLevel` is removed and `RequireSecurityLevel` is deleted.
  Callers who need lifecycle policy use `eat/psa`.
- The nonce compare uses `crypto/subtle.ConstantTimeCompare`. The nonce
  isn't secret, but this costs nothing and removes a review question.

#### `eat/psa` subpackage (RFC 9783)

```go
package psa

const (
	ClaimClientID                 int64 = 2394
	ClaimSecurityLifecycle        int64 = 2395
	ClaimImplementationID         int64 = 2396
	ClaimCertificationReference   int64 = 2398
	ClaimSoftwareComponents       int64 = 2399
	ClaimVerificationServiceIndic int64 = 2400
)

// SoftwareComponent is the RFC 9783 psa-software-components entry
// (the struct currently misfiled as eat.SWComponent).
type SoftwareComponent struct {
	MeasurementType  string // 1
	MeasurementValue []byte // 2
	Version          string // 4
	SignerID         []byte // 5
	MeasurementDesc  string // 6
}

type Claims struct {
	*eat.Claims
	ClientID              int64
	SecurityLifecycle     uint16
	ImplementationID      []byte
	CertificationRef      string
	SoftwareComponents    []SoftwareComponent
	VerificationService   string
}

func FromEAT(c *eat.Claims) (*Claims, error) // lifts PSA claims out of Private
```

`psa` lives inside the `eat` module (no new `go.mod`).

#### Detached EAT bundle and media types

```go
const TagDetachedEATBundle uint64 = 602 // RFC 9711 §5

type DetachedBundle struct {
	Token    []byte            // signed EAT (CBOR) carrying DetachedDigest submods
	Detached map[string][]byte // claims-set bytes, keyed by submod name
}

func DecodeDetachedBundle(data []byte) (*DetachedBundle, error)

// RFC 9782 media types.
const (
	MediaTypeEATCWT = "application/eat+cwt"
	MediaTypeEATUCS = "application/eat-ucs+cbor"
)
```

#### Measured component (RFC 10013)

`TypedBytes` carries measured components opaquely. A follow-up
(Phase D) adds `MeasuredComponent` decode helpers once RFC 10013 is
vendored and its open errata are reviewed. That proposal isn't filed
yet.

### Behavior / migration

This is a **wire-incompatible change**. Tokens produced before it
encode uptime at 266, software components at 267 and submods at 268.
After it, those keys mean submods, bootcount and bootseed.

- The default decoder reads only RFC 9711 numbering. A token from the
  old encoder is not a valid RFC 9711 token.
- Callers with stored or in-flight v0.2 tokens select
  `WithLegacyDraftClaimKeys()` explicitly. In that mode `DecodeClaims`,
  `Encode`, `Sign` and `Verify` use **only** the v0.2 numbering (261 =
  security level, 266 = uptime, 267 = software components, 268 =
  submods). The two numberings are never mixed or guessed between, which
  avoids the key-confusion hazard. Encode output in that mode is
  byte-identical to v0.2.2 for claims v0.2 could represent.

```go
// Option configures EAT encoding, decoding, signing and verification.
type Option func(*config)

func DecodeClaims(data []byte, opts ...Option) (*Claims, error)
func (c *Claims) Encode(opts ...Option) ([]byte, error)
func Sign(claims *Claims, signer *cose.Signer, opts ...Option) ([]byte, error)
func Verify(data []byte, verifier *cose.Verifier, opts ...Option) (*Claims, error)

// WithLegacyDraftClaimKeys reads and writes the draft-era claim
// numbering used by corecbor <= v0.2 instead of RFC 9711's. It applies
// to every claim in the token; numberings are never mixed.
//
// Deprecated: conflicts with RFC 9711 and the IANA CWT registry.
// Retained for reading tokens issued by corecbor <= v0.2. Removed no
// earlier than v0.32.0.
func WithLegacyDraftClaimKeys() Option

// WithLegacyValueChecks skips the RFC 9711 value constraints v0.2 did
// not enforce: nonce length 8..64, UEID type byte and length, dbgstat
// range, and eat_profile form.
//
// Deprecated: accepts non-conformant tokens; removed no earlier than v0.32.0.
func WithLegacyValueChecks() Option

// CompatV02 bundles WithLegacyDraftClaimKeys. It does not include
// WithLegacyValueChecks, which weakens freshness checks (see the
// bundling rule in proposal 027).
//
// Deprecated: migrate to explicit selectors; removed no earlier than v0.32.0.
func CompatV02() Option
```
- The changelog and `eat/doc.go` state the break. Old test vectors
  under `eat/` are regenerated for the default path. The v0.2.2 outputs
  are kept as `testdata/legacy-v0.2.2/` fixtures for the legacy
  selector.
- Callers that used `SWComponents` move to `psa.Claims.SoftwareComponents`.
  Callers that used `SecurityLevel` must choose a profile-specific claim.

### Failure modes

New sentinels: `ErrSubmodUnverified`, `ErrInvalidUEID`,
`ErrInvalidNonce`, `ErrDebugStatus`, `ErrUnknownDebugStatus`. A
`*ClaimError` (shared with `cwt`, proposal 031) reports the failing key.
Every wrap uses `%w`.

---

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).

| Change | Class | Default (v0.30) | Selector |
|---|---|---|---|
| Claim keys renumbered to RFC 9711 / IANA (261, 266–268 and the new claims) | Conformance | RFC 9711 | `func WithLegacyDraftClaimKeys() Option` — Deprecated; explicit, all-or-nothing |
| Software components moved to `eat/psa` under 2399 (RFC 9783) | Conformance | 2399 via `eat/psa` | covered by `WithLegacyDraftClaimKeys()` (reads/writes 267 in the PSA shape) |
| `SecurityLevel` / `RequireSecurityLevel` removed | Conformance (claim dropped from RFC 9711) | removed | legacy mode decodes 261 into `Private` as `cwt.ClaimKey{Int: 261}`; no typed field |
| Nonce 8–64 bytes, UEID type/length, `dbgstat` 0–4, `eat_profile` URI-or-OID | Conformance (RFC 9711 §4.1, §4.2.1, §4.2.9, §4.3.2) | enforced | `func WithLegacyValueChecks() Option` — Deprecated. Not bundled |
| `dbgstat` 0 ("enabled") encoded explicitly instead of omitted | Defect (indistinguishable from absent) | encoded | legacy mode keeps v0.2 omission for byte-identical output |
| Nested submodule tokens fail closed without `SubmodVerify` | Defect (fail-open) | `ErrSubmodUnverified` | none — defect. A caller can pass a `SubmodVerify` that decodes without verifying, which makes the choice explicit |
| Unknown, `cnf` and private claims preserved | Defect (data loss) | preserved | none — defect |
| Detached EAT bundle (tag 602), RFC 9782 media types, measured component (RFC 10013) | Additive | n/a | n/a |

Bundle: `eat.CompatV02() Option` = `WithLegacyDraftClaimKeys()`.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| Claim constants equal IANA registry values 256–275 | `TestClaimKeys_IANA` (table from registry snapshot checked into `eat/testdata/cwt-claims.xml`) | Yes |
| RFC 9711 Appendix A.1 CBOR examples decode, with corrections from verified errata 8528 (`Nonce` not `eat_nonce` in CWT examples), 8771 (`oemboot` not `secboot`), 8776 (`heading` may be null), 8782 (UEID base64url, no padding), 8783 (oemid-random-json `.size 22`) | `TestRFC9711_AppendixA` | Yes |
| Reported (unverified) errata 9193, 9196, 9199, 9200 reviewed; vectors follow the RFC text unless the erratum is verified by implementation time | review note in test file | No |
| Token with `submods` at 266, `bootcount` 267, `bootseed` 268 decodes correctly | `TestDecode_RegistryKeys` | Yes |
| Nested-token submod with `SubmodVerify == nil` → `ErrSubmodUnverified` | `TestAppraise_SubmodFailClosed` | Yes |
| Detached-digest submod `[alg, digest]` decodes; `SubmodDetached` invoked | `TestSubmod_Detached` | Yes |
| Unknown int/text claims and `cnf` round-trip byte-identically | `TestRoundTrip_Unknown` | Yes |
| `dbgstat` 0 encodes (not omitted); 4 accepted; 5 → `ErrUnknownDebugStatus` under `MinDebugStatus` | `TestDbgStat_*` | Yes |
| Nonce of 7 or 65 bytes → `ErrInvalidNonce` | `TestNonce_Length` | Yes |
| UEID type 0x04 or length 6 → `ErrInvalidUEID` | `TestUEID_Validate` | Yes |
| `eat_profile` OID form (bstr) decodes | `TestProfile_OID` | Yes |
| Pre-1970 `iat` round-trips (shared `cwt.NumericDate`) | `TestNumericDate_Pre1970` | Yes |
| RFC 9783 PSA token example decodes via `psa.FromEAT` | `TestPSA_RFC9783Example` | Yes |
| Tag 602 detached bundle decodes | `TestDetachedBundle` | Yes |
| `FuzzDecodeClaims` 60 s without panic | fuzz | Yes |
| RFC 9711, 9782, 9783 (and 10013 for Phase D) vendored with inventory rows | file review | Yes |
| v0.2.2-issued tokens (uptime, sw-components, submods, `dbgstat` 0) decode to the same values under `WithLegacyDraftClaimKeys()` and fail or decode differently by default; `Encode` under the selector is byte-identical to v0.2.2 | `TestCompatDraftClaimKeys` vs `testdata/legacy-v0.2.2/` | Yes |
| Under `WithLegacyDraftClaimKeys()`, an RFC 9711 token carrying `submods` at 266 is **not** read as submods (no mixing) | `TestCompatNoMixedNumbering` | Yes |
| `WithLegacyValueChecks()` accepts a 4-byte nonce; default rejects | `TestCompatValueChecks` | Yes |
| Legacy selectors and `CompatV02` carry `// Deprecated:` with removal floor v0.32.0; `CompatV02` excludes `WithLegacyValueChecks` | staticcheck SA1019 fixture + `TestCompatBundleContents` | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | Renumber claims; add missing scalar claims; fail-closed submods; `dbgstat`/nonce/UEID/profile rules; unknown-claim preservation via `cwt` (031 Phase A) | Pending | `TestClaimKeys_IANA`, `TestRFC9711_AppendixA`, `TestAppraise_SubmodFailClosed` pass |
| B | `eat/psa` package (RFC 9783); remove `SWComponent` / `SecurityLevel` from `eat` | Pending | `TestPSA_RFC9783Example` passes |
| C | Detached submods + tag-602 bundle + RFC 9782 media types | Pending | `TestSubmod_Detached`, `TestDetachedBundle` pass |
| D | Measured component (RFC 10013) helpers | Pending | follow-up proposal Accepted |

Phase A is a security fix (the submodule fail-open) and an interop fix
(the keys), and should land as soon as proposal 031 Phase A lands.

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestClaimKeys_IANA` | constants vs registry snapshot | `eat/claims_test.go` |
| `TestRFC9711_AppendixA` | spec examples (errata-corrected) | `eat/rfc9711_test.go` + `eat/testdata/` |
| `TestAppraise_*` | fail-closed submods, ordering, dbgstat, nonce | `eat/appraiser_test.go` |
| `TestPSA_*` | RFC 9783 | `eat/psa/psa_test.go` |
| `FuzzDecodeClaims` | arbitrary bytes → typed error | `eat/fuzz_test.go` (new) |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Existing stored tokens become undecodable | med | med | Pre-1.0; documented break; the old encoding was never interoperable |
| RFC 9711 examples contain further unverified errata | med | low | Use RFC text, annotate deviations; errata list checked at implementation time |
| PSA package drifts from Arm CCA profile | low | low | CCA is a separate I-D; `psa` covers RFC 9783 only |
| Fail-closed submods breaks callers relying on unverified decode | med | low | Callers who truly want it pass a `SubmodVerify` that decodes without verifying, which makes the choice explicit |

---

## Alternatives considered

**Auto-detect draft-era versus RFC 9711 numbering.** Rejected. A
dual-numbering decoder that guesses is a key-confusion hazard, because
266 can mean either submods or uptime. The explicit, deprecated
`WithLegacyDraftClaimKeys()` selector (proposal 034) is accepted
instead: the caller states which numbering a token uses, and the two
are never mixed.

**No legacy numbering at all.** Rejected under proposal 034. Callers
holding v0.2-issued tokens would be unable to upgrade.

**Model measurements as typed CoSWID/CoRIM structures now.**
Deferred. CoRIM (`draft-ietf-rats-corim-12`) is still in WG Last
Call. `TypedBytes` keeps the bytes intact for a later typed layer.

**Put PSA in a separate module.** Rejected. It is small, depends only
on `eat`, and a separate `go.mod` adds release overhead for no
isolation benefit.

---

## Open questions

- Should `Submod.Token` decoding recurse automatically when
  `SubmodVerify` returns claims, with a depth cap? The proposed answer
  is yes, with a cap of 4.
- Should `Location` (264) be typed now or carried as `corecbor.Value`?
  It is small, so the leaning is typed, including the erratum-8776
  nullable `heading`.

### Verify during implementation

- `ClaimSecurityLevel` → `psa-security-lifecycle` is a semantic
  mapping, not a renumbering. Confirm with RFC 9783 §4.3 that no
  automatic translation should be offered.
- Exact CDDL for `measres` (274) and `dloas` (269) structures (RFC 9711
  §4.2.17, §4.2.14).
- RFC 9782 media-type strings and CoAP content-format numbers (quote
  them from the vendored RFC, not from memory).

### Watch items

- RFC 9999 (CMW) registers CWT claim `cmw` (299). It is preserved
  through `Private` until a CMW proposal is filed.
- `draft-ietf-rats-ear-06` (EAT Attestation Results): an EAR
  producer/consumer may want an `eat/ear` package later.
- `draft-ietf-rats-eat-da`, `draft-reddy-rats-key-binding`,
  `draft-sun-rats-composite-eat`: profiles to track.
- RFC 10013 errata (the datatracker lists errata against it).

---

## Cross-references

- RFCs: RFC 9711 §4, §5, §10.2 and errata 8528, 8771, 8776, 8782,
  8783. RFC 9782. RFC 9783. RFC 9999. RFC 10013. RFC 9334.
- IANA: CWT Claims registry, entries 256–275 and 2394–2400.
- Sibling proposals: 005, 022, 027, 031, 033.

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft from 2026-11-20 codebase review + IANA registry check | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
