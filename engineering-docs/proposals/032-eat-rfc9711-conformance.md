# 032 — EAT: RFC 9711 conformance

## Header

| Field | Value |
|---|---|
| **Number** | 032 |
| **Tier** | 3 |
| **Status** | Closed |
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
- Several RFC 9711 value constraints aren't checked anywhere: nonce
  length, UEID type and length, the `dbgstat` range, and the
  `eat_profile` OID form.

This proposal renumbers to the registry, adds the missing claims, makes
submodule appraisal fail closed, and preserves unknown claims. The
package documents RFC 9711, so per proposal 034 the numbering is a
Contract defect fixed in place, and the v0.2 numbering stays selectable
through the deprecated `WithLegacyDraftClaimKeys()`. Selection is always
explicit and never auto-detected. No exported field, type or function
signature changes (034 API stability): new claims are new fields, value
checks are a new opt-in `Claims.Validate()` / `NewAppraiser()`, and the
PSA-shaped `SWComponents` field now maps to its real claim key, 2399
(RFC 9783), with an `eat/psa` view of the PSA claims.

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

// Claims keeps every v0.2.2 field with its type (proposal 034). The
// claim *keys* they map to are fixed to RFC 9711; new claims are
// appended as new fields whose zero value means "absent".
type Claims struct {
	cwt.ClaimsSet // incl. cnf, Private, PrivateClaims (proposal 031) — now encoded/decoded

	Nonce         [][]byte          // 10 — unchanged
	UEID          []byte            // 256 — unchanged type; see UEID helpers below
	OEMId         []byte            // 258 — unchanged
	SecurityLevel SecurityLevel     // Deprecated: not an RFC 9711 claim; populated only under WithLegacyDraftClaimKeys
	SecureBoot    *bool             // 262 oemboot — unchanged (same key; RFC 9711 name is "oemboot")
	Debug         DebugStatus       // 263 — unchanged; 0 still means "enabled or absent" (see DbgStat)
	Uptime        *uint64           // now 261 (RFC 9711); was 266
	Profile       string            // 265 — unchanged; URI / text form
	SWComponents  []SWComponent     // now RFC 9783 claim 2399 (psa-software-components); was 267
	Submods       map[string]Submod // now 266 (RFC 9711); was 268

	// --- new in v0.30 ---
	DbgStat      *DebugStatus    // 263 with explicit presence; takes precedence over Debug on encode
	ProfileOID   []byte          // 265 OID form (RFC 9711 §4.3.2)
	SUEIDs       map[string][]byte // 257
	HWModel      []byte          // 259
	HWVersion    *Version        // 260
	Location     *Location       // 264
	BootCount    *uint64         // 267
	BootSeed     []byte          // 268
	DLOAs        []DLOA          // 269
	SWName       string          // 270
	SWVersion    *Version        // 271
	Manifests    []TypedBytes    // 272: [content-format, bstr]
	Measurements []TypedBytes    // 273: [content-format, bstr]
	MeasRes      []MeasResGroup  // 274
	IntUse       *IntendedUse    // 275
}

// UEID is a Universal Entity ID (RFC 9711 §4.2.1). The Claims.UEID
// field keeps its []byte type; convert with eat.UEID(c.UEID).
type UEID []byte

type UEIDType uint8

const (
	UEIDTypeRAND UEIDType = 0x01
	UEIDTypeEUI  UEIDType = 0x02
	UEIDTypeIMEI UEIDType = 0x03
)

func (u UEID) Type() UEIDType
func (u UEID) Validate() error // type byte + length 7..33

// DebugStatus keeps its v0.2.2 underlying type (int64) and constants.
// One constant is added for the RFC 9711 value v0.2.2 lacked:
const DebugDisabledFullyAndPermanently DebugStatus = 4

// TypedBytes is a [content-format, bstr] pair used by manifests
// and measurements. CoAP content-format numbers are integers;
// media-type strings are text.
type TypedBytes struct {
	ContentFormat *uint64
	MediaType     string
	Value         []byte
}

// Submod keeps its v0.2.2 fields (Token, Claims) and gains two.
// Exactly one is set.
type Submod struct {
	Token    []byte          // nested CBOR token (COSE-protected EAT), raw bytes — unchanged
	Claims   *Claims         // inline Claims-Set — unchanged
	JSON     []byte          // new: nested JSON token (opaque; not decoded here)
	Detached *DetachedDigest // new: [hash-alg, digest]
}

type DetachedDigest struct {
	Alg    cose.Algorithm // hash alg (RFC 9054 identifiers)
	Digest []byte
}

// Validate checks the RFC 9711 value constraints DecodeClaims does not
// enforce (it keeps v0.2.2 acceptance): nonce length 8..64, UEID type
// byte and length, dbgstat 0..4, eat_profile form.
func (c *Claims) Validate() error
```

#### Unknown claims

Any claim this package doesn't model stays in the embedded
`cwt.ClaimsSet`: in `PrivateClaims` (`map[cwt.ClaimKey]corecbor.Value`)
and, for hashable keys, in the deprecated `Private` map, per proposal
031. v0.2.2 dropped both (`eat/claims.go:89-199`), contradicting the
embedded type's contract. That covers PSA claims when `eat/psa` isn't used,
`cmw` (299), and vendor claims. Encode writes them back out.
`DecodeClaims` → `Encode` is byte-identical for a deterministic input,
which `TestRoundTrip_Unknown` checks.

#### Appraiser

```go
// Appraiser keeps every v0.2.2 field and its zero-value behavior. New
// fields are appended; their zero values change nothing.
type Appraiser struct {
	RequireNonce         []byte // unchanged semantics; compare is now constant-time
	RequireSecurityLevel SecurityLevel // Deprecated: not an RFC 9711 claim (see Behavior)
	RequireSecureBoot    bool
	RequireDebugDisabled bool   // unchanged: rejects only DebugEnabled
	RequireProfile       string
	SWComponentPolicy    func([]SWComponent) error
	CWTValidator         *cwt.Validator // unchanged: nil skips CWT validation
	Custom               []func(*Claims) error
	SubmodPolicy         func(name string, claims *Claims) error
	SubmodVerifier       *cose.Verifier

	// --- new in v0.30 ---
	NonceVerifier     func(nonces [][]byte) error
	MinDebugStatus    *DebugStatus // unknown values fail
	RequireProfileOID []byte
	ValidateValues    bool // run Claims.Validate (RFC 9711 value constraints)
	SubmodVerify      func(ctx context.Context, name string, token []byte) (*Claims, error)
	SubmodDetached    func(ctx context.Context, name string, d DetachedDigest) error
	MeasurementPolicy func(ms []TypedBytes) error
}

// NewAppraiser returns an Appraiser with current-standards defaults:
// CWTValidator = cwt.NewValidator(), ValidateValues = true. It is the
// recommended constructor; the zero value keeps v0.2.2 behavior.
func NewAppraiser() *Appraiser

// Appraise keeps its v0.2.2 signature.
func (a *Appraiser) Appraise(claims *Claims) error

// AppraiseContext is Appraise with a context for SubmodVerify /
// SubmodDetached callbacks.
func (a *Appraiser) AppraiseContext(ctx context.Context, claims *Claims) error
```

Changes from v0.2.2:

- **Fail-closed submodules (Safety defect).** A nested `Token`
  submodule with `SubmodPolicy` set but neither `SubmodVerifier` nor
  `SubmodVerify` returns `ErrSubmodUnverified`. v0.2.2 decoded it
  without verifying and handed it to the policy as trusted
  (`eat/appraiser.go:85-91`).
- Submodules are visited in sorted name order (v0.2.2 used map order,
  so the first reported error varied).
- The nonce compare uses `crypto/subtle.ConstantTimeCompare`. The nonce
  isn't secret, but this costs nothing and removes a review question.
- `RequireSecurityLevel` keeps its v0.2.2 rule. Under RFC 9711
  numbering no claim populates `SecurityLevel`, so a non-zero
  `RequireSecurityLevel` fails closed (`ErrSecurityLevel`) unless
  `WithLegacyDraftClaimKeys()` is used to decode.

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

// SoftwareComponent is the RFC 9783 psa-software-components entry.
// eat.SWComponent (v0.2.2) keeps its name and fields; this is a type
// alias so both names refer to one type.
type SoftwareComponent = eat.SWComponent

// SoftwareComponents is the same data as eat.Claims.SWComponents
// (both map to claim 2399); psa exposes it under the RFC 9783 name.
// FromEAT copies the slice; ToEAT writes it back.
type Claims struct {
	*eat.Claims
	ClientID              int64
	SecurityLifecycle     uint16
	ImplementationID      []byte
	CertificationRef      string
	SoftwareComponents    []SoftwareComponent
	VerificationService   string
}

func FromEAT(c *eat.Claims) (*Claims, error) // lifts PSA claims out of PrivateClaims
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

Claim *numbering* changes; the Go API does not. The package documents
RFC 9711 (`eat/doc.go:4`), so the draft-era keys are a contract defect
and are fixed in place. Tokens produced by v0.2.2 encode uptime at 266,
software components at 267 and submods at 268; after this change those
keys mean submods, bootcount and bootseed.

- The default decoder reads only RFC 9711 numbering. A token from the
  old encoder is not a valid RFC 9711 token.
- Callers with stored or in-flight v0.2 tokens select
  `WithLegacyDraftClaimKeys()` explicitly. In that mode `DecodeClaims`,
  `Encode`, `Sign` and `Verify` use **only** the v0.2 numbering (261 =
  security level, 266 = uptime, 267 = software components, 268 =
  submods). The two numberings are never mixed or guessed between, which
  avoids the key-confusion hazard. Encode output in that mode is
  byte-identical to v0.2.2 for claims v0.2 could represent.
- `DecodeClaims` keeps v0.2.2's value acceptance (no nonce-length,
  UEID or dbgstat-range checks). Those RFC 9711 constraints run through
  the new `Claims.Validate()` and `NewAppraiser()`.
- `Debug == DebugEnabled` is still omitted on encode, as in v0.2.2;
  set `DbgStat` to encode an explicit 0.

```go
// Option configures EAT encoding, decoding, signing and verification.
type Option func(*config)

// Each gains an appended ...Option. With no options the only change
// from v0.2.2 is the contract-defect fix to RFC 9711 claim numbering
// (and preservation of cnf/private claims).
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

// CompatV02 bundles WithLegacyDraftClaimKeys.
//
// Deprecated: migrate to explicit selectors; removed no earlier than v0.32.0.
func CompatV02() Option
```
- The changelog and `eat/doc.go` state the numbering fix. Old test
  vectors under `eat/` are regenerated for the default path. The v0.2.2
  outputs are kept as `testdata/legacy-v0.2.2/` fixtures for the legacy
  selector.
- `SWComponents` keeps working; it now maps to RFC 9783 claim 2399, and
  `psa.Claims` exposes the same data. `SecurityLevel` is deprecated:
  RFC 9711 has no such claim.

### Failure modes

New sentinels: `ErrSubmodUnverified`, `ErrInvalidUEID`,
`ErrInvalidNonce`, `ErrDebugStatus`, `ErrUnknownDebugStatus`. A
`*ClaimError` (shared with `cwt`, proposal 031) reports the failing key.
Every wrap uses `%w`.

---

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).
No exported identifier is removed, renamed or retyped: every v0.2.2
field of `Claims`, `Submod`, `SWComponent` and `Appraiser` keeps its
name and type, `DebugStatus` stays `int64`, and `Appraise(claims)` keeps
its signature. The `eat` package documents RFC 9711 (`eat/doc.go:4`), so
the wire numbering is a Contract defect fixed in place.

| Change | Class | Contract restored | Existing identifiers in v0.30 | Selector |
|---|---|---|---|---|
| Claim keys renumbered to RFC 9711 / IANA (Uptime 266→261, Submods 268→266) | Contract defect | `eat/doc.go:4` ("Entity Attestation Tokens (EAT) as defined in RFC 9711"); RFC 9711 §10.2 | same fields, RFC keys | `func WithLegacyDraftClaimKeys() Option` — Deprecated; explicit, all-or-nothing |
| `SWComponents` encoded at RFC 9783 claim 2399 (was 267) | Contract defect | the map shape is RFC 9783's psa-software-components; 267 is bootcount in RFC 9711 | same field, key 2399 | covered by `WithLegacyDraftClaimKeys()` |
| `SecurityLevel` / `RequireSecurityLevel` | Superseded contract (claim dropped from RFC 9711) | — | kept, deprecated; populated only under legacy numbering; non-zero `RequireSecurityLevel` fails closed otherwise | none |
| cnf, private and unknown claims preserved | Contract defect | embedded `cwt.ClaimsSet` (`eat/claims.go:73`) carries them; v0.2.2 dropped them | preserved | none |
| Nested submodule tokens fail closed without a verifier | Safety defect (fail-open) | — | `ErrSubmodUnverified` | none. A caller may pass a `SubmodVerify` that decodes without verifying, which makes the choice explicit |
| RFC 9711 value constraints (nonce 8–64, UEID, dbgstat 0–4, profile form) | Additive (opt-in) | — | `DecodeClaims` acceptance unchanged | `Claims.Validate()`, `Appraiser.ValidateValues`, `NewAppraiser()` |
| `dbgstat` 0 encoded explicitly | Additive | — | `Debug == 0` still omitted | `DbgStat` field |
| Standards-default appraisal (CWT validation, value checks) | Superseded contract | — | zero-value `Appraiser` unchanged (nil `CWTValidator` skips validation) | `NewAppraiser()` (recommended) |
| New claims (257, 259, 260, 264, 267–275), `ProfileOID`, `Submod.JSON`/`Detached`, `DebugDisabledFullyAndPermanently`, detached bundle (602), RFC 9782 media types, `eat/psa` | Additive | — | n/a | n/a |

Bundle: `eat.CompatV02() Option` = `WithLegacyDraftClaimKeys()`.

**Appended `...Option` parameters (apidiff-visible, migration-guide
entries):** `DecodeClaims(data, opts ...Option)`,
`(*Claims).Encode(opts ...Option)`, `Sign(claims, signer, opts ...Option)`,
`Verify(data, verifier, opts ...Option)`. With no options each behaves
as v0.2.2 except the contract-defect rows above.

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
| `DbgStat` = 0 encodes (not omitted); `Debug` = 0 is still omitted as in v0.2.2; 4 accepted; 5 → `ErrUnknownDebugStatus` under `MinDebugStatus` | `TestDbgStat_*` | Yes |
| Nonce of 7 or 65 bytes decodes (as v0.2.2) and `Claims.Validate()` returns `ErrInvalidNonce` | `TestNonce_Length` | Yes |
| `UEID(...).Validate()` on type 0x04 or length 6 → `ErrInvalidUEID` | `TestUEID_Validate` | Yes |
| `eat_profile` OID form (bstr) decodes | `TestProfile_OID` | Yes |
| Pre-1970 `iat` round-trips (shared `cwt.NumericDate`) | `TestNumericDate_Pre1970` | Yes |
| RFC 9783 PSA token example decodes via `psa.FromEAT` | `TestPSA_RFC9783Example` | Yes |
| Tag 602 detached bundle decodes | `TestDetachedBundle` | Yes |
| `FuzzDecodeClaims` 60 s without panic | fuzz | Yes |
| RFC 9711, 9782, 9783 (and 10013 for Phase D) vendored with inventory rows | file review | Yes |
| v0.2.2-issued tokens (uptime, sw-components, submods, `dbgstat` 0) decode to the same values under `WithLegacyDraftClaimKeys()` and fail or decode differently by default; `Encode` under the selector is byte-identical to v0.2.2 | `TestCompatDraftClaimKeys` vs `testdata/legacy-v0.2.2/` | Yes |
| Under `WithLegacyDraftClaimKeys()`, an RFC 9711 token carrying `submods` at 266 is **not** read as submods (no mixing) | `TestCompatNoMixedNumbering` | Yes |
| Zero-value `Appraiser{}` behaves as v0.2.2 (nil `CWTValidator` skips validation; no value checks); `NewAppraiser()` validates | `TestAppraiserZeroUnchanged`, `TestNewAppraiserDefaults` | Yes |
| `WithLegacyDraftClaimKeys` and `CompatV02` carry `// Deprecated:` with removal floor v0.32.0; `SecurityLevel`, `RequireSecurityLevel` carry `// Deprecated:` | staticcheck SA1019 fixture | Yes |
| No exported identifier present in v0.2.2 is removed, renamed, or retyped, and no method is added to an exported interface (034 API stability) | `apidiff` against `v0.2.2` for this module, run in `make check` | Yes |
| Existing identifiers called with no new options reproduce the v0.2.2 golden vectors, except the contract-defect fixes listed under Compatibility selection | `testdata/legacy-v0.2.2/` golden tests | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | Renumber claims; add missing scalar claims; fail-closed submods; `dbgstat`/nonce/UEID/profile rules; unknown-claim preservation via `cwt` (031 Phase A) | Done | `TestClaimKeys_IANA`, `TestRFC9711_AppendixA`, `TestAppraise_SubmodFailClosed` pass |
| B | `eat/psa` package (RFC 9783); ~~remove `SWComponent` / `SecurityLevel` from `eat`~~ kept per 034 API stability (`SecurityLevel` deprecated; `SWComponents` maps to 2399, aliased as `psa.SoftwareComponent`) | Done | `TestPSA_RFC9783Example` passes |
| C | Detached submods + tag-602 bundle + RFC 9782 media types | Done | `TestSubmod_Detached`, `TestDetachedBundle` pass |
| D | Measured component (RFC 10013) helpers | Deferred (RFC vendored; `Measurements` carried as `TypedBytes`) | follow-up proposal Accepted |

Phase A is a security fix (the submodule fail-open) and an interop fix
(the keys), and should land as soon as proposal 031 Phase A lands.

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestClaimKeys_IANA` | constants vs registry snapshot | `eat/eat032_test.go` + `eat/testdata/cwt-claims.xml` |
| `TestRFC9711_AppendixA_*` | spec examples A.1.1–A.1.5 (errata-corrected) | `eat/eat032_test.go` + `eat/rfc9711_vectors_test.go` |
| `TestDetachedBundle` | A.2.2 tag-602 bundle and detached-digest submod (covers `TestSubmod_Detached`) | `eat/eat032_test.go` |
| `TestAppraise_SubmodFailClosed`, `TestDbgStat`, `TestNonce_Length`, `TestAppraiserDefaults` | fail-closed submods, ordering, dbgstat, nonce, zero vs `NewAppraiser()` | `eat/eat032_test.go` |
| `TestCompatDraftClaimKeys`, `TestCompatNoMixedNumbering`, `TestGoldenLegacyReproducesV022` | legacy numbering, byte-identical to v0.2.2 | `eat/eat032_test.go`, `eat/golden_legacy_test.go` |
| `TestPSA_*` | RFC 9783 | `eat/psa/psa_test.go` |
| `FuzzDecodeClaims`, `FuzzAppraise`, `FuzzDecodeDetachedBundle` | arbitrary bytes → typed error; fail-closed invariant | `eat/fuzz_test.go` |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Existing stored tokens no longer decode by default | med | med | `WithLegacyDraftClaimKeys()` / `CompatV02()`; the old encoding was never interoperable; migration guide entry |
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
  through `PrivateClaims` until a CMW proposal is filed.
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

## Implementation notes (2026-11-21)

**Phases A–C are implemented; D is deferred.** Claim keys were checked
against the live IANA CWT Claims registry (snapshot
`eat/testdata/cwt-claims.xml`, updated 2026-11-13) for 10, 256–275 and
2394–2400; `TestClaimKeys_IANA` parses the snapshot.

- **Delegation to `cwt` (031).** `DecodeClaims` decodes the map,
  handles the keys eat models and re-encodes the rest through
  `cwt.DecodeClaimsSet`, so registered claims, `cnf` and unknown claims
  land in the embedded `ClaimsSet` / `PrivateClaims`. eat never reads
  or writes the deprecated `Private`. Duplicate claim keys are rejected
  (RFC 8392 §7.2, inherited from 031).
- **Legacy numbering.** `WithLegacyDraftClaimKeys()` (and
  `CompatV02()`) switches all four draft keys at once and rejects
  RFC-only claims rather than mixing. `TestGoldenLegacyReproducesV022`
  runs the whole v0.2.2 eat golden corpus under the selector: every
  vector is byte-identical except `eat/appraise/submod-token-no-verifier`
  (the safety fix, which no selector undoes).
- **`SecurityLevel`.** Encoding a non-zero `SecurityLevel` without the
  legacy selector returns `ErrClaimNumbering` instead of silently
  dropping it; it decodes only under legacy numbering. A signed
  `SecurityLevel` or `Debug` is encoded as a CBOR integer (negative
  values were written as a wrapped uint64 in v0.2.2, which it could not
  decode back; found by `FuzzDecodeClaims`). Non-negative values encode
  as before.
- **Fail closed.** As specified, submodules are appraised only when
  `SubmodPolicy` is set; then a token or JSON submod with neither
  `SubmodVerify` nor `SubmodVerifier`, or a detached digest without
  `SubmodDetached`, returns `ErrSubmodUnverified`. Inline submods are
  checked one level deep by the appraiser (deeper levels are the
  policy's job); `Validate` recurses through inline submods.
- **Validation is opt-in.** `DecodeClaims` accepts what v0.2.2 accepted;
  `Claims.Validate()` and `NewAppraiser()` (`ValidateValues`) apply the
  nonce, UEID, dbgstat and profile rules.
- **Additions beyond the text:** `OEMIDPEN` (the integer oemid form),
  `DetachedDigest.AlgName` (text algorithm identifiers),
  `HeadingNull` on `Location` (erratum 8776). `eat/psa` uses pointer
  fields for presence; `ClientID` is range-checked to int32.
- **Not addressed:** inline submodule original bytes are not preserved
  (re-encoding is deterministic); JSON submods stay opaque bytes.
- **Open questions answered:** `Location` is typed. Nested tokens are
  not decoded recursively by the appraiser; `SubmodVerify` returns the
  claims and `SubmodPolicy` sees them. RFC 9783 §4.3 confirms no
  automatic security-level → lifecycle translation. Media types and
  content-formats 263–268 are quoted from the vendored RFC 9782.
- **RFC example inconsistencies** (documented in the tests): the A.1.3
  UEID is 16 bytes, which isn't a valid RAND length (reported erratum
  9193), so that test checks `Validate` rejects it. In A.2.2 the hex
  main token's detached digest (`8def652f…`) is not SHA-256 of the
  detached TEE claims set; the RFC's diagnostic notation (`ab86f765…`)
  is, and the appraisal test uses that. The A.1.3 payload isn't in
  deterministic key order, so its re-encoding is compared with the
  deterministic encoding of the same value.
- **Golden ids changed by default** (allowlisted, "proposal 032 …"):
  `eat/encode/{uptime,sw-components,submods-inline,submods-token,security-level}`,
  `eat/decode/{roundtrip-uptime-seclevel,rfc9711-uptime-261,rfc9711-submods-266,rfc9711-bootcount-267,rfc9711-bootseed-268,profile-oid-bstr}`,
  `eat/appraise/submod-token-no-verifier`.
- **Fuzz:** `FuzzDecodeClaims`, `FuzzAppraise` and
  `FuzzDecodeDetachedBundle` ran 60 s each without failure after the
  integer-encoding fix.

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft from 2026-11-20 codebase review + IANA registry check | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
| 2026-11-20 | API stability (signature + semantics) per revised 034 | corecbor maintainers |
| 2026-11-21 | Phases A–C implemented; D deferred; implementation notes | corecbor maintainers |
| 2026-11-22 | Status: Closed (deferred items tracked in 036) | corecbor maintainers |
