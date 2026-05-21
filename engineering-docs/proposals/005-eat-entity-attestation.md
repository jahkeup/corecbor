# 005 — EAT: Entity Attestation Tokens (RFC 9711)

## Header

| Field | Value |
|---|---|
| **Number** | 005 |
| **Tier** | 3 |
| **Status** | Accepted |
| **Filed** | 2026-05-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001 (corecbor), 002 (COSE), 003 (CWT) |
| **Supersedes** | none |
| **Spec sections touched** | none (tier-3; sibling module) |

---

## TL;DR

Implement Entity Attestation Tokens (EAT) per RFC 9711 as a sibling
Go module (`github.com/jahkeup/corecbor/eat`) that extends the CWT
module (proposal 003) with hardware attestation claims, nonces,
software measurements, and submodule attestation.

EAT extends CWT exactly as CWT extends COSE — it adds typed claims
to the claims map.  The implementation is ~400–600 LOC of additional
claim types + validation logic over the CWT module.  Zero non-stdlib
deps beyond corecbor/cose/cwt.

EAT is the standard attestation token format for:
- ARM PSA (Platform Security Architecture)
- Android Key Attestation (keystore-backed)
- FIDO/WebAuthn attestation statements
- TCG DICE (Device Identifier Composition Engine)
- Confidential computing attestation (SGX, TDX, SEV-SNP)

Blocked on proposal 003 (CWT Phase A).

---

## Motivation

Hardware attestation is the foundation of modern device trust:

- **"Is this device genuine?"** — an EAT from a TPM/secure enclave
  proves the device's identity and boot state.
- **"Is this software stack intact?"** — software component
  measurements in the EAT prove the firmware/OS/app hasn't been
  tampered with.
- **"Can I trust this execution environment?"** — confidential
  computing (SGX, TDX, SEV-SNP) attestation reports are EATs that
  prove code is running in a hardware-isolated enclave.

The attestation ecosystem is converging on EAT as the wire format:

| Platform | Attestation format | EAT relationship |
|---|---|---|
| ARM PSA | PSA Attestation Token | Profile of EAT |
| Android | Key Attestation | Maps to EAT claims |
| FIDO/WebAuthn | Attestation Object | Contains EAT-shaped data |
| TCG DICE | DICE Attestation Evidence | EAT profile |
| Intel SGX/TDX | Quote/Report | Wrappable in EAT |
| AMD SEV-SNP | Attestation Report | Wrappable in EAT |

A Go EAT module over corecbor enables attestation verifiers (relying
parties) and attesters (secure enclaves, TPMs) to produce and consume
standardized attestation tokens without hand-rolling CBOR/COSE parsing.

---

## Proposal

### Module structure

```
github.com/jahkeup/corecbor/eat/      # go.mod: module github.com/jahkeup/corecbor/eat
├── doc.go                            # Package doc
├── claims.go                         # EAT-specific claim types (extends CWT ClaimsSet)
├── nonce.go                          # Nonce claim handling (freshness)
├── swclaims.go                       # Software component measurements
├── submod.go                         # Submodule attestation (nested tokens)
├── profile.go                        # Profile identifier + validation
├── token.go                          # EAT Token (wraps CWT Token)
├── verify.go                         # Attestation verification logic
├── claims_test.go
├── token_test.go
├── verify_test.go
└── testdata/
    └── eat-vectors/                  # Test vectors (from EAT test suite)
```

### Dependency graph

```
github.com/jahkeup/corecbor/eat
    │
    ├── github.com/jahkeup/corecbor/cwt   (CWT Token, ClaimsSet, Validator)
    ├── github.com/jahkeup/corecbor/cose  (Sign1, Encrypt0, Key)
    ├── github.com/jahkeup/corecbor/cbor  (Value types)
    └── github.com/jahkeup/corecbor/rfc8949 (CBOR encoding)
```

No non-stdlib, non-corecbor dependencies.

### Public API surface

```go
package eat

import (
    "github.com/jahkeup/corecbor/cbor"
    "github.com/jahkeup/corecbor/cose"
    "github.com/jahkeup/corecbor/cwt"
)

// ---- EAT Claims (RFC 9711 §4) ----

// Claims extends CWT ClaimsSet with EAT-specific attestation claims.
type Claims struct {
    // Embeds all standard CWT claims (iss, sub, aud, exp, nbf, iat, cti).
    cwt.ClaimsSet

    // EAT-specific claims (RFC 9711 §4):

    // Nonce binds the token to a challenge for freshness.
    // Can be a single bstr or an array of bstr.
    Nonce [][]byte // claim key 10

    // UEID (Universal Entity ID) — globally unique device identifier.
    UEID []byte // claim key 256

    // OEMId identifies the device manufacturer.
    OEMId []byte // claim key 258

    // SecurityLevel indicates the security assurance of the attesting
    // environment.
    SecurityLevel SecurityLevel // claim key 261

    // SecureBoot indicates whether secure boot is active.
    SecureBoot *bool // claim key 262

    // Debug indicates whether debug facilities are enabled.
    Debug DebugStatus // claim key 263

    // Location is the device's geographic location at attestation time.
    Location *Location // claim key 264

    // Profile identifies which attestation profile this token conforms to.
    Profile Profile // claim key 265

    // Uptime is device uptime in seconds at token creation.
    Uptime *uint64 // claim key 266

    // SWComponents is the list of measured software components.
    SWComponents []SWComponent // claim key 267 (manifests-set / sw-components)

    // Submods contains nested attestation tokens from submodules.
    Submods map[string]Submod // claim key 268
}

// ---- Security Level (RFC 9711 §4.3.1) ----

type SecurityLevel int64

const (
    SecLevelUnrestricted     SecurityLevel = 1
    SecLevelRestrictedOS     SecurityLevel = 2
    SecLevelSecureRestricted SecurityLevel = 3
    SecLevelHardware         SecurityLevel = 4
)

// ---- Debug Status ----

type DebugStatus int64

const (
    DebugEnabled         DebugStatus = 0
    DebugDisabled        DebugStatus = 1
    DebugDisabledSince   DebugStatus = 2
    DebugPermanentDisable DebugStatus = 3
)

// ---- Software Component (RFC 9711 §4.4) ----

// SWComponent represents a measured software component.
type SWComponent struct {
    // Type identifies the component type (e.g., "BL1", "PRoT", "ARoT").
    Type string // key 1
    // MeasurementValue is the hash/digest of the component.
    MeasurementValue []byte // key 2
    // Version is the component version string.
    Version string // key 4
    // SignerID identifies who signed/measured this component.
    SignerID []byte // key 5
    // MeasurementDescription describes the measurement method.
    MeasurementDescription string // key 6
}

// ---- Location ----

type Location struct {
    Latitude  float64 // key 1
    Longitude float64 // key 2
    Altitude  float64 // key 3 (optional)
    Accuracy  float64 // key 4 (optional, meters)
    Timestamp int64   // key 6 (optional, epoch seconds)
}

// ---- Submodule Attestation ----

// Submod represents a nested attestation from a submodule.
// It can be either a nested EAT token (as bytes) or an inline claims set.
type Submod struct {
    // Token is a nested EAT (as signed/encrypted CBOR bytes).
    // Mutually exclusive with Claims.
    Token []byte
    // Claims is an inline submodule claims set.
    // Mutually exclusive with Token.
    Claims *Claims
}

// ---- Profile ----

// Profile identifies the attestation profile (URI or OID).
type Profile struct {
    URI string // text string form
    OID []byte // OID byte string form (alternative)
}

// Well-known profiles:
var (
    ProfilePSA  = Profile{URI: "http://arm.com/psa/2.0.0"}
    ProfileDICE = Profile{URI: "https://trustedcomputinggroup.org/dice/1.0"}
)

// ---- Token creation and verification ----

// Sign creates a signed EAT (CWT/COSE_Sign1-wrapped claims).
func Sign(claims *Claims, signer *cose.Signer, opts ...cwt.SignOption) ([]byte, error)

// Verify decodes and verifies a signed EAT.
func Verify(data []byte, verifier *cose.Verifier) (*Token, error)

// Token is a verified EAT.
type Token struct {
    Claims *Claims
}

// ---- Verification / Appraisal ----

// Appraiser evaluates attestation evidence against a policy.
type Appraiser struct {
    // RequireNonce requires a nonce claim matching the expected value.
    RequireNonce []byte

    // RequireSecurityLevel is the minimum acceptable security level.
    RequireSecurityLevel SecurityLevel

    // RequireSecureBoot requires secure boot to be active.
    RequireSecureBoot bool

    // RequireDebugDisabled requires debug to be disabled.
    RequireDebugDisabled bool

    // RequireProfile requires a specific attestation profile.
    RequireProfile *Profile

    // SWComponentPolicy is a function that validates software
    // component measurements against known-good reference values.
    // Return nil if the component is acceptable.
    SWComponentPolicy func([]SWComponent) error

    // CWTValidator handles standard CWT claim validation (exp, nbf, aud).
    // If nil, a default validator is used.
    CWTValidator *cwt.Validator

    // Custom appraiser functions for additional policy checks.
    Custom []func(*Claims) error
}

// Appraise evaluates an attestation token against policy.
// Returns nil if the token passes all policy checks.
func (a *Appraiser) Appraise(t *Token) error

// Appraisal errors.
var (
    ErrNonceMismatch      = errors.New("eat: nonce does not match expected value")
    ErrSecurityLevel      = errors.New("eat: security level below minimum")
    ErrSecureBootRequired = errors.New("eat: secure boot not active")
    ErrDebugEnabled       = errors.New("eat: debug facilities enabled")
    ErrProfileMismatch    = errors.New("eat: token does not match required profile")
    ErrSWComponentPolicy  = errors.New("eat: software component policy violation")
    ErrMalformedEAT       = errors.New("eat: malformed attestation token")
)
```

### Behavior

**EAT creation flow:**
1. Populate `Claims` (including CWT base claims + EAT-specific claims).
2. Call `Sign()` which:
   - Encodes `Claims` → CBOR map (CoreDeterministic).
   - Wraps in COSE_Sign1 via the COSE module.
   - Returns the serialized token.

**EAT verification flow:**
1. Call `Verify()` which:
   - Decodes CBOR → COSE_Sign1.
   - Verifies signature via COSE module.
   - Decodes payload → `Claims`.
   - Returns `Token`.
2. Call `Appraiser.Appraise()` which:
   - Validates CWT claims (expiration, audience) via CWT Validator.
   - Validates EAT-specific claims (nonce, security level, measurements).
   - Applies custom policy functions.

**Submodule attestation:**
EAT supports nested tokens — a platform-level attestation may contain
submodule attestations from individual secure enclaves.  Each submod
is either a nested EAT (verified recursively) or an inline claims set
(verified by the parent's signature).

### Claim numbering

EAT uses the same integer-keyed CBOR map as CWT:
- Keys 1–7: standard CWT claims (handled by `cwt.ClaimsSet`).
- Keys 10, 256–268: EAT-specific claims.
- Private-use keys: application-defined (e.g., PSA uses keys 2393–2400).

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| EAT test vectors round-trip | `TestEATVectors` (from EAT working group examples) | Yes |
| Sign + Verify round-trip (Ed25519) with all EAT claims | `TestSignVerify_AllClaims` | Yes |
| Nonce validation | `TestAppraiser_NonceMismatch`: wrong nonce → `ErrNonceMismatch` | Yes |
| Security level enforcement | `TestAppraiser_SecurityLevel`: level 1 token with level 3 requirement → `ErrSecurityLevel` | Yes |
| Secure boot enforcement | `TestAppraiser_SecureBoot` | Yes |
| Debug status enforcement | `TestAppraiser_DebugEnabled` | Yes |
| Software component policy | `TestAppraiser_SWPolicy`: measurement mismatch → `ErrSWComponentPolicy` | Yes |
| Submodule nested token verification | `TestSubmod_NestedToken`: nested EAT is independently verifiable | Yes |
| Submodule inline claims | `TestSubmod_InlineClaims` | Yes |
| Profile matching | `TestAppraiser_ProfileMismatch` | Yes |
| CWT base claim validation (exp, nbf, aud) passes through | `TestAppraiser_CWTValidation` | Yes |
| No non-stdlib/non-corecbor deps | `go mod graph` | Yes |
| FuzzDecodeEATNeverPanics | 30s fuzz | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | Core claims (nonce, UEID, security level, debug, secure boot) + Sign/Verify + basic Appraiser | Pending | EAT vectors pass; appraiser rejects bad tokens |
| B | Software component measurements + profile validation + Location | Pending | PSA-profile test vectors pass |
| C | Submodule attestation (nested + inline) + full Appraiser policy | Pending | Nested token verification works end-to-end |

Phase A is independently shippable — it covers the basic attestation
verification flow (challenge-response with nonce, check device
identity and security posture).

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestEATVectors` | Working group test vectors | `token_test.go` |
| `TestSignVerify_*` | Per-algorithm round-trip | `token_test.go` |
| `TestClaims_Encode` | Deterministic encoding of all claim types | `claims_test.go` |
| `TestSWComponent_*` | Software measurement encoding/decoding | `swclaims_test.go` |
| `TestSubmod_*` | Nested and inline submodule attestation | `submod_test.go` |
| `TestAppraiser_*` | Each appraisal rule | `verify_test.go` |
| `TestProfile_*` | Profile matching (URI and OID forms) | `profile_test.go` |
| `FuzzDecodeEATNeverPanics` | Arbitrary bytes → no panic | `token_test.go` |

---

## Performance

| Metric | Target | Test mechanism |
|---|---|---|
| Sign EAT (Ed25519, typical IoT claims) | ≥ 8,000 ops/s | `BenchmarkSign_Ed25519` |
| Verify + Appraise (Ed25519, typical IoT claims) | ≥ 8,000 ops/s | `BenchmarkVerifyAppraise_Ed25519` |
| Claims encode | ≤ 1 allocation (pre-allocated dst) | `-benchmem` |
| Claims decode | ≤ 3 allocations | `-benchmem` |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| RFC 9711 is relatively new; claim assignments may shift | low (it's published) | low | Pin to RFC 9711 claim keys; future additions are additive |
| PSA/DICE profiles define additional claims beyond base EAT | high | low | Private claims map handles profile-specific extensions |
| Submodule verification requires recursive trust chains | medium | medium | Document trust model clearly; limit recursion depth |
| Platform-specific attestation formats need custom parsing | high | low | EAT is the envelope; platform-specific raw evidence is opaque bytes in the token |
| CWT module (003) API instability | medium | medium | EAT pins CWT version; interface is small (ClaimsSet embedding, Sign/Verify) |

---

## Alternatives considered

### Combine EAT into the CWT module

Rejected. EAT adds significant domain-specific complexity (software
measurements, submodules, security levels, appraisal policies) that
don't belong in a general-purpose token library. Keeping them separate
allows CWT to remain simple (7 claims + private map) while EAT adds
the attestation domain.

### Skip typed claims (let callers parse private claims manually)

Rejected. Attestation verification is security-critical — incorrect
claim parsing leads to accepting bad attestations. Typed claims with
validation prevent the class of bugs where callers misinterpret
measurement values or security levels.

### Support only PSA profile (skip generic EAT)

Rejected. The generic EAT types are the foundation; PSA is one
profile. Supporting generic EAT means any profile (DICE, Android,
custom) can be verified with the same toolkit. Profile-specific
validation goes in the `SWComponentPolicy` callback.

---

## Open questions

- **PSA profile as first-class sub-package**: Should there be a
  `eat/psa` sub-package that defines PSA-specific claim keys and
  validation? Lean: yes, after Phase B, as a profile helper.

- **Evidence vs. Attestation Result**: RFC 9711 covers Evidence
  tokens (from attester to verifier). Attestation Results (from
  verifier to relying party, per RATS architecture RFC 9334) are a
  different token type with a different claims set. Should this module
  handle both? Lean: Evidence first (Phase A–C); Attestation Results
  as a follow-on proposal.

- **COSE_Sign vs COSE_Sign1**: Some attestation architectures require
  multiple signatures (e.g., manufacturer + device). Should EAT
  support `COSE_Sign` (multi-signer) in addition to `Sign1`? Lean:
  Sign1 first (Phase A), multi-signer support tracks COSE module
  Phase B.

---

## Cross-references

- RFCs: RFC 9711 — EAT (primary spec).
- RFCs: RFC 8392 — CWT (base token format).
- RFCs: RFC 9334 — RATS Architecture (context for EAT's role).
- RFCs: RFC 9052/9053 — COSE (signing/encryption).
- Sibling proposals: `001` (corecbor), `002` (COSE), `003` (CWT).
- External: ARM PSA Attestation Token:
  https://arm-software.github.io/psa-api/
- External: TCG DICE Attestation:
  https://trustedcomputinggroup.org/resource/dice-attestation-architecture/
- External: IETF RATS WG:
  https://datatracker.ietf.org/wg/rats/about/

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-20 | Initial draft | corecbor maintainers |
