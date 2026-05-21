# 003 — CWT: CBOR Web Tokens (RFC 8392)

## Header

| Field | Value |
|---|---|
| **Number** | 003 |
| **Tier** | 3 |
| **Status** | Closed |
| **Filed** | 2026-05-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001 (corecbor primitives), 002 (COSE) |
| **Supersedes** | none |
| **Spec sections touched** | none (tier-3; sibling module) |

---

## TL;DR

Implement CBOR Web Tokens (CWT) per RFC 8392 as a sibling Go module
(`github.com/jahkeup/corecbor/cwt`) that depends on the COSE module
(proposal 002) for cryptographic envelope and corecbor for CBOR
encoding.

CWT is the CBOR analog of JWT (RFC 7519).  It is a claims set encoded
as a CBOR map with integer-keyed standard claims, wrapped in a COSE
message (Sign1, Encrypt0, or Mac0) for integrity/confidentiality.  The
implementation is ~300 LOC of typed claims + validation logic over
the COSE module — zero algorithmic complexity, zero non-stdlib deps.

Blocked on proposal 002 (COSE Phase A — Sign1/Verify1).

---

## Motivation

CWT is the token format for:

- **WebAuthn / FIDO2 attestation** — attestation statements in CBOR
  use CWT-shaped claims for device identity.
- **ACE-OAuth (RFC 9200)** — Authorization in constrained environments
  uses CWT as the access token format.
- **IoT device identity / EAT** — Entity Attestation Tokens (proposal
  005) extend CWT with hardware attestation claims.
- **Matter / Thread / IoT commissioning** — device-to-cloud tokens.
- **CBOR-LD verifiable credentials** — W3C VC data model in CBOR uses
  CWT as the secured envelope.

CWT is trivial structurally — it's a CBOR map with 7 standard claims
(integer keys 1–7) plus arbitrary private claims, wrapped in a COSE
Sign1 or Encrypt0.  But a correct implementation requires:

- Proper claim validation (expiration, not-before, audience matching).
- Integration with COSE Sign1/Verify1 for signed tokens.
- Integration with COSE Encrypt0 for encrypted tokens.
- Nested tokens (signed-then-encrypted, encrypted-then-signed).
- CWT Claims Set encoding in CoreDeterministic mode for
  reproducibility.

A purpose-built CWT module over corecbor/cose avoids the pattern of
every consumer hand-rolling claims parsing on top of raw CBOR decode.

---

## Proposal

### Module structure

```
github.com/jahkeup/corecbor/cwt/     # go.mod: module github.com/jahkeup/corecbor/cwt
├── doc.go                           # Package doc
├── claims.go                        # ClaimsSet type, standard claim accessors
├── token.go                         # Token type (wraps COSE message + claims)
├── sign.go                          # Sign / Verify (delegates to cose.Signer)
├── encrypt.go                       # Encrypt / Decrypt (delegates to cose.Encrypt0)
├── validate.go                      # Claims validation (exp, nbf, aud, ...)
├── claims_test.go
├── token_test.go
├── validate_test.go
└── testdata/
    └── rfc8392-appendix-a/          # Vendored test vectors
```

### Dependency graph

```
github.com/jahkeup/corecbor/cwt
    │
    ├── github.com/jahkeup/corecbor/cose   (Sign1, Encrypt0, Key)
    ├── github.com/jahkeup/corecbor/cbor   (Value types for claims map)
    └── github.com/jahkeup/corecbor/rfc8949 (deterministic encoding)
```

No non-stdlib, non-corecbor dependencies.

### Public API surface

```go
package cwt

import (
    "time"

    "github.com/jahkeup/corecbor/cbor"
    "github.com/jahkeup/corecbor/cose"
)

// ---- Claims (RFC 8392 §3) ----

// ClaimsSet is the CWT Claims Set — a CBOR map with integer-keyed
// standard claims and arbitrary private claims.
type ClaimsSet struct {
    // Standard claims (RFC 8392 §3.1).
    // Zero value means "not present" for all pointer/slice fields.
    Issuer     string     // claim key 1 (iss)
    Subject    string     // claim key 2 (sub)
    Audience   string     // claim key 3 (aud) — single value
    Audiences  []string   // claim key 3 (aud) — array form
    Expiration time.Time  // claim key 4 (exp) — NumericDate
    NotBefore  time.Time  // claim key 5 (nbf) — NumericDate
    IssuedAt   time.Time  // claim key 6 (iat) — NumericDate
    CWTID      []byte     // claim key 7 (cti)

    // Private claims. Keys are int64 or string per CBOR map convention.
    // Standard claim keys (1–7) in this map are ignored in favor of
    // the typed fields above.
    Private map[any]cbor.Value
}

// Get retrieves a private claim by label. Returns nil if not present.
func (c *ClaimsSet) Get(label any) cbor.Value

// Set stores a private claim. label must be int64 or string.
func (c *ClaimsSet) Set(label any, value cbor.Value)

// Encode serializes the ClaimsSet to CBOR bytes using
// CoreDeterministic encoding.
func (c *ClaimsSet) Encode() ([]byte, error)

// DecodeClaimsSet parses a CBOR-encoded claims map.
func DecodeClaimsSet(data []byte) (*ClaimsSet, error)

// ---- Token (the COSE-wrapped CWT) ----

// Token is a CWT — a ClaimsSet wrapped in a COSE security message.
type Token struct {
    Claims  *ClaimsSet
    message any // *cose.Sign1, *cose.Encrypt0, or *cose.Mac0
}

// Sign creates a signed CWT (COSE_Sign1-wrapped claims).
func Sign(claims *ClaimsSet, signer *cose.Signer, opts ...SignOption) ([]byte, error)

// Verify decodes and verifies a signed CWT. Returns the validated
// token on success. Does NOT validate claims (expiration, etc.) —
// call token.Validate() separately.
func Verify(data []byte, verifier *cose.Verifier) (*Token, error)

// Encrypt creates an encrypted CWT (COSE_Encrypt0-wrapped claims).
func Encrypt(claims *ClaimsSet, key []byte, alg cose.Algorithm, opts ...EncryptOption) ([]byte, error)

// Decrypt decodes and decrypts an encrypted CWT.
func Decrypt(data []byte, key []byte, alg cose.Algorithm) (*Token, error)

// ---- Validation ----

// Validator checks claims against a set of requirements.
type Validator struct {
    // Required audience. If set, the token's aud claim must match.
    Audience string

    // Clock skew tolerance for exp/nbf checks.
    Leeway time.Duration

    // Now function for testing. Defaults to time.Now.
    Now func() time.Time

    // RequireExpiration rejects tokens without an exp claim.
    RequireExpiration bool

    // RequireIssuedAt rejects tokens without an iat claim.
    RequireIssuedAt bool

    // Custom claim validators. Each function receives the ClaimsSet
    // and returns an error if validation fails.
    Custom []func(*ClaimsSet) error
}

// Validate checks the token's claims against the validator's rules.
// Returns nil if all checks pass.
func (v *Validator) Validate(t *Token) error

// Common validation errors.
var (
    ErrTokenExpired    = errors.New("cwt: token has expired")
    ErrTokenNotYetValid = errors.New("cwt: token not yet valid (nbf)")
    ErrAudienceMismatch = errors.New("cwt: audience mismatch")
    ErrMissingExpiration = errors.New("cwt: missing required exp claim")
    ErrMissingIssuedAt  = errors.New("cwt: missing required iat claim")
)

// ---- Options ----

type SignOption func(*signOpts)
type EncryptOption func(*encryptOpts)

// WithExternalData sets the COSE external AAD for signing/encryption.
func WithExternalData(aad []byte) SignOption

// WithDetachedPayload creates a token with detached payload
// (claims not included in the COSE message; transmitted separately).
func WithDetachedPayload() SignOption
```

### Behavior

**Signing flow:**
1. Encode `ClaimsSet` → CBOR bytes (CoreDeterministic).
2. Create `cose.Sign1` with the claims bytes as payload.
3. Call `cose.Signer.Sign1()`.
4. Marshal the COSE_Sign1 → final CWT bytes.

**Verification flow:**
1. Unmarshal CWT bytes → `cose.Sign1`.
2. Call `cose.Verifier.Verify1()`.
3. Decode the payload → `ClaimsSet`.
4. Return `Token` (caller validates claims via `Validator`).

**Separation of concerns:**
- Cryptographic verification (is the signature valid?) → COSE module.
- Claims validation (is the token expired? audience match?) → CWT module.
- This mirrors the JWT ecosystem split (jose vs jwt libraries).

### NumericDate encoding

CWT uses "NumericDate" — seconds since Unix epoch as a CBOR integer
or floating-point value (RFC 8392 §2).  The CWT module:

- Encodes `time.Time` as integer seconds when sub-second precision
  is not needed (the common case).
- Encodes as float64 when sub-second precision is present.
- Decodes both integer and float forms (forgiving).
- Uses CoreDeterministic encoding to ensure integer form when possible
  (avoids float→int ambiguity in round-trip).

### Failure modes

```go
var (
    ErrTokenExpired     = errors.New("cwt: token has expired")
    ErrTokenNotYetValid = errors.New("cwt: token not yet valid (nbf)")
    ErrAudienceMismatch = errors.New("cwt: audience mismatch")
    ErrMissingExpiration = errors.New("cwt: missing required exp claim")
    ErrMissingIssuedAt  = errors.New("cwt: missing required iat claim")
    ErrMalformedClaims  = errors.New("cwt: malformed claims set")
    ErrUnsupportedMessage = errors.New("cwt: unsupported COSE message type")
)
```

All errors wrap the relevant sentinel via `fmt.Errorf("%w: ...", err)`.
COSE-layer errors (signature invalid, decryption failed) propagate
from the COSE module without rewrapping.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| RFC 8392 Appendix A vectors decode correctly | `TestRFC8392AppendixA` table test | Yes |
| Sign + Verify round-trip (Ed25519) | `TestSignVerify_Ed25519` | Yes |
| Sign + Verify round-trip (ES256) | `TestSignVerify_ES256` | Yes |
| Encrypt + Decrypt round-trip (AES-GCM-256) | `TestEncryptDecrypt_AESGCM256` | Yes |
| Expired token rejected | `TestValidate_Expired`: token with past exp → `ErrTokenExpired` | Yes |
| Not-yet-valid token rejected | `TestValidate_NotBefore`: token with future nbf → `ErrTokenNotYetValid` | Yes |
| Audience mismatch rejected | `TestValidate_AudienceMismatch` | Yes |
| Leeway tolerance works | `TestValidate_Leeway`: token expired by 1s, leeway=5s → passes | Yes |
| Private claims round-trip | `TestPrivateClaims_RoundTrip`: custom int/string-keyed claims survive encode/decode | Yes |
| NumericDate integer encoding preferred | `TestNumericDate_IntegerPreferred`: time with zero nanos encodes as int, not float | Yes |
| NumericDate float decoding | `TestNumericDate_FloatDecode`: float-encoded timestamp decodes correctly | Yes |
| ClaimsSet deterministic encoding | Same claims encoded twice → byte-equal output | Yes |
| Nested token (sign then encrypt) | `TestNestedToken_SignThenEncrypt` | Yes |
| FuzzDecodeClaimsNeverPanics | 30s fuzz, arbitrary bytes → no panic | Yes |
| No non-stdlib/non-corecbor deps | `go mod graph` | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | ClaimsSet + Sign/Verify (Sign1 only) + Validation | Pending | RFC 8392 Appendix A vectors pass; sign/verify round-trips |
| B | Encrypt/Decrypt (Encrypt0) + Nested tokens + Mac0 | Pending | Encrypted CWT round-trips; nested sign-then-encrypt works |

Phase A is independently shippable and covers the dominant use case
(signed CWTs for access tokens and attestation).

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestRFC8392AppendixA` | Vendored RFC vectors | `token_test.go` |
| `TestSignVerify_*` | Per-algorithm sign+verify | `sign_test.go` (via `token_test.go`) |
| `TestEncryptDecrypt_*` | Per-algorithm encrypt+decrypt | `encrypt_test.go` |
| `TestValidate_*` | Each validation rule | `validate_test.go` |
| `TestClaimsSet_Encode` | Deterministic encoding | `claims_test.go` |
| `TestPrivateClaims_RoundTrip` | Custom claims survive | `claims_test.go` |
| `TestNumericDate_*` | Integer/float encoding/decoding | `claims_test.go` |
| `TestNestedToken_*` | Sign-then-encrypt, encrypt-then-sign | `token_test.go` |
| `FuzzDecodeClaimsNeverPanics` | Adversarial input → no panic | `claims_test.go` |
| `FuzzTokenVerify` | Arbitrary bytes → verify → typed error | `token_test.go` |

---

## Performance

| Metric | Target | Test mechanism |
|---|---|---|
| Sign CWT (Ed25519, 7 standard claims) | ≥ 10,000 ops/s | `BenchmarkSign_Ed25519` |
| Verify CWT (Ed25519, 7 standard claims) | ≥ 10,000 ops/s | `BenchmarkVerify_Ed25519` |
| ClaimsSet encode (7 claims) | 0 allocations (pre-allocated dst) | `-benchmem` |
| ClaimsSet decode | ≤ 2 allocations | `-benchmem` |

Performance limited by COSE signing speed (Ed25519 ~30μs/op on modern
hardware), not by CWT encoding overhead.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| COSE module (002) API instability | medium | medium | CWT pins a specific COSE module version; interface surface is small (Sign1, Verify1, Encrypt0) |
| NumericDate precision loss at extreme timestamps | low | low | Document that sub-microsecond precision is not preserved; use integer encoding when possible |
| Audience claim can be string or array (RFC ambiguity) | medium | low | Support both: `Audience` (single) and `Audiences` (array); encode as array only when multiple values |
| ACE-OAuth extensions (RFC 9200) require additional claims | high | low | Private claims map handles arbitrary extensions; ACE-specific claims are just integer-keyed private claims |

---

## Alternatives considered

### Combine CWT into the COSE module

Rejected. CWT is a consumer of COSE, not part of it. Separating them
allows the COSE module to remain focused on RFC 9052 compliance while
CWT adds application-layer semantics (claims validation, token
lifecycle). This mirrors the JOSE ecosystem (go-jose vs golang-jwt).

### Use `time.Duration` instead of `time.Time` for exp/nbf

Rejected. RFC 8392 defines NumericDate as absolute epoch-seconds.
Using `time.Time` is natural in Go and matches the semantics.
Relative durations are a construction-time concern, not a token-format
concern.

### Skip validation (let callers validate claims)

Rejected. Claims validation is the #1 source of JWT/CWT security
bugs. Providing a correct, tested `Validator` with safe defaults
prevents the class of bugs where callers forget to check expiration
or audience.

---

## Open questions

- **MAC tokens (COSE_Mac0)**: Should CWT support Mac0-wrapped tokens
  in Phase A or defer to Phase B?  Mac0 is simpler than Sign1 (no
  public-key crypto) but less common in practice.  Lean: Phase B.

- **Detached payload**: Should the CWT module support detached
  payloads (claims transmitted separately from the COSE envelope)?
  Some protocols use this for bandwidth savings.  Lean: support via
  option, document the pattern.

- **Confirmation claim (cnf, key 8)**: RFC 8747 defines the
  "confirmation" claim for proof-of-possession tokens.  Should CWT
  model this as a first-class field or leave it in Private claims?
  Lean: first-class in a follow-up after Phase B (it's common enough
  in OAuth/ACE to warrant it).

---

## Cross-references

- RFCs: RFC 8392 — CWT (primary spec).
- RFCs: RFC 7519 — JWT (the JSON analog; informs API design).
- RFCs: RFC 9200 — ACE-OAuth (major CWT consumer).
- RFCs: RFC 8747 — CWT Proof-of-Possession (cnf claim).
- Sibling proposals: `001` (corecbor primitives), `002` (COSE).
- Downstream: proposal `005` (EAT) extends CWT.
- External: `golang-jwt/jwt` — the JWT analog in Go; informative for
  API ergonomics (Validator pattern, Claims interface).

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-20 | Initial draft | corecbor maintainers |
