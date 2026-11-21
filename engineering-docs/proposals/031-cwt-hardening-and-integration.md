# 031 — CWT hardening and ACE / SCITT integration

## Header

| Field | Value |
|---|---|
| **Number** | 031 |
| **Tier** | 3 |
| **Status** | Draft |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 003 (CWT), 012 (cnf), 021 (core safety), 022 (raw-byte preservation), 023 (strict decode policy), 027 (COSE verification hardening), 028 (COSE header / key API), 034 (compatibility policy) |
| **Supersedes** | none (amends 003 and 012) |
| **Spec sections touched** | none — sibling module `cwt/` |

---

## TL;DR

The `cwt` module decodes and verifies tokens, but it has four problems:

- A malformed claims set can **panic** it.
- It applies **no time validation** unless the caller builds a
  `Validator` by hand. Even then `exp` is optional, a token is accepted
  at exactly `exp`, and a nil validator panics.
- It **rejects tag-61 CWTs**.
- It has no support for the ACE (RFC 9200) or SCITT (RFC 9597)
  integration points that its likely consumers need.

This proposal does four things:

1. Make claims decoding total: typed claim keys, no panics, duplicate
   keys rejected, memory budget on.
2. Make validation fail closed by default.
3. Add one `Verify` entry point that combines verification and
   validation and resolves the key through a context-aware resolver.
4. Add the missing standard claims and envelope handling.

Acceptance: `FuzzDecodeClaimsSet` runs 60 s with no panics. A
zero-configuration `cwt.Verify` rejects expired, not-yet-valid and
`exp`-less tokens. Tag-61, untagged and RFC 9597 header-carried claims
round-trip. Every error satisfies `errors.Is` against both the `cwt`
sentinel and the underlying `corecbor` / `cose` sentinel.

---

## Motivation

The review of `main@00e1307` (2026-11-20) confirmed the following by
reading the code. The panic was also reproduced with a throwaway probe.

| # | Defect | Evidence |
|---|---|---|
| 1 | **Panic on untrusted input.** A claim keyed by a bstr, array or map reaches `cs.Private[fromValue(key)]`. `fromValue` returns `[]byte` or `corecbor.Value`, neither of which is hashable, so the map assignment panics. | `cwt/claims.go:121-127`, `:183-187`, `:264-283` |
| 2 | **Key aliasing.** `entryKeyInt` converts with a plain `int64(...)` cast, which wraps. NegInt `-(2^64-1)` (n = 2^64−2) becomes `-1 - (-2) = 1` and decodes as `iss`. Uint ≥ 2^63 becomes negative. | `cwt/claims.go:224-233` |
| 3 | **Numeric dates aren't range-checked.** A uint above MaxInt64 wraps to a negative time. That fails closed for `exp` but **fails open for `nbf`**. NaN and ±Inf floats go through `int64(NaN)`, which is implementation-defined. | `cwt/claims.go:206-222` |
| 4 | **`Verify` returns claims with no time checks.** `cwt.Verify` verifies the signature and decodes. Validation is a separate opt-in step, and EDHOC's CWT-credential path skips it (`edhoc/credential.go:43`). | `cwt/token.go:28-39` |
| 5 | **The zero `Validator` accepts tokens without `exp`.** `RequireExpiration` is opt-in. | `cwt/validate.go:12,22` |
| 6 | **`exp` boundary is off by one.** `now.After(exp + leeway)` accepts `now == exp`. RFC 8392 §3.1.4 says the token MUST NOT be accepted "on or after" `exp`. | `cwt/validate.go:31` |
| 7 | **A nil `*Validator` panics** (`v.Now` is dereferenced). A negative `Leeway` is accepted and silently tightens the window. There is no check for an issuer or for `iat` in the future. | `cwt/validate.go:16-47` |
| 8 | **`aud` must be a single string.** RFC 9200 §5.10.1 and EAT profiles use arrays; such tokens fail with "aud must be text". | `cwt/claims.go:145-151` |
| 9 | **Tag 61 is rejected.** `cose.UnmarshalSign1` rejects any tag other than 18, so `61(18([...]))` fails. Untagged COSE is accepted, but the caller can't require a tag. | `cose/marshal.go:64-79` |
| 10 | **`cnf` is incomplete.** `Encrypted` is modeled as a bstr, but RFC 8747 §3.3 defines `COSE_Encrypt` / `COSE_Encrypt0`. OKP keys are assumed to be Ed25519 without checking `crv`, so an X25519 key is misread. Symmetric (kty 4) keys are unsupported. Unknown members and multiple methods are accepted silently. `kid` and `alg` on the key are dropped. | `cwt/claims.go:303-342`, `:430-439` |
| 11 | **Oversized EC2 coordinates are truncated silently.** `padLeftBytes` returns oversize input unchanged, then `copy` into a fixed-width slot truncates it. | `cwt/claims.go:380-387`, `:470-473` |
| 12 | **Decoding is lenient.** `corecbor.NewDecoder()` accepts duplicate map keys, so a second `exp` overwrites the first. No memory budget is set. | `cwt/claims.go:108` |
| 13 | **Underlying errors are flattened with `%v`,** so `errors.Is(err, corecbor.ErrMemoryBudgetExceeded)` and similar checks are false. | `cwt/token.go:31`, `cwt/claims.go:111,155,161,167,180`, `cwt/encrypt.go:33,64` |
| 14 | **The caller supplies the Encrypt0 nonce, and it isn't written to the IV header.** Decryption needs it out of band, which invites reuse. | `cwt/encrypt.go:15,30` |
| 15 | **Private claims can collide with registered claims.** Their int keys aren't checked, so `Private[int64(1)]` emits a duplicate key 1. | `cwt/claims.go:90-100` |

### Consumers

- **ACE resource servers (RFC 9200 / 9203).** They need `aud` arrays,
  `scope` (9), `ace_profile` (38), `cnonce` (39), `exi` (40), symmetric
  `cnf` for the OSCORE profile, and fail-closed time validation.
- **SCITT (RFC 9943, RFC 9597).** Issuer and subject travel in the
  COSE protected header under label 15, not in the payload.
- **EAT (proposal 032)** embeds `ClaimsSet` and inherits every decode
  and validation defect above.
- **EDHOC (proposal 033)** uses CWT/CCS credentials, and RFC 9528
  §3.5.2 requires validating them.

---

## Proposal

### Public API surface

#### Claim keys and private claims

```go
// ClaimKey is a CWT claim label: an integer or a text string
// (RFC 8392 §4). It is comparable and safe to use as a map key.
type ClaimKey struct {
	Int    int64
	Text   string
	IsText bool
}

func IntKey(n int64) ClaimKey
func TextKey(s string) ClaimKey

// Registered claim keys (IANA "CBOR Web Token (CWT) Claims").
const (
	ClaimIss        int64 = 1
	ClaimSub        int64 = 2
	ClaimAud        int64 = 3
	ClaimExp        int64 = 4
	ClaimNbf        int64 = 5
	ClaimIat        int64 = 6
	ClaimCti        int64 = 7
	ClaimCnf        int64 = 8   // RFC 8747
	ClaimScope      int64 = 9   // RFC 9200 §5.10.1
	ClaimNonce      int64 = 10  // RFC 9711
	ClaimACEProfile int64 = 38  // RFC 9200
	ClaimCNonce     int64 = 39  // RFC 9200
	ClaimExi        int64 = 40  // RFC 9200
)

type ClaimsSet struct {
	Issuer       string
	Subject      string
	Audience     Audience // was string
	Expiration   time.Time
	NotBefore    time.Time
	IssuedAt     time.Time
	CWTID        []byte
	Confirmation *Confirmation
	Scope        *Scope  // nil when absent
	ACEProfile   *int64  // nil when absent
	CNonce       []byte
	Exi          *uint64 // seconds; nil when absent

	// Private holds every claim this package does not model, keyed
	// by label, with the decoded value. Values alias the decoder's
	// output; use corecbor.Value.Clone to retain them past the decode
	// buffer when ZeroCopy is in use.
	Private map[ClaimKey]corecbor.Value
}

// Audience is the "aud" claim: a single StringOrURI or an array of
// them (RFC 9200 §5.10.1). Encodes as a text string when it has one
// element.
type Audience []string

func (a Audience) Contains(s string) bool

// Scope is the ACE "scope" claim: text (space-separated) or bytes
// (RFC 9200 §5.8.1).
type Scope struct {
	Text  string
	Bytes []byte
	IsText bool
}
```

`Private` changes from `map[any]any` to `map[ClaimKey]corecbor.Value`.
This breaks the API, which is acceptable for a pre-1.0 sibling module,
and it fixes defects 1, 2 and 15 together:

- Decode rejects keys that are neither int nor text, returning
  `ErrMalformedClaims` wrapped in a `*ClaimError`.
- Integer keys outside the int64 range are rejected.
- Encode rejects any `Private` key that collides with a registered
  claim this package models.

#### Numeric dates

```go
// NumericDate is the RFC 8392 §2 NumericDate: seconds since the
// epoch as an int or float. Decoding rejects values outside
// [MinNumericDate, MaxNumericDate] and non-finite floats.
type NumericDate struct{ time.Time }

func (d NumericDate) MarshalCBORValue() corecbor.Value
func ParseNumericDate(v corecbor.Value) (NumericDate, error)
```

The `eat` module (proposal 032) uses the same type, which removes its
duplicate `parseNumericDate` (`eat/claims.go:443-452`). That copy has no
float support, and its encoder has the pre-1970 wraparound
(`eat/claims.go:102-108`).

#### Validation

```go
type Validator struct {
	Issuers   []string      // when non-empty, iss MUST be one of these
	Audience  string        // when set, aud MUST contain it
	Leeway    time.Duration // MUST be >= 0
	MaxAge    time.Duration // when > 0, iat MUST be within MaxAge of now
	Now       func() time.Time

	// AllowMissingExpiration disables the default exp requirement.
	// Policy-class selector (proposal 034): restores the v0.2 default.
	AllowMissingExpiration bool
	// AllowFutureIssuedAt disables the iat-in-the-future check.
	// Policy-class selector (proposal 034): restores the v0.2 default.
	AllowFutureIssuedAt bool
	RequireConfirmation bool
	RequireIssuedAt     bool
}

// DefaultValidator returns a Validator that requires exp, uses a
// 60 s leeway, and rejects iat more than Leeway in the future.
func DefaultValidator() *Validator

// Validate checks claims against v. A nil v behaves like
// DefaultValidator().
func (v *Validator) Validate(claims *ClaimsSet) error
```

Semantics:

| Check | Rule |
|---|---|
| `exp` | Reject when `!now.Before(exp.Add(leeway))` ("on or after", RFC 8392 §3.1.4). |
| `nbf` | Reject when `now.Before(nbf.Add(-leeway))`. |
| `iat` | Reject when it is after `now + leeway`. With `MaxAge > 0`, also reject when it is before `now - MaxAge - leeway`. |
| Leeway | A negative leeway returns `ErrInvalidValidator`. |

**Migration:** `RequireExpiration bool` is replaced by
`AllowMissingExpiration bool`, which inverts the default. The proposal
accepts this break, and the changelog must call it out. The zero
`Validator{}` now requires `exp`.

#### Verify entry point

```go
// KeyResolver returns the verification key for a message. It is
// called after the protected header is parsed and before any
// cryptographic operation. Implementations MUST NOT trust
// unprotected header values for key selection unless the deployment
// profile allows it.
type KeyResolver interface {
	ResolveKey(ctx context.Context, h *cose.Headers, alg cose.Algorithm) (crypto.PublicKey, error)
}

// KeyResolverFunc adapts a function to KeyResolver.
type KeyResolverFunc func(ctx context.Context, h *cose.Headers, alg cose.Algorithm) (crypto.PublicKey, error)

type VerifyOptions struct {
	Keys      KeyResolver
	Validator *Validator // nil: DefaultValidator()

	// RequireTag requires the outer CWT tag 61 (RFC 8392 §6).
	RequireTag bool
	// AllowedAlgorithms restricts the protected alg (proposal 027).
	AllowedAlgorithms []cose.Algorithm
}

// Token is a verified CWT and its COSE envelope.
type Token struct {
	Protected   *cose.Headers
	Unprotected *cose.Headers
	Claims      *ClaimsSet
	Tagged      bool // outer tag 61 was present
}

// Verify parses data (optionally tag-61 wrapped, COSE_Sign1 tagged
// or untagged), resolves the key, verifies the signature, checks
// typ/cty when present, decodes the claims strictly and validates
// them. It is the recommended entry point.
func Verify(ctx context.Context, data []byte, opts VerifyOptions) (*Token, error)
```

The existing `Verify(data, verifier)` is renamed to `VerifySignature`
and documented as "signature only; caller MUST validate". MAC
(`VerifyMAC`) and Encrypt0 (`Decrypt`) get the same treatment.

#### Envelope and headers

Envelope handling:

- **Tag 61:** strip an outer tag 61, then require one of tags 18, 17 or
  16 inside it, or an untagged COSE array of the expected shape (RFC 8392
  §6). Reject anything else with `ErrMalformedClaims`.
- **`typ` (label 16, RFC 9596):** if present, it MUST equal
  `"application/cwt"` or CoAP content-format 61. A mismatch returns
  `ErrUnexpectedType`. This depends on proposal 028 providing
  `Headers.Type()`.
- **`cty` (label 3):** if present, it MUST NOT indicate a nested
  non-CWT payload. Nested CWT (`cty` = 61, RFC 8392 §7.1 step 6) is
  supported via `VerifyOptions.MaxNesting` (default 1).

Integration helpers:

```go
// RFC 9597: CWT claims carried in a COSE protected header (label 15).
const HeaderLabelCWTClaims int64 = 15

// ClaimsFromHeaders decodes the label-15 claims map from h.
func ClaimsFromHeaders(h *cose.Headers) (*ClaimsSet, bool, error)

// SetClaimsHeader encodes c into h under label 15. RFC 9597 §2
// requires the protected bucket for claims that must be integrity-protected.
func SetClaimsHeader(h *cose.Headers, c *ClaimsSet) error
```

**UCCS (RFC 9781):** `TagUCCS = 601`. Add `DecodeUCCS(data []byte)
(*ClaimsSet, error)`, which strips tag 601 and decodes. Its doc comment
MUST say that UCCS is unprotected and relies on a secure channel (RFC
9781 §3).

**Encrypt0:** `Encrypt` generates a random IV and writes it to the
unprotected IV header (label 5). `Decrypt` reads it from there, so the
nonce parameters are removed. This depends on proposal 029 for the COSE
side. Tokens encrypted by v0.2 carry no IV header; they stay readable
through `DecryptWithNonce(data []byte, key []byte, nonce []byte)
(*ClaimsSet, error)`, which is `// Deprecated:` (removal floor
v0.32.0).

#### Confirmation (RFC 8747)

```go
type Confirmation struct {
	Key       *cose.Key        // 1: COSE_Key (EC2, OKP, Symmetric)
	Encrypted *EncryptedKey    // 2: COSE_Encrypt0 or COSE_Encrypt (was []byte)
	KeyID     []byte           // 3: kid
}

type EncryptedKey struct {
	Encrypt0 *cose.Encrypt0
	Encrypt  *cose.Encrypt
}

// Match reports whether pub is the key bound by c (by value or kid).
func (c *Confirmation) Match(k *cose.Key) bool
```

Decode rules:

- Exactly one confirmation method must be present. More than one
  returns `ErrMalformedClaims`, because RFC 8747 §3.1 defines a single
  method per `cnf`.
- An unknown member is an error unless `DecodeOptions.AllowUnknownCnf`
  is set.

```go
// DecodeOptions adjusts claims decoding. The zero value is the v0.30
// default.
type DecodeOptions struct {
	// AllowUnknownCnf accepts cnf members other than 1, 2 and 3
	// (ignored), as v0.2 did. Policy-class selector.
	AllowUnknownCnf bool

	// AllowDuplicateClaims restores v0.2's last-one-wins handling of
	// duplicate claim keys.
	//
	// Deprecated: duplicate claims make exp/nbf ambiguous (RFC 8392
	// §7.2); removed no earlier than v0.32.0.
	AllowDuplicateClaims bool
}

func DecodeClaimsSetWith(data []byte, opts DecodeOptions) (*ClaimsSet, error)
```

`VerifyOptions` gains a `Decode DecodeOptions` field.
- OKP keys MUST carry `crv`. Ed25519 and X25519 are distinguished
  instead of assumed.
- EC2 coordinates must be exactly the curve size.
- Key decoding moves to `cose.ParseKey` (proposal 028). The private
  `unmarshalCOSEKey` / `coseKeyFromMaps` duplicates in `cwt/claims.go`
  and `edhoc/credential.go` are removed.

### Behavior

| Before | After |
|---|---|
| `DecodeClaimsSet` panics on a bstr / array / map claim key | Returns `*ClaimError{Key, Err: ErrMalformedClaims}` |
| Duplicate claim → last wins | Rejected (`corecbor.ErrDuplicateMapKey` wrapped) |
| `cwt.Verify(data, v)` → no time checks | `cwt.Verify(ctx, data, opts)` validates by default; the old function is renamed `VerifySignature` |
| `Validator{}` accepts no-`exp` tokens | Rejects; opt out via `AllowMissingExpiration` |
| `now == exp` accepted | Rejected |
| `61(18([...]))` rejected | Accepted |
| `aud: ["a","b"]` rejected | Accepted; `Audience.Contains` |

### Failure modes

New sentinels in `cwt/errors.go`:
`ErrIssuerMismatch`, `ErrIssuedInFuture`, `ErrTokenTooOld`,
`ErrUnexpectedType`, `ErrInvalidValidator`, `ErrKeyResolution`.

```go
// ClaimError reports which claim failed and why. Err wraps a cwt
// sentinel and, where applicable, the underlying corecbor/cose error.
type ClaimError struct {
	Key ClaimKey
	Err error
}

func (e *ClaimError) Error() string
func (e *ClaimError) Unwrap() error
```

All `fmt.Errorf("%w: %v", ...)` sites become `fmt.Errorf("%w: %w", ...)`
so both errors stay in the chain (Go ≥ 1.20 multi-`%w`).

---

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).
Defaults follow RFC 8392 / 8747 / 9200 and fail closed.

`AllowMissingExpiration()` in 034's decision table is the
`Validator.AllowMissingExpiration` field here, because `cwt` configures
validation with a struct, not functional options.

| Change | Class | Default (v0.30) | Selector |
|---|---|---|---|
| Non-scalar claim keys → `*ClaimError`, no panic; key overflow aliasing; private/registered key collision | Defect | error | none — defect |
| NumericDate range/NaN checks (`nbf` failed open) | Defect | error | none — defect |
| Nil `*Validator` no longer panics; negative leeway → `ErrInvalidValidator` | Defect | fixed | none — defect |
| `exp` rejected "on or after" (RFC 8392 §3.1.4) | Defect (off-by-one vs MUST) | `now == exp` rejected | none — `Leeway` covers clock tolerance |
| `exp` required by default | Policy | required | `Validator.AllowMissingExpiration bool` |
| `iat` in the future rejected by default | Policy | rejected | `Validator.AllowFutureIssuedAt bool` |
| `cwt.Verify` validates by default; old signature-only function | Policy | validating `Verify(ctx, data, opts)` | `VerifySignature(data, verifier)` (the v0.2 `Verify`, renamed; not deprecated, documented "caller MUST validate") |
| Duplicate claim keys rejected | Conformance (RFC 8392 §7.2) | rejected | `DecodeOptions.AllowDuplicateClaims` — Deprecated |
| `cnf`: exactly one method; OKP requires `crv`; unknown members rejected | Conformance (RFC 8747 §3.1) / Policy (unknown members) | rejected | `DecodeOptions.AllowUnknownCnf` for unknown members; none for multiple methods or missing `crv` (ambiguous key binding) |
| `typ` checked when present (RFC 9596) | Conformance | checked | none — v0.2 never emitted `typ`, so no v0.2 token is affected |
| Tag 61, untagged COSE, `aud` arrays accepted; UCCS, RFC 9597 header bridge, ACE claims | Additive (widening) | accepted | n/a |
| Encrypted CWT IV in label 5; `Decrypt` takes no nonce | Conformance (RFC 9052 §3.1, via 029) | IV in header | `DecryptWithNonce(...)` — Deprecated, reads v0.2 tokens |

**No `cwt.CompatV02` bundle.** Every `cwt` selector except
`DecryptWithNonce` relaxes token validation. Under 027's bundling rule,
selectors that weaken verification must be named at the call site, so a
bundle would be empty or unsafe. (Flagged for 034: its "each module
exports CompatV02" note doesn't apply to `cwt`.)

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| No panic on any input to `DecodeClaimsSet`, `Verify`, `ClaimsFromHeaders`, `DecodeUCCS` | `FuzzDecodeClaimsSet`, `FuzzVerify` 60 s | Yes |
| bstr / array / map claim key → `*ClaimError` wrapping `ErrMalformedClaims` | `TestDecodeClaims_NonScalarKey` | Yes |
| NegInt `-(2^64-1)` key does not alias `iss` | `TestDecodeClaims_KeyOverflow` | Yes |
| uint `exp`/`nbf` > MaxInt64, NaN, ±Inf → error | `TestNumericDate_Range` | Yes |
| Duplicate `exp` → error wrapping `corecbor.ErrDuplicateMapKey` | `TestDecodeClaims_DuplicateKey` | Yes |
| `Validator{}` rejects missing `exp`; `nil` validator does not panic | `TestValidator_Defaults` | Yes |
| `now == exp` rejected; `now == exp - 1ns` accepted (leeway 0) | `TestValidator_ExpBoundary` | Yes |
| Negative leeway → `ErrInvalidValidator` | `TestValidator_NegativeLeeway` | Yes |
| `iat` > now+leeway → `ErrIssuedInFuture` | `TestValidator_FutureIat` | Yes |
| `aud` text and array both decode; `Contains` matches | `TestAudience_StringOrArray` | Yes |
| RFC 8392 Appendix A.3 signed CWT verifies with tag 61 and without | `TestVerify_RFC8392_A3` (vector already used by `cwt_test.go`; add tagged form) | Yes |
| `typ: "application/cwt"` accepted; other `typ` rejected | `TestVerify_TypHeader` | Yes |
| RFC 9597 label-15 claims round-trip through `SetClaimsHeader` / `ClaimsFromHeaders` | `TestClaimsHeader_RoundTrip` | Yes |
| UCCS tag 601 decodes | `TestDecodeUCCS` | Yes |
| `cnf` with two methods → error; OKP without `crv` → error; X25519 not read as Ed25519 | `TestCnf_*` | Yes |
| `cnf` symmetric key (kty 4) round-trips | `TestCnf_Symmetric` | Yes |
| `errors.Is(err, corecbor.ErrMemoryBudgetExceeded)` true through `DecodeClaimsSet` | `TestErrors_WrapChain` | Yes |
| Encrypted CWT carries its IV in label 5; `Decrypt` needs no nonce argument | `TestEncrypt_IVHeader` | Yes |
| RFC 8392, 8747, 9200, 9596, 9597, 9781 vendored under `engineering-docs/rfcs/` with inventory rows | file review | Yes |
| Each selector reproduces v0.2.2 acceptance on its fixture (no-`exp` token, future `iat`, duplicate `exp`, unknown `cnf` member, IV-less encrypted token) and the default rejects it | `TestCompat*` vs `testdata/legacy-v0.2.2/` | Yes |
| `VerifySignature` behaves exactly like v0.2.2 `Verify` on the RFC 8392 A.3 vector | `TestCompatVerifySignature` | Yes |
| `DecodeOptions.AllowDuplicateClaims` and `DecryptWithNonce` carry `// Deprecated:` with removal floor v0.32.0 | staticcheck SA1019 fixture | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | Total decode: `ClaimKey`, `Private` redesign, key/date range checks, duplicate rejection, budget, `%w` chain, `ClaimError` | Pending | Fuzz + `TestDecodeClaims_*` pass |
| B | Fail-closed `Validator` + new `Verify(ctx, …)` + `KeyResolver` | Pending | `TestValidator_*`, `TestVerify_*` pass |
| C | Envelope: tag 61, `typ`/`cty`, nested CWT, UCCS, RFC 9597 header bridge | Pending | Envelope tests pass (requires 028 `Headers` accessors) |
| D | ACE claims (`scope`, `ace_profile`, `cnonce`, `exi`) + `cnf` completion + Encrypt0 IV | Pending | `TestCnf_*`, `TestEncrypt_IVHeader` pass (requires 029) |

Phase A has no dependency outside this module and should land first,
because it removes a crash on untrusted input.

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `FuzzDecodeClaimsSet` | arbitrary bytes → typed error, never panic | `cwt/fuzz_test.go` (new) |
| `FuzzVerify` | arbitrary envelope bytes with a fixed key | same |
| `TestDecodeClaims_*` | key types, overflow, duplicates, dates | `cwt/claims_test.go` |
| `TestValidator_*` | defaults, boundaries, leeway, iat, issuer | `cwt/validate_test.go` |
| `TestVerify_*` | tag 61, untagged, typ, nested, resolver errors | `cwt/token_test.go` |
| `TestCnf_*` | RFC 8747 §3 examples | `cwt/cnf_test.go` |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Fail-closed defaults break existing callers that relied on `exp`-less tokens | med | med | `AllowMissingExpiration` opt-out; changelog entry; `eat` and `edhoc` updated in the same PR series |
| `Private` type change breaks callers | med | low | Pre-1.0; `ClaimKey` helpers make migration mechanical |
| Phase C/D blocked on COSE proposals 028/029 | med | low | Phases A/B are independent and carry the safety fixes |
| Nested-CWT recursion DoS | low | med | `MaxNesting` default 1, hard cap 4 |

---

## Alternatives considered

**Keep `map[any]any` and skip unhashable keys.** Rejected. Silently
dropping claims breaks round-trips, and the map still can't tell
`int64(1)` apart from `int(1)`.

**Keep `Verify` signature-only and document "call Validate".** Rejected.
That is the current state, and the in-tree consumer
(`edhoc/credential.go:43`) already forgets to call `Validate`.

**Model `aud` as `string` plus `ExtraAudiences []string`.** Rejected as
clumsy. `Audience []string`, encoding as text when it has one element,
is wire-compatible with RFC 8392.

---

## Open questions

- Should `DefaultValidator` leeway be 60 s or 0? ACE deployments
  usually configure leeway explicitly. 60 s matches common JWT
  libraries.
- Should `VerifyOptions` carry a `crit` allow-list, or delegate fully
  to proposal 027's `cose.VerifyOptions`? The leaning is to embed
  `cose.VerifyOptions`.

### Verify during implementation

- RFC 9200 §5.10.1 audience semantics. Confirm the RFC says array
  `aud` membership rather than exact-set match.
- Whether `exi` (40) must be enforced against a stored first-seen time.
  That needs RS-side state, which may be out of scope for a stateless
  validator.

### Watch items (do not implement yet)

- `draft-ietf-spice-sd-cwt` (selective-disclosure CWT). IANA has
  **temporarily** registered claim 11 `vct` (2025-12-02), and
  publication has been requested. Track it; don't model it until the
  draft becomes an RFC.
- IANA CWT registry additions with no RFC (e.g. CAT claims 308-323,
  `status_list` 65533, `ttl` 65534). They surface through `Private`
  with no special handling.

---

## Cross-references

- RFCs: RFC 8392 §3, §6, §7.1. RFC 8747 §3. RFC 9200 §5.8.1 and
  §5.10. RFC 9596. RFC 9597 §2. RFC 9781. RFC 9943 (SCITT
  architecture).
- IANA: "CBOR Web Token (CWT) Claims" registry (updated 2026-11-13).
- Sibling proposals: 003, 012, 021, 022, 023, 027, 028, 029, 032, 033.

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft from 2026-11-20 codebase review | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
