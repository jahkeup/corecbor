# 031 — CWT hardening and ACE / SCITT integration

## Header

| Field | Value |
|---|---|
| **Number** | 031 |
| **Tier** | 3 |
| **Status** | Closed |
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

1. Make claims decoding total: typed claim keys (beside the existing
   `Private` map), no panics, duplicate keys rejected, memory budget on.
2. Add `cwt.NewValidator()`, which fails closed with current-standards
   defaults. The zero-value `Validator` keeps its v0.2.2 behavior, per
   proposal 034 (existing identifiers keep their semantics).
3. Add one new `VerifyToken` entry point that combines verification and
   validation and resolves the key through a context-aware resolver.
   The existing `Verify` keeps its signature-only meaning.
4. Add the missing standard claims and envelope handling.

Acceptance: `FuzzDecodeClaimsSet` runs 60 s with no panics. A
zero-configuration `cwt.VerifyToken` rejects expired, not-yet-valid and
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
	Raw    string // encoded key for non-int/text labels (malformed per RFC 8392 §4, kept for diagnostics)
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

// Existing fields keep their names, types and v0.2.2 meaning
// (proposal 034). New fields are appended; their zero values change
// nothing.
type ClaimsSet struct {
	Issuer       string
	Subject      string
	Audience     string // unchanged: the single-string form
	Expiration   time.Time
	NotBefore    time.Time
	IssuedAt     time.Time
	CWTID        []byte
	Confirmation *Confirmation

	// Private is the v0.2.2 catch-all, unchanged in type. Decode no
	// longer panics: claims whose key is not hashable as a Go map key
	// (bstr, array, map) are omitted here and appear only in
	// PrivateClaims.
	//
	// Deprecated: use PrivateClaims.
	Private map[any]any

	// --- new in v0.3 ---

	// Audiences is the "aud" claim in either form (RFC 9200 §5.10.1:
	// a StringOrURI or an array of them). For a single-string aud,
	// Audience == Audiences[0]. Encoding uses Audiences when it has
	// more than one element, and otherwise Audience.
	Audiences []string

	Scope      *Scope  // RFC 9200 claim 9; nil when absent
	ACEProfile *int64  // claim 38; nil when absent
	CNonce     []byte  // claim 39
	Exi        *uint64 // claim 40, seconds; nil when absent

	// PrivateClaims holds every claim this package does not model,
	// keyed by label, with the decoded value. Values alias the
	// decoder's output; use corecbor.Value.Clone to retain them past
	// the decode buffer when ZeroCopy is in use.
	PrivateClaims map[ClaimKey]corecbor.Value
}

// ContainsAudience reports whether s is the aud claim or one of its
// elements.
func (c *ClaimsSet) ContainsAudience(s string) bool

// Scope is the ACE "scope" claim: text (space-separated) or bytes
// (RFC 9200 §5.8.1).
type Scope struct {
	Text  string
	Bytes []byte
	IsText bool
}
```

`Private` keeps its v0.2.2 type, per proposal 034; the correctly typed
`PrivateClaims` is added beside it and `Private` is deprecated. This
fixes defects 1, 2 and 15 without breaking the API:

- Decode never panics. Keys that are neither int nor text go only into
  `PrivateClaims` (which can hold them via `ClaimKey`'s text/int form
  plus a new `ClaimKey.Raw []byte` for other key types), not `Private`.
- Integer keys outside the int64 range no longer wrap onto registered
  keys: −(2^64−1) is a private claim, not `iss`.
- Encode rejects a `Private` or `PrivateClaims` key that collides with
  a registered claim this package models (v0.2.2 emitted a map with
  duplicate keys).
- Claims 9, 38, 39 and 40, which v0.2.2 put in `Private`, now populate
  the typed fields **and** stay in `Private` (so v0.2.2 readers of
  `Private[int64(9)]` see no change). They do not appear in
  `PrivateClaims`. On encode, a typed field and a `Private` entry for
  the same key must agree, or `Encode` returns `ErrMalformedClaims`.
- If both `Private` and `PrivateClaims` are set, `PrivateClaims` wins
  for keys present in both only when the values are equal; otherwise
  `Encode` returns `ErrMalformedClaims`.

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
// Validator keeps its v0.2.2 fields and zero-value behavior: exp and
// iat checks are opt-in, exactly as before. New fields are appended;
// their zero values change nothing.
type Validator struct {
	Audience            string        // unchanged; now also matches an element of Audiences
	Leeway              time.Duration // unchanged
	Now                 func() time.Time
	RequireExpiration   bool // unchanged
	RequireConfirmation bool // unchanged

	// --- new in v0.3 ---
	Issuers              []string      // when non-empty, iss MUST be one of these
	MaxAge               time.Duration // when > 0, iat MUST be within MaxAge of now
	RequireIssuedAt      bool
	RejectFutureIssuedAt bool // iat after now+Leeway → ErrIssuedInFuture
}

// NewValidator returns a Validator with current-standards defaults:
// RequireExpiration, RejectFutureIssuedAt, and a 60 s Leeway. It is the
// recommended way to build a Validator; the zero value keeps v0.2.2
// behavior.
func NewValidator() *Validator

// Validate checks claims against v. Calling it on a nil *Validator
// returns ErrInvalidValidator (v0.2.2 panicked).
func (v *Validator) Validate(claims *ClaimsSet) error
```

Semantics:

| Check | Rule |
|---|---|
| `exp` | Reject when `!now.Before(exp.Add(leeway))` ("on or after", RFC 8392 §3.1.4 → RFC 7519 §4.1.4). Applies to every `Validator`; v0.2.2 accepted `now == exp`. |
| `nbf` | Reject when `now.Before(nbf.Add(-leeway))` (unchanged). |
| `iat` | With `RejectFutureIssuedAt`, reject when after `now + leeway`. With `MaxAge > 0`, also reject when before `now - MaxAge - leeway`. |
| `aud` | When `Audience` is set, it must equal `claims.Audience` or appear in `claims.Audiences`. For single-string tokens this is the v0.2.2 rule. |
| Leeway | Unchanged: any value, as in v0.2.2. `NewValidator` sets 60 s. |

**Migration:** none required. `Validator{}` behaves as in v0.2.2 apart
from the `exp` boundary fix. Callers adopt the standards defaults with
`cwt.NewValidator()`.

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
	Validator *Validator // nil: NewValidator()

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

// VerifyToken parses data (optionally tag-61 wrapped, COSE_Sign1
// tagged or untagged), resolves the key, verifies the signature,
// checks typ/cty when present, decodes the claims strictly and
// validates them. It is the recommended entry point.
func VerifyToken(ctx context.Context, data []byte, opts VerifyOptions) (*Token, error)

// VerifyMACToken and OpenToken are the COSE_Mac0 and COSE_Encrypt0
// counterparts, with the same options plus the MAC / content key.
func VerifyMACToken(ctx context.Context, data []byte, key []byte, opts VerifyOptions) (*Token, error)
func OpenToken(ctx context.Context, data []byte, key []byte, opts VerifyOptions) (*Token, error)
```

The existing `Verify(data, verifier)`, `VerifyMAC` and `Decrypt` keep
their names, signatures and v0.2.2 meaning (signature/MAC/decryption
only, no time validation), per proposal 034. Their godoc gains
"does not validate claims; use VerifyToken or call Validator.Validate".
They pick up only the contract-defect fixes listed under Compatibility
selection (tag 61 accepted, no panics, duplicate claims rejected).

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

**Encrypt0:** the existing `Encrypt(claims, key, nonce, alg)` and
`Decrypt(data, key, nonce, alg)` keep their signatures and v0.2.2
behavior (caller-supplied nonce, no IV header) and are deprecated. New
`Seal(claims *ClaimsSet, key []byte, alg cose.Algorithm, opts
...cose.EncryptOption) ([]byte, error)` generates a random IV and writes
it to the unprotected IV header (label 5), via 029's `Encrypt0Seal`;
`OpenToken` reads it from there.

#### Confirmation (RFC 8747)

```go
type Confirmation struct {
	Key       *cose.Key // 1: COSE_Key (EC2, OKP, Symmetric) — unchanged
	KeyID     []byte    // 3: kid — unchanged
	// Encrypted keeps its v0.2.2 type. On decode it holds the encoded
	// bytes of member 2 (the bstr v0.2.2 emitted, or the encoded
	// COSE_Encrypt0/COSE_Encrypt array RFC 8747 §3.3 specifies). On
	// encode it is emitted as a bstr, as in v0.2.2.
	//
	// Deprecated: use EncryptedKey, which encodes per RFC 8747 §3.3.
	Encrypted []byte

	// EncryptedKey is member 2 as RFC 8747 §3.3 defines it. New in v0.3;
	// takes precedence over Encrypted on encode.
	EncryptedKey *EncryptedKey
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
  method per `cnf` (v0.2.2 silently kept all of them).
- Unknown members are ignored, as in v0.2.2. `DecodeOptions.RejectUnknownCnf`
  opts into rejecting them.

```go
// DecodeOptions adjusts claims decoding. The zero value is exactly
// DecodeClaimsSet's behavior.
type DecodeOptions struct {
	// RejectUnknownCnf rejects cnf members other than 1, 2 and 3.
	// Opt-in; DecodeClaimsSet ignores them, as in v0.2.2.
	RejectUnknownCnf bool

	// AllowDuplicateClaims restores v0.2's last-one-wins handling of
	// duplicate claim keys.
	//
	// Deprecated: duplicate claims make exp/nbf ambiguous (RFC 8392
	// §7.2); removed no earlier than v0.5.0.
	AllowDuplicateClaims bool
}

func DecodeClaimsSetWith(data []byte, opts DecodeOptions) (*ClaimsSet, error)
```

`VerifyOptions` gains a `Decode DecodeOptions` field.
- OKP keys MUST carry `crv` (RFC 9053 §7.2). Ed25519 and X25519 are
  distinguished instead of assumed (v0.2.2 read an X25519 key as an
  Ed25519 key).
- EC2 coordinates follow 028: oversize rejected, short left-padded as
  in v0.2.2.
- Key decoding moves to `cose.ParseKey` (proposal 028). The private
  `unmarshalCOSEKey` / `coseKeyFromMaps` duplicates in `cwt/claims.go`
  and `edhoc/credential.go` are removed.

### Behavior

| Before (v0.2.2) | After (v0.3) |
|---|---|
| `DecodeClaimsSet` panics on a bstr / array / map claim key | No panic; the claim lands in `PrivateClaims` only |
| −(2^64−1) claim key decodes as `iss` | Decodes as a private claim |
| Duplicate claim → last wins | Rejected (`corecbor.ErrDuplicateMapKey` wrapped); `DecodeOptions.AllowDuplicateClaims` restores v0.2.2 |
| `cwt.Verify(data, v)` → no time checks | Unchanged. `cwt.VerifyToken(ctx, data, opts)` is the new validating entry point |
| `Validator{}` accepts no-`exp` tokens | Unchanged. `cwt.NewValidator()` requires `exp` |
| `now == exp` accepted | Rejected |
| `nil.Validate(c)` panics | `ErrInvalidValidator` |
| `61(18([...]))` rejected | Accepted (by `Verify` and `VerifyToken`) |
| `aud: ["a","b"]` rejected | Accepted; `Audiences`, `ContainsAudience` |
| Multiple `cnf` methods kept | Rejected |

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
No exported identifier is removed, renamed or retyped: `ClaimsSet`,
`Confirmation` and `Validator` keep every v0.2.2 field with its type,
and `Sign`, `Verify`, `Encrypt`, `Decrypt`, `MAC`, `VerifyMAC`,
`DecodeClaimsSet` keep their signatures and meaning. The standards-
current behavior arrives in new identifiers (`NewValidator`,
`VerifyToken`, `VerifyMACToken`, `OpenToken`, `Seal`, `Audiences`,
`PrivateClaims`, `EncryptedKey`).

| Change | Class | Contract restored | Existing identifiers in v0.3 | Selector |
|---|---|---|---|---|
| Non-scalar claim keys no longer panic | Safety defect | — | omitted from `Private`, present in `PrivateClaims` | none |
| Out-of-range int keys alias registered claims; private/registered key collision on encode | Contract defect | RFC 8392 §4 (claim keys are int or text; registered keys mean the registered claim) | not aliased; collision → `ErrMalformedClaims` | none |
| NumericDate range/NaN checks (`nbf` failed open) | Safety defect | — | out-of-range → error | none |
| Nil `*Validator` | Safety defect (panic) | — | `ErrInvalidValidator` | none |
| `exp` rejected "on or after" | Contract defect | RFC 8392 §3.1.4 → RFC 7519 §4.1.4 ("on or after") | `now == exp` rejected | none (`Leeway` covers clock tolerance) |
| `exp` required, future `iat` rejected, issuer allow-list, max age | Superseded contract | — | zero-value `Validator` unchanged | `cwt.NewValidator()` (recommended); new fields `Issuers`, `MaxAge`, `RequireIssuedAt`, `RejectFutureIssuedAt` |
| Verify + validate in one call; typ/cty checks | Additive (new identifier) | — | `Verify`/`VerifyMAC`/`Decrypt` unchanged (signature/MAC/decrypt only) | `VerifyToken`, `VerifyMACToken`, `OpenToken` |
| Duplicate claim keys rejected | Contract defect | RFC 8392 §7.2 (validation fails on duplicate claims) | rejected | `DecodeClaimsSetWith(data, DecodeOptions{AllowDuplicateClaims: true})` — field Deprecated. Not bundled |
| Multiple `cnf` methods rejected; OKP without `crv` rejected | Contract defect | RFC 8747 §3.1 (one method per cnf); RFC 9053 §7.2 (`crv` required for OKP) | rejected | none (ambiguous key binding) |
| Unknown `cnf` members | unchanged | — | ignored, as v0.2.2 | `DecodeOptions.RejectUnknownCnf` (opt-in) |
| Tag 61 accepted around COSE | Contract defect | RFC 8392 §6 (CWT tag 61 MAY wrap the COSE message) | accepted | none |
| `aud` arrays | Additive (input v0.2.2 rejected) | — | `Audience` holds single-string aud as before | `Audiences`, `ContainsAudience` |
| ACE claims 9/38/39/40 | Additive | — | still present in `Private` as in v0.2.2 | typed fields |
| `cnf` member 2 per RFC 8747 §3.3 | Superseded contract | — | `Encrypted []byte` unchanged, deprecated | `EncryptedKey` |
| Encrypted CWT IV in label 5 | Superseded contract | — | `Encrypt`/`Decrypt` unchanged (caller nonce), deprecated | `Seal` / `OpenToken` |
| UCCS, RFC 9597 header bridge | Additive | — | n/a | `DecodeUCCS`, `ClaimsFromHeaders`, `SetClaimsHeader` |

**No `cwt.CompatV02` bundle.** The only `Legacy`-style selector
(`AllowDuplicateClaims`) weakens validation and must be named at the
call site; everything else keeps v0.2.2 behavior in the existing
identifiers. No `...Option` parameters are appended to existing
functions.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| No panic on any input to `DecodeClaimsSet`, `Verify`, `ClaimsFromHeaders`, `DecodeUCCS` | `FuzzDecodeClaimsSet`, `FuzzVerify` 60 s | Yes |
| bstr / array / map claim key decodes without panic into `PrivateClaims` only (not `Private`) | `TestDecodeClaims_NonScalarKey` | Yes |
| NegInt `-(2^64-1)` key does not alias `iss` | `TestDecodeClaims_KeyOverflow` | Yes |
| uint `exp`/`nbf` > MaxInt64, NaN, ±Inf → error | `TestNumericDate_Range` | Yes |
| Duplicate `exp` → error wrapping `corecbor.ErrDuplicateMapKey` | `TestDecodeClaims_DuplicateKey` | Yes |
| `NewValidator()` rejects missing `exp`; `nil` validator returns `ErrInvalidValidator` | `TestValidator_Defaults` | Yes |
| `now == exp` rejected; `now == exp - 1ns` accepted (leeway 0) | `TestValidator_ExpBoundary` | Yes |
| With `RejectFutureIssuedAt` (set by `NewValidator`), `iat` > now+leeway → `ErrIssuedInFuture` | `TestValidator_FutureIat` | Yes |
| `aud` text and array both decode into `Audiences`; text also into `Audience`; `ContainsAudience` matches | `TestAudience_StringOrArray` | Yes |
| RFC 8392 Appendix A.3 signed CWT verifies with tag 61 and without | `TestVerify_RFC8392_A3` (vector already used by `cwt_test.go`; add tagged form) | Yes |
| `VerifyToken`: `typ: "application/cwt"` accepted, other `typ` rejected; `Verify` ignores `typ` as in v0.2.2 | `TestVerify_TypHeader` | Yes |
| RFC 9597 label-15 claims round-trip through `SetClaimsHeader` / `ClaimsFromHeaders` | `TestClaimsHeader_RoundTrip` | Yes |
| UCCS tag 601 decodes | `TestDecodeUCCS` | Yes |
| `cnf` with two methods → error; OKP without `crv` → error; X25519 not read as Ed25519 | `TestCnf_*` | Yes |
| `cnf` symmetric key (kty 4) round-trips | `TestCnf_Symmetric` | Yes |
| `errors.Is(err, corecbor.ErrMemoryBudgetExceeded)` true through `DecodeClaimsSet` | `TestErrors_WrapChain` | Yes |
| `Seal` writes its IV in label 5 and `OpenToken` needs no nonce; `Encrypt`/`Decrypt` reproduce v0.2.2 bytes | `TestSeal_IVHeader`, `TestEncryptUnchanged` | Yes |
| RFC 8392, 8747, 9200, 9596, 9597, 9781 vendored under `engineering-docs/rfcs/` with inventory rows | file review | Yes |
| `DecodeOptions{AllowDuplicateClaims: true}` reproduces v0.2.2 acceptance of a duplicate-`exp` token and the default rejects it | `TestCompatDuplicateClaims` vs `testdata/legacy-v0.2.2/` | Yes |
| `Verify` behaves exactly like v0.2.2 on the RFC 8392 A.3 vector | `TestCompatVerify` | Yes |
| `DecodeOptions.AllowDuplicateClaims` carries `// Deprecated:` with removal floor v0.5.0; `Private`, `Confirmation.Encrypted`, `Encrypt`, `Decrypt` carry `// Deprecated:` pointing to their replacements | staticcheck SA1019 fixture | Yes |
| No exported identifier present in v0.2.2 is removed, renamed, or retyped, and no method is added to an exported interface (034 API stability) | `apidiff` against `v0.2.2` for this module, run in `make check` | Yes |
| Existing identifiers called with no new options reproduce the v0.2.2 golden vectors, except the contract-defect fixes listed under Compatibility selection | `testdata/legacy-v0.2.2/` golden tests | Yes |
| `Validator{}` accepts a token without `exp` and with a future `iat` (v0.2.2); `NewValidator()` rejects both | `TestValidatorZeroUnchanged`, `TestNewValidatorDefaults` | Yes |
| `cwt.Verify` returns claims for an expired token (signature-only, as v0.2.2); `VerifyToken` rejects it | `TestVerifyUnchanged`, `TestVerifyTokenValidates` | Yes |
| Decoding claim 9 populates `Scope` and leaves `Private[int64(9)]` as in v0.2.2 | `TestACEClaimsPrivateCompat` | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | Total decode: `ClaimKey`, `PrivateClaims` beside `Private`, key/date range checks, duplicate rejection, budget, `%w` chain, `ClaimError` | Done | Fuzz + `TestDecodeClaims_*` pass |
| B | Fail-closed `Validator` + new `Verify(ctx, …)` + `KeyResolver` | Done | `TestValidator_*`, `TestVerify_*` pass |
| C | Envelope: tag 61, `typ`/`cty`, nested CWT, UCCS, RFC 9597 header bridge | Done | Envelope tests pass (requires 028 `Headers` accessors) |
| D | ACE claims (`scope`, `ace_profile`, `cnonce`, `exi`) + `cnf` completion + Encrypt0 IV | Done | `TestCnf_*`, `TestEncrypt_IVHeader` pass (requires 029) |

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
| Callers keep using the zero-value `Validator` / `Verify` and never get fail-closed checks | high | med | Godoc on both points to `NewValidator`/`VerifyToken`; in-tree consumers (`eat`, `edhoc`) switch in the same PR series |
| `Private` and `PrivateClaims` drift apart on encode | med | low | Encode rejects conflicting values; `Private` deprecated |
| Phase C/D blocked on COSE proposals 028/029 | med | low | Phases A/B are independent and carry the safety fixes |
| Nested-CWT recursion DoS | low | med | `MaxNesting` default 1, hard cap 4 |

---

## Alternatives considered

**Retype `Private` to `map[ClaimKey]corecbor.Value`.** Cleaner, but it
retypes an exported field. Rejected under proposal 034; `PrivateClaims`
is added beside it instead.

**Make `Verify` validate by default (renaming the old one).** It would
fix forgetful callers such as `edhoc/credential.go:43`, but changes the
meaning of an existing identifier and renames another. Rejected under
034; `VerifyToken` is the new, recommended entry point and in-tree
callers move to it.

**Retype `aud` to `[]string`.** Wire-compatible, but retypes an exported
field. Rejected under 034; `Audiences` is added beside `Audience`.

---

## Open questions

- Should `NewValidator` leeway be 60 s or 0? ACE deployments
  usually configure leeway explicitly. 60 s matches common JWT
  libraries.
- Should `VerifyOptions` carry a `crit` allow-list, or delegate fully
  to proposal 027's `cose.VerifyOptions`? The leaning is to embed
  `cose.VerifyOptions`.

### Verify during implementation

- RFC 9200 §5.10.1 audience semantics. Confirm the RFC says array
  `aud` membership rather than exact-set match.
  **Resolved:** RFC 9200 §5.10.1 is the authorization-information
  endpoint and does not define array `aud`. RFC 8392 §3.1.3 makes `aud`
  a single StringOrURI; the array form and its membership semantics
  come from RFC 7519 §4.1.3 (JWT), which ACE and EAT deployments carry
  over. Accepting arrays is therefore a deliberate superset of RFC
  8392; `Validator.Audience` matches by membership.
- Whether `exi` (40) must be enforced against a stored first-seen time.
  That needs RS-side state, which may be out of scope for a stateless
  validator.
  **Resolved:** RFC 9200 §5.10.3 requires the RS to record when it
  first received each token and to track expired token identifiers.
  That is per-deployment state, so `Validator` does not enforce `exi`;
  it is decoded into `ClaimsSet.Exi` for the caller's store.

### Implementation notes (2026-11-21)

- **KeyResolver:** `VerifyOptions.Keys` is `cose.KeyResolver`
  (proposal 028), not the cwt-local `KeyResolver` sketched above. It
  returns `[]*cose.Key`, so each key's `alg` and `key_ops` apply, and
  `cose.WithAllowedAlgorithms` carries `AllowedAlgorithms`. Resolver
  failures wrap `ErrKeyResolution`.
- **MAC/decrypt algorithm choice:** `VerifyMACToken` and `OpenToken`
  take raw key bytes with no algorithm, so the algorithm comes from the
  protected header and must be in `AllowedAlgorithms`. The default list
  is the full-length HMACs (5, 6, 7) and AES-GCM (1, 2, 3); HMAC 256/64
  must be listed explicitly, which closes the header-chosen truncation
  downgrade 027 closed for multi-recipient MACs. RFC 8392 A.4 (HMAC
  256/64) verifies with `AllowedAlgorithms: {AlgHMAC256_64}`.
- **`Seal`** generates a 12-byte IV and writes it to the unprotected IV
  header itself; it does not depend on 029. AES-CCM (RFC 8392 A.5+)
  arrives with 029.
- **Nested CWT** (`cty` 61 or `"application/cwt"`) is supported for
  COSE_Sign1 inside COSE_Sign1, validated at the innermost level;
  `Token.Nested` holds the inner token. `MaxNesting`: 0 means 1,
  negative forbids nesting. MAC/Encrypt0 outer layers with a CWT `cty`
  return `ErrUnexpectedType`.
- **`Private` is not yet marked `// Deprecated:`.** `edhoc/credential.go`
  still reads `claims.Private[cnf]` as a fallback (dead under 031:
  `cnf` always decodes into `Confirmation`), and deprecating the field
  would fail `make check` (staticcheck SA1019) in a module this change
  doesn't own. Add the marker when that read is removed (033 follow-up).
  `Confirmation.Encrypted`, `Encrypt`, `Decrypt` and
  `DecodeOptions.AllowDuplicateClaims` are deprecated as specified.
- **Encode collisions:** a claim emitted from more than one place (a
  modeled field, `Private`, `PrivateClaims`) is accepted when the
  values are equal and rejected otherwise. v0.2.2 also let `Private`
  carry a registered key when the modeled field was empty; that still
  works.
- **ACE claims with the wrong CBOR type** (e.g. integer `scope`) leave
  the typed field nil and stay in `Private` and `PrivateClaims`,
  rather than failing the decode, so v0.2.2 inputs keep decoding.
- **Encoding a symmetric `cnf` key** emits it as is; asymmetric keys are
  reduced to their public parameters (as v0.2.2 did), so a private key
  passed by mistake doesn't leak. RFC 8747 §3.3 requires symmetric keys
  to travel in an encrypted CWT or an Encrypted_COSE_Key; that is the
  caller's responsibility.
- **Byte stability of float NumericDates:** a float epoch passes
  through `time.Time` nanoseconds, which a float64 can't always
  represent, so encode → decode → encode can move a sub-second date by
  a nanosecond (unchanged from v0.2.2). `FuzzDecodeClaimsSet` checks
  that re-encoded output decodes, not byte stability.
- **Decode budget:** 8 MiB per claims decode.
- **Vectors:** RFC 8392 Appendix A.3 (ES256; tagged 18, tag 61 wrapped,
  untagged) and A.4 (HMAC 256/64 in tag 61) verify through `Verify`,
  `VerifyMAC`, `VerifyToken` and `VerifyMACToken`.

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
| 2026-11-20 | API stability (signature + semantics) per revised 034 | corecbor maintainers |
| 2026-11-21 | Implemented (phases A–D on feat/031-cwt); RFC 9200 audience and exi questions resolved; implementation notes | corecbor maintainers |
| 2026-11-22 | `ClaimsSet.Private` marked `// Deprecated:` (use `PrivateClaims`) now that edhoc no longer reads it (033 follow-ups); closes the implementation-notes gap | corecbor maintainers |
| 2026-11-22 | Status: Closed (acceptance met) | corecbor maintainers |
