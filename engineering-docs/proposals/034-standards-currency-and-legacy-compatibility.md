# 034 — Standards currency and legacy-compatibility selection policy

## Header

| Field | Value |
|---|---|
| **Number** | 034 |
| **Tier** | 1 |
| **Status** | Closed |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: none (governs 021–033) |
| **Supersedes** | none |
| **Spec sections touched** | §12 (proposal discipline: new "compatibility" rule); new §14 (API stability + standards currency) |

---

## TL;DR

Proposals 021–033 change wire output, defaults, and code points to track
published standards. Some callers will have deployed peers, stored data,
or partner integrations that depend on today's behavior. This proposal
sets one rule for every module:

1. **The exported API is stable in signature *and* semantics.** A
   documented contract (godoc, `encoder-decoder-spec.md`, or an RFC the
   identifier claims to implement) is API. Existing identifiers keep
   their meaning across v0.30.
2. **New identifiers default to the current standards state**: the
   latest published RFC, its verified errata, and the current IANA
   registries. Deployed-ecosystem interop only breaks ties.
3. **Internet-Drafts are never defaults.** Draft behavior is opt-in,
   named for the draft and revision, and documented as unstable.
4. **Code that contradicts its own documented contract is a defect** and
   is fixed in place. Where callers may depend on the broken behavior,
   a named, deprecated legacy selector restores it. Races, panics and
   memory corruption get no selector.
5. **Where a contract predates the current standard**, the old
   identifier keeps its contract and is deprecated; the standards-current
   behavior arrives under a new identifier, which becomes the
   recommended path.

Acceptance: each of 021–033 carries a "Compatibility selection" section
that classifies its changes under this policy and names the selectors;
§14 lands in `encoder-decoder-spec.md`; `apidiff` against v0.2.2 and
v0.2.2 golden vectors gate every module in `make check`.

---

## Motivation

The 2026-11 review (`../upstream-status-2026-11.md`) found three kinds of
drift:

- **Code that predates the RFC it claims.** EAT uses draft-era claim keys
  (261, 266–268 mean different claims in RFC 9711). EDHOC follows a
  pre-RFC 9528 key schedule. Tokens and sessions already produced by
  this code exist in the field.
- **Standards that moved after the code shipped.** RFC 9864 deprecates
  ES256/ES384/ES512/EdDSA in favor of fully-specified identifiers, but
  WebAuthn/FIDO, mDL, and most COSE verifiers deployed today still emit
  and expect `-7` and `-8`.
- **Drafts close to publication.** draft-ietf-cbor-serialization-13 and
  draft-ietf-cose-hpke-27 are near final; their code points or rules may
  still change.

Without a policy, each proposal invents its own answer, and callers
can't predict whether an upgrade changes the bytes they emit.

---

## Proposal

### API stability (signature and semantics)

For every exported identifier present in v0.2.2, in every module:

- **Signature.** Not allowed: removing or renaming it; changing a
  parameter, result, or struct-field type; adding a method to an
  exported interface. Allowed: new identifiers; new struct fields whose
  zero value preserves existing behavior (exception: a field that bounds
  attacker-controlled work, such as `PBES2Key.MaxCount`, may treat zero
  as a safe documented limit, because unbounded was a safety defect);
  `// Deprecated:` with a pointer to the replacement; appending a
  variadic `...Option` parameter **only if** a call with no options
  behaves exactly as before, apart from defect fixes listed in the same
  proposal (each instance is listed in the migration guide, since
  `apidiff` reports it).
- **Semantics.** The documented behavior of an existing identifier,
  including its zero value and default configuration, does not change.
  The exceptions are **defects**: a safety defect (see Classification),
  or an implementation that contradicts the contract it documents.
  Fixing those is required, not a semantic change.
- **Wrongly-typed API.** When an existing type is unsafe (for example
  `cwt.ClaimsSet.Private map[any]any` panicking on byte-string keys, or
  `cose.Headers.Set` with no error result), fix the internals so the
  old identifier can't panic or silently corrupt, keep its documented
  behavior otherwise, add a correctly-typed replacement beside it, and
  deprecate the old one.

### Precedence for new identifiers and defect fixes

When choosing the behavior of a *new* identifier, or the target of a
defect fix, apply these in order and stop at the first that decides:

1. **The current standards state**: the latest published RFC, its
   verified errata, and the current IANA registry. Examples: EAT claim
   keys follow RFC 9711 and the IANA CWT registry; a new COSE signer
   path emits fully-specified identifiers (`ESP256 (-9)`, `Ed25519
   (-19)`) per RFC 9864.
2. **Deployed-ecosystem interoperability, as a tie-breaker** where the
   standard permits several behaviors equally. Where the ecosystem lags
   the standard (WebAuthn/FIDO and mDL still use `-7`), the standard is
   the default of the new identifier and the existing identifier keeps
   serving the ecosystem behavior.
3. **Existing behavior**, where neither decides (for example Go struct
   field-name casing in reflection): keep it, and add the alternative
   as an opt-in.
4. **Internet-Drafts.** Opt-in only (see "Draft behavior").

On the *accept* side (decode/verify), be liberal where the input is
unambiguous: verify both `-7` and `-9` for P-256. Where two behaviors
are ambiguous on the wire (EAT key 266 is "uptime" in the draft and
"submods" in the RFC), accept only the selected behavior.

### Classification

Every change in a proposal is classified as one of:

| Class | Meaning | Selector? | Example |
|---|---|---|---|
| **Safety defect** | Race, panic, memory corruption; fail-open authentication or validation; attacker-chosen downgrade (e.g. MAC truncation); unbounded attacker-controlled work or allocation | No | 021 data race; `valueToAny` unhashable-key panic; `VerifyMulti` nil error with zero verified; EAT submods accepted unverified; HMAC 256/64 selectable from the message; uncapped PBES2 count |
| **Contract defect** | Implementation contradicts its documented contract (godoc, spec, or the RFC it claims) | Fixed in place; `Legacy…` selector (deprecated on arrival) where callers may depend on the broken bytes | EAT claim keys vs its RFC 9711 claim; EDHOC vs RFC 9528; `RawMessage` re-encoding; `StrictDecoder` vs spec §3.2; PBES2 code-point collisions; `TimeTo` pre-1970 |
| **Superseded contract** | Existing identifier faithfully does what it documents, but the current standard has moved on | Old identifier unchanged + `// Deprecated:`; new identifier carries the standards behavior | polymorphic `-7`/`-8` emission (RFC 9864); zero-value `cwt.Validator` not requiring `exp` |
| **Additive** | New identifier, no existing behavior affected | n/a | tag helpers; receipts; `KeySet` |
| **Draft** | Behavior defined only by an Internet-Draft | Opt-in `Draft…`/Experimental identifier | HPKE (draft-27), serialization checking (draft-13) |

### Public API surface

Selectors are functional options (`DecoderOption`, `SignerOption`,
`EncryptOption`, …) or, where a package already configures through a
struct (`cwt.Validator`), documented struct fields whose zero value
preserves existing behavior. They are named, not boolean bags, so grep
finds every caller relying on legacy behavior.

```go
// Contract defect, legacy selector. The eat package documents RFC 9711;
// the draft-era keys it shipped contradict that, so the default is fixed
// in place and this restores the old bytes.
//
// Deprecated: draft-era EAT claim keys conflict with RFC 9711. Retained
// for reading tokens issued by corecbor <= v0.2. Removed no earlier than
// v0.32.0.
func WithLegacyDraftClaimKeys() eat.Option

// Superseded contract, new identifier. NewSigner keeps emitting the
// polymorphic identifier it documents today (ES256 = -7 for P-256);
// this option is the recommended path and emits RFC 9864 identifiers
// (ESP256 = -9, Ed25519 = -19). Verifiers accept both.
func WithFullySpecifiedAlgorithms() cose.SignerOption

// Superseded contract, new identifier. The zero-value cwt.Validator
// keeps its documented behavior (exp optional). NewValidator is the
// recommended path and starts from current-standards defaults:
// exp required, iat not in the future, exp rejected "on or after".
func NewValidator() *cwt.Validator

// Draft: names the draft and revision it implements.
//
// Experimental: implements draft-ietf-cose-hpke-27. Code points are
// assigned by IANA on publication and WILL change.
func WithDraftHPKE27() cose.EncryptOption
```

Exported constants never change value. Where a constant carries a
colliding or deprecated code point (for example
`AlgPBES2_HS256_A128KW = -11`), add a correctly-valued constant beside
it, deprecate the old one, and switch internal emission to the new one
only if the old emission was a contract defect.

Bundles for callers who want an entire earlier behavior set:

```go
// CompatV02 applies every Legacy* selector needed to reproduce v0.2.x
// wire output for this package. It exists to unblock upgrades, not as
// a long-term mode.
//
// Deprecated: migrate to explicit selectors; removed no earlier than v0.32.0.
func CompatV02() Option
```

Bundles are per module and per option type; there is no cross-module
global switch. **A selector that weakens verification or validation is
never bundled.** The caller must name it explicitly. Bundles only
contain `Legacy…` selectors for contract defects; superseded contracts
need no bundle because the old identifiers keep their behavior.

### Lifecycle

- `Legacy…` and `CompatV02` selectors are `// Deprecated:` from the
  release they appear in and survive at least two minor releases after
  the v0.30 line (removal no earlier than v0.32.0). Removal needs its
  own proposal.
- Identifiers deprecated as **superseded contracts** keep working for
  the life of the v0.x line; deprecation is guidance toward the
  standards-current identifier, not a removal schedule.
- `Draft…` identifiers are replaced when the draft publishes: the RFC
  behavior arrives under a new non-draft identifier, and the `Draft…`
  one is deprecated with a pointer to it.

### Spec change

Add §14 to `encoder-decoder-spec.md` containing the API stability,
Precedence, and Classification sections above, and add a rule to §12: *"A proposal that
changes wire output, validation outcomes, or code points, or touches an
exported identifier, MUST include a Compatibility selection section
classifying each change per §14."*

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| §14 added to the spec and §12 rule added | doc review | Yes |
| 021–033 each contain a "Compatibility selection" section classifying every wire/default/code-point change | doc review | Yes |
| No exported identifier present in v0.2.2 is removed, renamed, or retyped; every appended `...Option` is listed in the migration guide | `apidiff` (golang.org/x/exp) against `v0.2.2` per module, wired into `make check` as a pinned go tool | Yes |
| Existing identifiers keep their documented semantics: v0.2.2 golden vectors (encode output, decode results, validation outcomes) still pass when called with no new options | golden-vector tests per module | Yes |
| Every contract-defect fix lists the contract it restores (godoc line, spec §, or RFC §) | doc review | Yes |
| Every `Legacy…` selector has a test asserting the default and the selected behavior against v0.2.2 bytes | `go test ./...` in each module | Yes |
| No `CompatV02*` bundle includes a selector that weakens verification or validation | test enumerating bundle contents | Yes |
| Every `Legacy…`/`CompatV02` selector carries `// Deprecated:` with a removal floor | `staticcheck` SA1019 fires on use in a fixture | Yes |
| Every `Draft…` identifier names the draft and revision in its doc comment | grep check in `make lint` | No |
| `migration-v0.2-to-v0.30.md` lists every selector and new identifier with before/after bytes | doc review | Yes |

---

## Known decisions under this policy

Recorded here so the per-proposal sections agree. Proposals own the
details.

| Area (proposal) | Class | Existing identifiers in v0.30 | New / selector |
|---|---|---|---|
| Data races, aliasing, panics, embedded structs (021) | Safety defect | fixed | none |
| `TimeTo` pre-1970 emitting a huge uint (021) | Contract defect | fixed | none (output was not a valid time) |
| `RawMessage`/`RawTag` re-encoding (022) | Contract defect (014: "without re-encoding") | original bytes | none |
| `StrictDecoder` rejecting all tags (023) | Contract defect (spec §3.2) | well-known tag allow-list | `WithAllowedTags()` with no IDs reproduces "reject all" |
| Serialization profiles, checking decoders (024) | Draft until RFC | unchanged (RFC 8949 §4.2.1) | `ModePreferredPlus`, `RequirePreferredPlus()` marked Experimental (draft-13) |
| Bignum leading-zero strip / reduction; NaN-key equality per erratum 8589 (024) | Contract defect (modes document RFC 8949 §3.4.3 / §4.2.1; §5.6.1 + erratum) | fixed | `WithLegacyBignumPassthrough()`, `WithLegacyFloatKeyEquality()` |
| COSE alg binding, `crit`, duplicate labels (027) | Contract defect (RFC 9052 §3, §3.1) | enforced | `WithLegacyAlgorithmFromKey()`, `WithLegacyIgnoreCritical()` — never bundled |
| `VerifyMulti` fail-open, `VerifyMACMulti` header-chosen truncation, PBES2 count cap, empty HMAC keys (027) | Safety defect | fixed | none; short (non-empty) HMAC keys still accepted, `WithStrictMACKeyLength()` opt-in |
| Reflection field-name casing (025) | No standard; existing behavior | lowercase (unchanged) | `WithGoFieldNames()`, `WithCaseInsensitiveFieldNames()` opt-in |
| Every `Unmarshaler` receives original bytes, not a re-encoding (022) | Contract defect (`marshal.go:14-18`; maintainer decision) | original bytes | none; re-encoded input may be added later as a new opt-in |
| COSE algorithm emission (029) | Superseded contract (RFC 9864) | `NewSigner` emits `-7`/`-8` as documented; `AlgES256`/`AlgEdDSA` deprecated; verifiers accept both | `WithFullySpecifiedAlgorithms()` (recommended), `AlgESP256`, `AlgEd25519`, … |
| PBES2 / HPKE code-point collisions (029) | Contract defect (claims RFC 9053 / IANA ids) / Draft | new non-colliding constants beside deprecated old ones (e.g. `AlgPrivatePBES2_HS256_A128KW`); emission switched; existing `HPKEKey` unchanged and deprecated | `WithLegacyPBES2Labels()`, `WithLegacyECDHES()`, `WithDraftHPKE27()` |
| CWT `exp` required, issuer/audience, iat checks (031) | Superseded contract | zero-value `Validator` unchanged | `cwt.NewValidator()` with standards defaults (recommended) |
| CWT `exp` accepted at exactly `now` (031) | Contract defect (RFC 8392 → RFC 7519 "on or after") | fixed | none; `Leeway` covers skew |
| CWT `Private map[any]any` panics; `aud` string-only (031) | Wrongly-typed API | old fields kept, internals made panic-free | `PrivateClaims`, `Audiences` beside them; old ones deprecated |
| COSE `Headers.Set` silently writes null (027) | Wrongly-typed API | `Set` kept, now panics-free and documented | `SetChecked(label, v) error` beside it; `Set` deprecated |
| EAT claim keys (032) | Contract defect (package documents RFC 9711) | RFC 9711 / IANA | `WithLegacyDraftClaimKeys()`; eat `CompatV02()` |
| EDHOC key schedule and messages (033) | Contract defect (package documents RFC 9528) | RFC 9528 | `WithLegacyPreRFCProtocol()` for peers running corecbor ≤ v0.2 only; never bundled |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Selector sprawl makes the API hard to read | med | med | Named options only, `CompatV02` bundles, removal floor |
| Legacy paths rot untested | med | high | Acceptance requires a test per selector; legacy golden vectors captured from v0.2.2 before code changes |
| Superseded-contract identifiers linger and new code keeps using them | med | med | `// Deprecated:` pointers + staticcheck SA1019 in `make lint`; godoc of each old identifier names the recommended replacement |
| "Contract defect" stretched to justify semantic changes | med | high | Each fix must cite the contract line it restores (acceptance criterion); golden vectors catch anything else |
| Keeping pre-RFC EDHOC alive invites new deployments of it | low | high | Selector is deprecated on arrival, logs nothing but documents non-interop; no `CompatV02` inclusion for EDHOC |

---

## Alternatives considered

- **Change defaults of existing identifiers to the current standard.**
  Rejected: the API is semantic as well as syntactic; callers upgrading
  without code changes would silently get different bytes and
  validation outcomes.
- **Hard break, no selectors.** Simplest code. Rejected: callers with
  stored EAT tokens or deployed EDHOC peers can't upgrade at all.
- **Global `corecbor.SetCompat(v)`.** Rejected: process-global state,
  untestable, and wrong for multi-tenant services talking to peers of
  different vintages.
- **Version-pinned sub-packages (`eat/v1`, `eat/v2`).** Rejected for
  now: duplicates large surfaces for a handful of differences. Revisit
  if a module's legacy surface exceeds its current surface.

---

## Open questions

- None blocking. Each proposal's open questions cover its own selectors.

---

## Cross-references

- `../upstream-status-2026-11.md` — the drift this policy responds to
- `../release-notes-v0.30-maintainers.md` — version bump and migration guide
- Proposals 021–033

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft | corecbor maintainers |
| 2026-11-20 | Safety defect covers fail-open auth, downgrade, unbounded work; appended-option rule allows listed defect fixes; decisions table synced with amended 021–033 | corecbor maintainers |
| 2026-11-20 | Standards-state-first precedence; API stability is signature + semantics; reclassified changes (contract defect / superseded contract / additive / draft) | corecbor maintainers |
| 2026-11-20 | Bundles per module/option type; never bundle verification-weakening selectors; struct-field selectors (reconciled with 021–033) | corecbor maintainers |
| 2026-11-22 | Status: Closed (acceptance met) | corecbor maintainers |
