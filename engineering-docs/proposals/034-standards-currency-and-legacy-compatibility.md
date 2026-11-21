# 034 — Standards currency and legacy-compatibility selection policy

## Header

| Field | Value |
|---|---|
| **Number** | 034 |
| **Tier** | 1 |
| **Status** | Draft |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: none (governs 021–033) |
| **Supersedes** | none |
| **Spec sections touched** | §12 (proposal discipline: new "compatibility" rule); new §14 (standards currency) |

---

## TL;DR

Proposals 021–033 change wire output, defaults, and code points to track
published standards. Some callers will have deployed peers, stored data,
or partner integrations that depend on today's behavior. This proposal
sets one rule for every module:

1. **Defaults follow what the deployed ecosystem interoperates with
   today, then the latest published RFC and the current IANA registry.**
2. **Internet-Drafts are never defaults.** Draft behavior is opt-in,
   named for the draft and revision, and documented as unstable.
3. **Every intentional wire- or policy-visible change ships with a named
   legacy selector**, so a caller with incompatibilities on their side
   can choose the old behavior explicitly. Pure defects (races, panics,
   memory corruption, malformed output) do not get selectors.

Acceptance: each of 021–033 carries a "Compatibility selection" section
that classifies its changes under this policy and names the selectors;
§14 lands in `encoder-decoder-spec.md`.

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

### Precedence

When choosing a default, apply these in order and stop at the first
that decides:

1. **Interoperability with the deployed ecosystem today.** If the large
   majority of deployed peers emit or require a behavior that a
   published RFC still permits (even if it's deprecated), that behavior
   is the default *for emission*. Example: COSE signers keep emitting
   `ES256 (-7)` for P-256 keys by default.
2. **The latest published RFC and current IANA registry.** Where the
   ecosystem doesn't decide, or where the old behavior is not permitted
   by any published RFC, the RFC wins. Example: EAT claim keys follow
   RFC 9711 and the IANA CWT registry.
3. **Internet-Drafts.** Opt-in only (see "Draft behavior").

On the *accept* side (decode/verify), be liberal where the input is
unambiguous: verify both `-7` and `-9` for P-256. Where the two
behaviors are ambiguous on the wire (EAT key 266 is "uptime" in the
draft and "submods" in the RFC), accept only the selected behavior.

> Interpretation note: "current state of the world" is read here as
> *what deployed peers interoperate with*. If maintainers intend "the
> current standards state", swap steps 1 and 2; the rest of the policy
> is unchanged.

### Classification

Every change in a proposal is classified as one of:

| Class | Meaning | Selector? | Example |
|---|---|---|---|
| **Defect** | Race, panic, memory corruption, or output that is malformed or means something other than intended | No | 021 data race; `TimeTo` pre-1970 emitting a huge uint |
| **Conformance** | Old behavior is well-formed but violates a published RFC or registry | Yes — `Legacy…` selector, deprecated on arrival | EAT draft claim keys; EDHOC pre-RFC key schedule; PBES2 label collisions |
| **Policy** | Old and new behavior are both conformant; the default changes | Yes — option that restores the old default | CWT `exp` required by default; reflection field-name casing |
| **Ecosystem hold** | RFC prefers new behavior, the ecosystem hasn't moved | Yes — option that opts *into* the RFC behavior | RFC 9864 fully-specified algorithm emission |
| **Draft** | Behavior defined only by an Internet-Draft | Yes — opt-in `Draft…` selector | HPKE (draft-27), serialization checking (draft-13) |

### Public API surface

Selectors are functional options, following the existing
`DecoderOption` / `Option` idiom. They are named, not boolean bags, so
grep finds every caller relying on legacy behavior.

```go
// Conformance class: restores pre-RFC behavior. Deprecated on arrival.
//
// Deprecated: draft-era EAT claim keys conflict with RFC 9711. Retained
// for reading tokens issued by corecbor <= v0.2. Removed no earlier than
// v0.32.0.
func WithLegacyDraftClaimKeys() eat.Option

// Policy class: restores the old default.
// (cwt.Validator is a struct, so this one is a field.)
type Validator struct {
	// ...
	AllowMissingExpiration bool
}

// Ecosystem hold: opts into the RFC-preferred behavior early.
func WithFullySpecifiedAlgorithms() cose.SignerOption

// Draft class: names the draft and revision it implements.
//
// Experimental: implements draft-ietf-cose-hpke-27. Code points are
// assigned by IANA on publication and WILL change.
func WithDraftHPKE27() cose.EncryptOption
```

Bundles for callers who want an entire earlier behavior set:

```go
// CompatV02 applies every Legacy*/policy selector needed to reproduce
// v0.2.x wire output and validation defaults for this package. It
// exists to unblock upgrades, not as a long-term mode.
//
// Deprecated: migrate to explicit selectors; removed no earlier than v0.32.0.
func CompatV02() Option
```

Bundles are per module and per option type; there is no cross-module
global switch. **A selector that weakens verification or validation is
never bundled.** The caller must name it explicitly. As drafted:

| Module | Bundles |
|---|---|
| root | `CompatV02() Option` (encode), `CompatV02Decoding() DecoderOption` |
| `cose` | `CompatV02Keys() KeyOption`, `CompatV02Encryption() EncryptOption` |
| `eat` | `CompatV02() Option` (draft claim keys) |
| `cwt`, `edhoc` | none — every selector there weakens verification |

Where a package already configures behavior through a struct (for
example `cwt.Validator`), the selector is a documented field rather
than a functional option.

### Lifecycle

- `Legacy…` and `CompatV02` selectors are `// Deprecated:` from the
  release they appear in and survive at least two minor releases after
  the v0.30 line (removal no earlier than v0.32.0). Removal needs its
  own proposal.
- `Draft…` selectors are renamed (not aliased) when the draft
  publishes. The RFC behavior becomes eligible for default under the
  precedence rules, and the draft selector is removed in the same
  release.
- Ecosystem holds are re-evaluated on each minor release. Flipping one
  is a Policy change and needs a selector restoring the hold.

### Spec change

Add §14 to `encoder-decoder-spec.md` containing the Precedence and
Classification sections above, and add a rule to §12: *"A proposal that
changes wire output, validation defaults, or code points MUST include a
Compatibility selection section classifying each change per §14."*

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| §14 added to the spec and §12 rule added | doc review | Yes |
| 021–033 each contain a "Compatibility selection" section classifying every wire/default/code-point change | doc review | Yes |
| Every Conformance/Policy/Ecosystem/Draft change has a named selector and a test asserting both the default and the selected behavior | `go test ./...` in each module | Yes |
| No `CompatV02*` bundle includes a selector that weakens verification or validation | test enumerating bundle contents | Yes |
| Every `Legacy…`/`CompatV02` selector carries `// Deprecated:` with a removal floor | `staticcheck` SA1019 fires on use in a fixture | Yes |
| Every `Draft…` selector names the draft and revision in its doc comment | grep check in `make lint` | No |
| `migration-v0.2-to-v0.30.md` lists every selector with before/after bytes | doc review | Yes |

---

## Known decisions under this policy

Recorded here so the per-proposal sections agree. Proposals own the
details.

| Area (proposal) | Class | Default (v0.30) | Selector |
|---|---|---|---|
| Data races, aliasing, panics, `TimeTo` negative, embedded structs (021) | Defect | fixed | none |
| `RawMessage`/`RawTag` re-encoding (022) | Defect | original bytes | none |
| `StrictDecoder` rejecting all tags (023) | Defect vs §3.2 | well-known tag allow-list | `WithAllowedTags()` with no IDs reproduces "reject all" |
| Serialization profiles, checking decoders (024) | Draft until RFC; RFC 8949 rules stay default | RFC 8949 §4.2.1 | `RequirePreferredPlus()` etc. documented as draft-13 until publication |
| Bignum leading-zero strip / reduction to major 0/1; float map-key equality per erratum 8589 (024) | Conformance (RFC 8949 §3.4.3, §5.6.1) | on | `WithLegacyBignumPassthrough()`, `WithLegacyFloatKeyEquality()` |
| COSE alg binding, `crit`, duplicate labels, HMAC key minimums (027) | Conformance | enforced | `WithLegacyAlgorithmFromKey()`, `WithLegacyIgnoreCritical()`, `WithLegacyShortHMACKeys()` — never bundled |
| Reflection field-name casing (025) | Policy | Go field name as-is (matches ecosystem: fxamacker/cbor, encoding/json) | `WithLowercaseFieldNames()` |
| Fully-specified COSE algorithms (029) | Ecosystem hold | emit `-7`/`-8`; verify both old and new | `WithFullySpecifiedAlgorithms()` |
| PBES2 / HPKE code-point collisions (029) | Conformance / Draft | non-colliding private-use values; HPKE draft-27 behind selector | `WithLegacyPBES2Labels()`, `WithLegacyECDHES()`, `WithLegacyHPKE()`, `WithDraftHPKE27()` |
| CWT `exp` required, issuer/audience checks (031) | Policy | required | `Validator.AllowMissingExpiration` (field; not bundled) |
| EAT claim keys (032) | Conformance | RFC 9711 / IANA | `WithLegacyDraftClaimKeys()` |
| EDHOC key schedule and messages (033) | Conformance | RFC 9528 | `WithLegacyPreRFCProtocol()` for peers running corecbor ≤ v0.2 only |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Selector sprawl makes the API hard to read | med | med | Named options only, `CompatV02` bundles, removal floor |
| Legacy paths rot untested | med | high | Acceptance requires a test per selector; legacy golden vectors captured from v0.2.2 before code changes |
| "Ecosystem" judgment is subjective | med | low | Holds listed explicitly in the table above, re-evaluated each minor release |
| Keeping pre-RFC EDHOC alive invites new deployments of it | low | high | Selector is deprecated on arrival, logs nothing but documents non-interop; no `CompatV02` inclusion for EDHOC |

---

## Alternatives considered

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

- Should `CompatV02` in the root package also force the v0.2 field-name
  casing, or is that one too visible to bundle? (Leaning: include it;
  that's the point of the bundle.)

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
| 2026-11-20 | Bundles per module/option type; never bundle verification-weakening selectors; struct-field selectors (reconciled with 021–033) | corecbor maintainers |
