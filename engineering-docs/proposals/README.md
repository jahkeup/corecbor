# corecbor proposals — index

This file is the denormalized view of the `proposals/NNN-*.md` files.
The status header inside each proposal is the source of truth; this
table is the convenient summary.

See `../README.md` for tier definitions, status definitions, and
proposal lifecycle.

## Active proposals

| # | Tier | Status | Title | Owner | Depends on | Last update |
|---|---|---|---|---|---|---|
| [015](015-tinygo-support-and-profiling.md) | 2 | Draft | TinyGo latent support and performance profiling | corecbor maintainers | 001 | 2026-05-21 |
| [016](016-value-tagged-union-struct.md) | 1 | Draft | Replace Value interface with tagged-union struct | corecbor maintainers | 001 | 2026-05-22 |
| [017](017-cose-encoder-reuse.md) | 2 | Draft | COSE encoder reuse strategy | corecbor maintainers | 001, 016 | 2026-05-22 |
| [018](018-opt-in-performance-extensions.md) | 2 | Draft | Opt-in performance extensions for complex use cases | corecbor maintainers | 001, 016 | 2026-05-23 |
| [019](019-encode-throughput-recovery.md) | 2 | Draft | Encode path throughput recovery | corecbor maintainers | 016 | 2026-05-24 |
| [020](020-default-decode-recovery.md) | 1 | Draft | Default-path decode recovery and residual throughput fixes | corecbor maintainers | 016, 018, 019 | 2026-05-24 |
| [025](025-value-accessors-and-reflection-ergonomics.md) | 2 | Draft | Value accessors and reflection ergonomics | corecbor maintainers | 008, 016, 021 | 2026-11-20 |
| [026](026-tag-helpers-and-registry-refresh.md) | 2 | Draft | Tag helpers for published CBOR tag RFCs, and registry refresh | corecbor maintainers | 006, 021, 023 | 2026-11-20 |
| [028](028-cose-signing-and-key-api.md) | 3 | Draft | COSE signing headers, detached payloads, and COSE_Key API | corecbor maintainers | 002, 011, 027 | 2026-11-20 |
| [029](029-cose-algorithms-and-encryption-conformance.md) | 3 | Draft | COSE algorithm registry alignment and encryption conformance | corecbor maintainers | 002, 027, 028 | 2026-11-20 |
| [030](030-cose-hash-envelope-and-receipts.md) | 3 | Draft | COSE Hash Envelope, COSE Receipts, and SCITT signed statements | corecbor maintainers | 027, 028, 029, 031 | 2026-11-20 |
| [031](031-cwt-hardening-and-integration.md) | 3 | Draft | CWT hardening and ACE / SCITT integration | corecbor maintainers | 003, 012, 021, 022, 023, 027, 028 | 2026-11-20 |
| [032](032-eat-rfc9711-conformance.md) | 3 | Draft | EAT: RFC 9711 conformance | corecbor maintainers | 005, 022, 027, 031 | 2026-11-20 |
| [033](033-edhoc-rfc9528-conformance-rewrite.md) | 3 | Draft | EDHOC: RFC 9528 conformance rewrite | corecbor maintainers | 004, 022, 028, 031 | 2026-11-20 |
| [034](034-standards-currency-and-legacy-compatibility.md) | 1 | Draft | Standards currency and legacy-compatibility selection policy | corecbor maintainers | — | 2026-11-20 |
| [035](035-invalid-utf8-text-policy.md) | 1 | Accepted | Caller-selected representation of text that is not valid UTF-8 | corecbor maintainers | 021, 023, 034 | 2026-11-21 |

## Closed proposals

| # | Tier | Status | Title | Owner | Closed | Outcome |
|---|---|---|---|---|---|---|
| [024](024-serialization-profiles-alignment.md) | 1 | Closed | Serialization alignment and caller-selected map key identity | corecbor maintainers | 2026-11-21 | Erratum 8589; one key-identity rule at every map size + WithMapKeyIdentity/KeepDuplicateMapKeys; preferred bignums; CTAP2 NaN; RequireDeterministic; Experimental PreferredPlus. Strict >16-key decode ~+15% accepted. |
| [023](023-strict-decode-policy-and-errors.md) | 1 | Closed | Strict decode policy (tag allowlist) and structured errors | corecbor maintainers | 2026-11-21 | StrictDecoder matches spec §3.2; WithAllowedTags/TagsModeled/TagsWellKnown; *DecodeError with offset (+ optional path), *UnmarshalTypeError; err113 enforces sentinel wrapping. |
| [027](027-cose-verification-hardening.md) | 3 | Closed | COSE verification hardening | corecbor maintainers | 2026-11-21 | Verify over received protected bytes; fail-closed multi-verify; alg binding, crit, duplicate labels; typed headers, decode limits; cose fuzz in CI. |
| [022](022-raw-byte-preservation.md) | 1 | Closed | Raw byte preservation through decode | corecbor maintainers | 2026-11-20 | DecodePrefix/DecodeRaw/Cursor; every Unmarshaler gets original bytes; Permissive RawMessage/RawTag splice; Cursor rejects what Decode rejects. apicheck clean. |
| [021](021-core-codec-safety-fixes.md) | 1 | Closed | Core codec safety fixes | corecbor maintainers | 2026-11-20 | D1–D19: concurrency, arena aliasing, panics on untrusted input, embedded structs, time/bignum, stream encoder, DecodeFrom, wire well-formedness, diagnostics. apicheck clean; golden changes allowlisted. |
| [001](001-phase-1-foundational-primitives.md) | 1 | Closed | Phase 1: Foundational primitives | corecbor maintainers | 2026-05-20 | All acceptance criteria met. Phases 1-4 implemented. §9 perf targets exceeded. |
| [002](002-cose-structures-and-signing.md) | 3 | Closed | COSE structures and cryptographic operations | corecbor maintainers | 2026-05-21 | Phases A-E complete. Sign1, Encrypt0, Mac0, multi-recipient, AES-KW, ECDH-ES, PBES2, HPKE, key escrow patterns. |
| [003](003-cwt-cbor-web-tokens.md) | 3 | Closed | CWT: CBOR Web Tokens | corecbor maintainers | 2026-05-21 | Phases A-B complete. Sign/Verify/Encrypt/Decrypt/MAC + Validator. |
| [004](004-edhoc-key-exchange.md) | 3 | Superseded | EDHOC: Ephemeral DH Over COSE | corecbor maintainers | 2026-05-21 | Superseded 2026-11-20 by [033](033-edhoc-rfc9528-conformance-rewrite.md): shipped protocol core is pre-RFC 9528 and never passed RFC 9529 traces. |
| [005](005-eat-entity-attestation.md) | 3 | Closed | EAT: Entity Attestation Tokens | corecbor maintainers | 2026-05-21 | Phases A-C complete. Claims, SW measurements, profile, submodules. |
| [006](006-iana-registry-sync-codegen.md) | 2 | Closed | IANA CBOR registry sync + codegen | corecbor maintainers | 2026-05-21 | Full IANA fetch (260 tags), codegen tool, go:embed registry. |
| [007](007-cross-library-compatibility-testing.md) | 2 | Closed | Cross-library compatibility testing | corecbor maintainers | 2026-05-21 | 55 vectors (41 canonical + 14 quirky), 209 test cases. |
| [008](008-reflective-marshal-unmarshal.md) | 1 | Closed | Reflective Marshal/Unmarshal API | corecbor maintainers | 2026-05-21 | Marshal/Unmarshal + struct tags + Marshaler/Unmarshaler interfaces. |
| [009](009-diagnostic-notation.md) | 2 | Closed | CBOR Diagnostic Notation | corecbor maintainers | 2026-05-21 | Diagnostic() + DiagnosticValue() + DiagCompact option. |
| [010](010-cbor-sequences.md) | 2 | Closed | CBOR Sequences (RFC 8742) | corecbor maintainers | 2026-05-21 | Sequence type + EncodeSequence/DecodeSequence/MarshalSequence. |
| [011](011-cose-multi-signer.md) | 3 | Closed | COSE_Sign + COSE_Mac multi-signer | corecbor maintainers | 2026-05-21 | SignMulti/VerifyMulti/AddSignature + ComputeMACMulti/VerifyMACMulti. |
| [012](012-cwt-proof-of-possession.md) | 3 | Closed | CWT cnf claim (RFC 8747) | corecbor maintainers | 2026-05-21 | Confirmation type + RequireConfirmation validator. |
| [013](013-diagnostic-cli.md) | 2 | Closed | Diagnostic CLI | corecbor maintainers | 2026-05-21 | cmd/cbor-diag with -hex/-compact/-sequence flags. |
| [014](014-raw-message-and-tag-wrapping.md) | 1 | Closed | RawMessage + RawTag + tag=N | corecbor maintainers | 2026-05-21 | RawMessage, RawTag types + cbor:\",tag=N\" struct tag option. |

## Numbering

Next available proposal number: **036**

Numbers are assigned at filing and never reused. Withdrawn / Rejected
proposals keep their numbers — the historical record matters more than
sequence compactness.

## Quick filters

- **Tier-1, blocking:** [001](001-phase-1-foundational-primitives.md)
  (Phase 1 — foundational primitives; gates everything downstream)
- **Tier-2, depends on a tier-1:**
  - [006](006-iana-registry-sync-codegen.md) — IANA registry sync + codegen (depends on 001)
  - [007](007-cross-library-compatibility-testing.md) — Cross-library compatibility testing (depends on 001)
  - [015](015-tinygo-support-and-profiling.md) — TinyGo latent support + profiling (depends on 001)
  - [017](017-cose-encoder-reuse.md) — COSE encoder reuse (depends on 001, 016)
  - [018](018-opt-in-performance-extensions.md) — Opt-in performance extensions (depends on 001, 016)
- **Tier-3, sibling-module:**
  - [002](002-cose-structures-and-signing.md) — COSE (RFC 9052/9053; depends on 001)
  - [003](003-cwt-cbor-web-tokens.md) — CWT (RFC 8392; depends on 001, 002)
  - [004](004-edhoc-key-exchange.md) — EDHOC (RFC 9528; depends on 001, 002)
  - [005](005-eat-entity-attestation.md) — EAT (RFC 9711; depends on 001, 002, 003)

- **2026-11 review + upstream sync** (see [`../upstream-status-2026-11.md`](../upstream-status-2026-11.md)):
  - Core safety / conformance (tier-1): 021 → 022, 023 → 024
  - Core ergonomics (tier-2): 025, 026
  - COSE (tier-3): 027 → 028 → 029 → 030
  - CWT / EAT / EDHOC (tier-3): 031 → 032; 033 (supersedes 004)
  - Cross-cutting policy (tier-1): 034 — every proposal above classifies its
    changes and names legacy selectors per 034
  - Release: deliver as **v0.30.0** or later — see
    [`../release-notes-v0.30-maintainers.md`](../release-notes-v0.30-maintainers.md)

## Future considerations (not yet proposals)

- **CDDL (RFC 8610)** — Concise Data Definition Language for CBOR.
  Interesting for *programmatic schema construction* (generating
  CDDL from Go types, or generating Go types from CDDL). Not yet
  scoped as a consumer of corecbor — the validation/consumption
  direction is less clear than the generation direction. Revisit
  once corecbor Phase 1 ships and real-world usage patterns emerge.
  If filed, would likely be tier-3 with its own module.

## How to add a row

When filing a new proposal:

1. Increment "Next available proposal number" above.
2. Add a row to **Active proposals** with tier, status (`Draft`), title,
   owner, dependencies (proposal numbers or `—` if none), today's date.
3. When the proposal closes, move the row from **Active** to **Closed**
   and replace `Last update` with `Closed` date and `Outcome`
   (one-line summary).

The table format is intentional — flat, greppable, and survives
out-of-order index updates with a simple `git diff` review.
