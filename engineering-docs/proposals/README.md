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

## Closed proposals

| # | Tier | Status | Title | Owner | Closed | Outcome |
|---|---|---|---|---|---|---|
| [001](001-phase-1-foundational-primitives.md) | 1 | Closed | Phase 1: Foundational primitives | corecbor maintainers | 2026-05-20 | All acceptance criteria met. Phases 1-4 implemented. §9 perf targets exceeded. |
| [002](002-cose-structures-and-signing.md) | 3 | Closed | COSE structures and cryptographic operations | corecbor maintainers | 2026-05-21 | Phases A-E complete. Sign1, Encrypt0, Mac0, multi-recipient, AES-KW, ECDH-ES, PBES2, HPKE, key escrow patterns. |
| [003](003-cwt-cbor-web-tokens.md) | 3 | Closed | CWT: CBOR Web Tokens | corecbor maintainers | 2026-05-21 | Phases A-B complete. Sign/Verify/Encrypt/Decrypt/MAC + Validator. |
| [004](004-edhoc-key-exchange.md) | 3 | Closed | EDHOC: Ephemeral DH Over COSE | corecbor maintainers | 2026-05-21 | Phases A-C complete. Suite 0+2, msg4, Exporter, CWT credentials. |
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

Next available proposal number: **019**

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
