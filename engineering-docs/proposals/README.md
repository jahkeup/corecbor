# corecbor proposals — index

This file is the denormalized view of the `proposals/NNN-*.md` files.
The status header inside each proposal is the source of truth; this
table is the convenient summary.

See `../README.md` for tier definitions, status definitions, and
proposal lifecycle.

## Active proposals

| # | Tier | Status | Title | Owner | Depends on | Last update |
|---|---|---|---|---|---|---|
| [001](001-phase-1-foundational-primitives.md) | 1 | Draft | Phase 1: Foundational primitives | corecbor maintainers | — | 2026-05-20 |
| [002](002-cose-structures-and-signing.md) | 3 | Draft | COSE structures and cryptographic operations (RFC 9052 + RFC 9053) | corecbor maintainers | 001 | 2026-05-20 |
| [003](003-cwt-cbor-web-tokens.md) | 3 | Draft | CWT: CBOR Web Tokens (RFC 8392) | corecbor maintainers | 001, 002 | 2026-05-20 |
| [004](004-edhoc-key-exchange.md) | 3 | Draft | EDHOC: Ephemeral DH Over COSE (RFC 9528) | corecbor maintainers | 001, 002 | 2026-05-20 |
| [005](005-eat-entity-attestation.md) | 3 | Draft | EAT: Entity Attestation Tokens (RFC 9711) | corecbor maintainers | 001, 002, 003 | 2026-05-20 |

## Closed proposals

| # | Tier | Status | Title | Owner | Closed | Outcome |
|---|---|---|---|---|---|---|
| — | — | — | _none yet_ | — | — | — |

## Numbering

Next available proposal number: **006**

Numbers are assigned at filing and never reused. Withdrawn / Rejected
proposals keep their numbers — the historical record matters more than
sequence compactness.

## Quick filters

- **Tier-1, blocking:** [001](001-phase-1-foundational-primitives.md)
  (Phase 1 — foundational primitives; gates everything downstream)
- **Tier-2, depends on a tier-1:** _(none yet)_
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
