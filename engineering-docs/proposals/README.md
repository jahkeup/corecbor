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

## Closed proposals

| # | Tier | Status | Title | Owner | Closed | Outcome |
|---|---|---|---|---|---|---|
| — | — | — | _none yet_ | — | — | — |

## Numbering

Next available proposal number: **002**

Numbers are assigned at filing and never reused. Withdrawn / Rejected
proposals keep their numbers — the historical record matters more than
sequence compactness.

## Quick filters

- **Tier-1, blocking:** [001](001-phase-1-foundational-primitives.md)
  (Phase 1 — foundational primitives; gates everything downstream)
- **Tier-2, depends on a tier-1:** _(none yet)_
- **Tier-3, sibling-module:** _(none yet)_

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
