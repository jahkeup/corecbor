# corecbor engineering documentation

This directory holds the engineering specifications and the proposal-driven
development process for corecbor — a strict-RFC-conformant CBOR encoder
plus a forgiving CBOR decoder, with the same primitives serving both
storage / cryptographic-AAD use cases and wire-protocol implementation
use cases.

The discipline below is consciously velocity-biased: tier-1 work ships
on tier-1 timelines and does not block on tier-2 review. See `§12 of
encoder-decoder-spec.md` for the underlying principle.

## Layout

```
engineering-docs/
├── README.md                       — this file
├── encoder-decoder-spec.md         — tier-1 spec; the contract
├── proposals/                      — in-flight + closed proposals
│   ├── README.md                   — proposal index (status + ownership)
│   └── 000-template.md             — template every proposal forks from
└── rfcs/                           — vendored RFC text for citation
    ├── README.md
    ├── rfc8949.txt                 — CBOR primary spec
    ├── rfc8742.txt                 — CBOR Sequences
    ├── rfc9562.txt                 — UUID v7
    ├── rfc7049.txt                 — legacy CBOR (superseded; cited)
    └── rfc9052.txt                 — COSE downstream consumer
```

## Tier system

Every proposal carries a tier in its header. Tier semantics:

| Tier | Meaning | Examples | Block tier-N+1? |
|---|---|---|---|
| **Tier 1** | Foundational. Touches the contract in `encoder-decoder-spec.md` or its acceptance criteria. Must land before downstream consumers can integrate. | Phase 1–4 of the spec; new error sentinels; encoder mode additions | Yes — tier-2 waits |
| **Tier 2** | Quality-of-life and depth. Improves perf, ergonomics, observability, or coverage. Doesn't change the contract. | Buffer-pool tuning, additional fuzz targets, helper APIs (`AsTime`, etc.), CI integration | No — but defer until depending tier-1 closes |
| **Tier 3** | Adjacent libraries and ecosystem. Lives outside corecbor proper but is enumerated for visibility. | COSE / CWT helper packages, CDDL validator, OSS-Fuzz integration | No — entirely independent |

The tier is a property of the proposal, not the proposer. A nice-to-have
optimization on a tier-1 hot path is still tier-2.

## Proposal lifecycle

```
   Draft      ─►   In-Review   ─►   Accepted   ─►   In-Progress   ─►   Closed
                                       │
                                       ▼
                                   Rejected         (terminal)
                                   Superseded       (terminal — link successor)
                                   Withdrawn        (terminal)
```

Each transition is reflected in the proposal's status header (a single
line near the top of the file) AND mirrored in `proposals/README.md`'s
index table. The status header is the source of truth; the index is the
denormalized view.

### Status definitions

- **Draft** — author is still writing. Reviewers MAY skim but should not
  invest in deep critique. Authors mark "Draft → In-Review" themselves
  when they're done writing.
- **In-Review** — open for critique. Comments inline in the file (the
  proposal's own document), referenced commits, or in a sibling
  `proposals/NNN-author-feedback.md` if the discussion grows large.
- **Accepted** — the design is locked. Implementation can begin. Changes
  to the design after Accepted require an amendment (a new proposal that
  references this one as `supersedes:` or `amends:`).
- **In-Progress** — implementation underway. The proposal text is the
  spec; PR descriptions point back at it.
- **Closed** — implementation merged, acceptance criteria met. The
  proposal becomes historical record. Archive in place; do not move
  files.
- **Rejected** — explicit decision not to do the work. Body must capture
  the rejection reason; future authors with similar ideas read it before
  re-filing.
- **Superseded** — the proposal is replaced by a newer one. Header points
  at the successor. Stays in place as historical record.
- **Withdrawn** — author abandoned the proposal before review. Less heavy
  than Rejected; no committee decision was made.

### Velocity discipline

Per `encoder-decoder-spec.md` §12, tier-1 work does not block on tier-2
review. Concretely:

1. Tier-1 PRs reference an Accepted tier-1 proposal in their description.
2. Tier-1 PRs MAY merge with open comments on tier-2 surface (perf
   suggestions, additional tests beyond the spec's acceptance criteria,
   API ergonomic refinements). Those comments get filed as their own
   tier-2 proposals; the tier-1 PR doesn't wait.
3. Tier-2 PRs reference a tier-1 spec section AND an Accepted tier-2
   proposal. They merge under normal review.
4. Tier-3 work happens in sibling repos / modules; corecbor's `go.mod`
   is the gate.

This means a tier-1 implementation can land "incomplete-but-correct" —
satisfying the acceptance criteria of the proposal it implements without
satisfying every reviewer's wishlist. Wishlist items become proposals.

### Numbering

Proposals are numbered `NNN-short-kebab-name.md` where `NNN` is a
zero-padded sequence starting at `001`. The next available number is
visible at the bottom of `proposals/README.md`.

Numbers are assigned at filing (Draft) and never reused. Withdrawn /
Rejected proposals keep their numbers; the historical record is more
valuable than the small saving of compacting the sequence.

## Citing the spec

References to `encoder-decoder-spec.md` use the `§N` form (e.g.,
"strict-mode encoder per §2.2"). Section numbers are stable; the spec
itself is a tier-1 artifact and changes go through the proposal process.

References to RFCs use the canonical numbered form
(e.g., "RFC 8949 §4.2.1"). The vendored copies under `rfcs/` are the
authoritative reference text — see `rfcs/README.md`.

## Authoring a new proposal

1. Pick the next number from `proposals/README.md`.
2. Copy `proposals/000-template.md` to `proposals/NNN-your-name.md`.
3. Fill in the header (tier, status: Draft, owner, dependencies).
4. Write the body. The template's section list is a checklist, not a
   straitjacket — drop sections that don't apply, but don't drop the
   header.
5. Add a row to `proposals/README.md`'s index.
6. Push the file with status `Draft`. Move to `In-Review` when ready
   for critique.

## What does NOT live here

- Implementation source code. Lives at the repo root.
- API godoc. Generated from source.
- User-facing tutorials. If/when corecbor has consumers needing onboarding
  docs, those go in a separate `docs/` directory at the repo root.
- Benchmark results. Captured in proposals under their performance
  sections; bench raw output goes into per-proposal `bench-data/`
  subdirectories at filing time.
- Vendored upstream code. The `rfcs/` directory is the only "vendored"
  artifact; everything else is original to corecbor.

## When in doubt

Read `encoder-decoder-spec.md` first. It's the contract; the proposals
extend or refine it. If the spec doesn't answer your question, the
question is itself a proposal.
