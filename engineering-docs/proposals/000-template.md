<!--
  This is the corecbor proposal template. Copy to NNN-your-name.md and
  edit. Delete this comment block before filing.

  Section list is a CHECKLIST, not a straitjacket. Sections that don't
  apply to your proposal can be dropped — but don't drop the header
  block at the top, and don't reorder the remaining sections without a
  good reason. Reviewers read these in order.

  Style notes:
  - Cite the spec by §N (e.g., "extends §2.2"). Do not duplicate spec
    contents; link to them.
  - Cite RFCs by canonical number (e.g., "RFC 8949 §3.4"). The vendored
    text under engineering-docs/rfcs/ is the reference.
  - Code samples are Go. Specifications are language-agnostic.
  - Be concrete about acceptance criteria. Vague criteria don't gate.
-->

# NNN — <one-line title, imperative or noun-phrase>

## Header

| Field | Value |
|---|---|
| **Number** | NNN |
| **Tier** | 1 / 2 / 3 |
| **Status** | Draft / In-Review / Accepted / In-Progress / Closed / Rejected / Superseded / Withdrawn |
| **Filed** | YYYY-MM-DD |
| **Owner** | <github-handle or name> |
| **Depends on** | proposals: NNN, MMM (or: none) |
| **Supersedes** | proposals: NNN (or: none) |
| **Spec sections touched** | §X.Y, §X.Z (or: none — informational only) |

<!--
  STATUS RULES (copy from engineering-docs/README.md when reading,
  delete this comment when filing):

  - Draft → author is writing; reviewers may skim.
  - In-Review → open for critique; reviewers should engage.
  - Accepted → design locked; implementation can begin.
  - In-Progress → code being written; PRs reference this proposal.
  - Closed → implemented + acceptance criteria met.
  - Rejected → explicit decision not to do the work; reason captured below.
  - Superseded → replaced by a later proposal; successor named in header.
  - Withdrawn → author abandoned before review.

  TIER RULES:
  - Tier 1 = touches the spec contract or its acceptance criteria.
  - Tier 2 = quality-of-life, perf, ergonomics, depth — no contract change.
  - Tier 3 = adjacent libraries / ecosystem (sibling repos).
-->

---

## TL;DR

One paragraph. What does this propose, what's the scope, and what's the
acceptance criterion? A reviewer who reads only the TL;DR should be able
to decide whether to read the rest now or later.

For tier-1 proposals: include the velocity-discipline note here if the
proposal is gated on a different proposal closing first.

---

## Motivation

Why this work? What's broken or missing? What use case forces the
question? Concrete callers and concrete failures preferred over
abstract concerns.

If the motivation is a downstream consumer's need, name the consumer
and link to their gap.

---

## Proposal

The substance. What changes, in what order, with what observable
behavior. Use `§N` references to the spec for context; don't duplicate.

Sub-sections as needed:

### Public API surface

For tier-1 (contract-touching) proposals: the exact API additions /
modifications. Go signatures, full doc-comment text, behavioral notes.

```go
// Sample code goes here. Real signatures, not placeholders.
```

For tier-2 (depth) proposals: usually no public API change; describe
the internal change.

### Behavior

What changes for a caller. What was true before and what's true after.
Migration impact (none if the change is purely additive).

### Failure modes

What new typed errors emerge? What existing errors might surface in
new circumstances? See `encoder-decoder-spec.md` §5 — every error MUST
wrap a sentinel.

---

## Acceptance criteria

Concrete, testable, gating. A criterion is acceptable if a reviewer can
compile a test or run a benchmark and answer yes/no. Vague criteria
("performance is acceptable", "code quality is good") are not gating
and should not appear here.

| Criterion | Test mechanism | Gating? |
|---|---|---|
| <one-line concrete behavior> | <test, bench, fuzz target, manual verification step> | Yes / No |

For tier-1 proposals, list the matching spec section's acceptance
criterion under "Test mechanism" if the proposal implements existing
spec criteria.

---

## Phases (optional)

If the work is large enough to ship incrementally, enumerate the
phases. Each phase is independently shippable and has its own
acceptance criterion.

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | <slice> | Pending / Active / Done | <criterion> |
| 2 | <slice> | Pending | <criterion> |

If a phase is large enough to warrant its own proposal, say so here
and link forward.

---

## Test surface

Where new tests live, what they cover, how the fuzz coverage extends.
For tier-1 proposals, every change to the contract MUST extend the
fuzz target catalog (`encoder-decoder-spec.md` §7) — name the targets.

| Test | Covers | Lives at |
|---|---|---|
| `TestExampleHappyPath` | normal-input round-trip | `path/to/file_test.go` |
| `FuzzExampleNeverPanics` | adversarial input → typed error | same |

---

## Performance

Required for tier-1 proposals; optional for tier-2 unless the proposal
is itself a perf change.

| Metric | Target | Test mechanism |
|---|---|---|
| <metric> | <value> | `go test -bench BenchmarkX` |

If the proposal regresses a §9 metric, the regression must be
documented + justified, OR the proposal blocks until the regression
is offset.

---

## Risks

What could go wrong, and what's the mitigation. Be honest — a
proposal that lists no risks reads as one whose author hasn't thought
about the failure modes.

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| <risk> | low / med / high | low / med / high | <plan> |

---

## Alternatives considered

Designs that were on the table but rejected. Each gets a short paragraph
saying what it was, why it was rejected, and (if relevant) under what
future condition it might be revisited.

A proposal with no "alternatives considered" reads as one whose author
locked in early.

---

## Open questions

Things the author hasn't decided yet but that don't block filing the
proposal. Reviewers can address them inline.

If a question is load-bearing — answering it changes the design — it
belongs in **Proposal** with a note, not here.

---

## Cross-references

- Spec sections: §X.Y of `encoder-decoder-spec.md`
- RFCs: `rfcs/rfcNNNN.txt` §M.N
- Sibling proposals: `proposals/MMM-name.md`
- External: URLs to RFC errata, library docs, prior-art writeups

---

## Changelog

For long-lived proposals, append entries here as the document evolves.
Short proposals can omit this section entirely.

| Date | Change | Author |
|---|---|---|
| YYYY-MM-DD | Initial draft | <handle> |
| YYYY-MM-DD | Status: Draft → In-Review | <handle> |
