# Maintainer note — v0.3 release line

**Audience:** maintainers cutting releases. Not user-facing.
**Filed:** 2026-11-20. **Last release at filing:** `v0.2.2` (`00e1307`).

## Decision

Once the 2026-11 review proposals (021–035, and 036 item 25) are
delivered, release them as **`v0.3.0`**: the next minor after `v0.2.2`.
Those proposals change a large share of the unstable API and wire
behavior: reflection defaults, `RawMessage` semantics, `StrictDecoder`
tag policy, COSE header/key APIs, CWT validation defaults, EAT claim
keys, and the whole EDHOC protocol core. The minor bump plus the
migration guide (`migration-v0.2-to-v0.3.md`) carry that message.
Legacy selectors are removed no earlier than **v0.5.0**: they survive
at least the v0.3 and v0.4 lines.

"Delivered" means: every proposal in scope is Closed, Rejected, or
explicitly deferred out of v0.3 in `proposals/README.md` (036's
remaining items are deferred: each waits on an external trigger). If a
subset had shipped earlier, it would have gone out as `v0.2.x` only if
purely additive or a Defect fix under proposal 034.

## Release checklist for v0.3.0

1. **Proposals.** All in-scope proposals Closed; index updated.
2. **Migration guide.** Write `engineering-docs/migration-v0.2-to-v0.3.md`
   in the style of `migration-v0.1-to-v0.2.md`. Per proposal 034 it must
   list every `Legacy…`, `Draft…`, policy selector and `CompatV02`
   bundle, with before/after bytes for each wire-visible change.
3. **Legacy golden vectors.** Before the first wire-changing PR merges,
   capture v0.2.2 outputs (EAT tokens, EDHOC transcripts, COSE messages
   with PBES2/HPKE, reflection output) as fixtures, so the legacy
   selectors are tested against real v0.2 bytes.
4. **Sub-module versioning.** `cose`, `cwt`, `eat`, `edhoc` and `scitt`
   had never been tagged and required `corecbor v0.0.0`, so they couldn't
   be consumed from outside this repo. For v0.3.0:
   - every sub-module requires the in-repo modules at `v0.3.0`. The
     `replace ../` directives stay for local development and CI: Go
     ignores `replace` in a dependency's go.mod, so consumers resolve the
     real tags. (Dropping them first would break `go mod tidy` and CI
     until the tags exist.)
   - tag every module **at the same commit**: `v0.3.0`, `cose/v0.3.0`,
     `cwt/v0.3.0`, `eat/v0.3.0`, `edhoc/v0.3.0`, `scitt/v0.3.0`.
     `tools/release-tags.sh v0.3.0` checks the tree and creates the
     annotated tags locally; pushing them is a separate, deliberate step
     (`git push origin <tags>`).
   - after tagging, add `scitt` to `tools/apicheck.sh` with v0.3.0 as
     its baseline (036 item 14), and verify from a scratch module:
     `go get github.com/jahkeup/corecbor/scitt@v0.3.0 && go build ./...`.
5. **EDHOC status.** Proposal 033 closed on 2026-11-22 (RFC 9529 traces
   pass; experimental marking removed), so `edhoc` is tagged with the
   rest.
6. **Deprecation floor.** Record in the release notes that `Legacy…` and
   `CompatV02` selectors are removed no earlier than v0.5.0 (every
   `Deprecated:` comment says so; tests in eat and edhoc check it).
7. **Upstream re-check.** Re-run the survey behind
   `upstream-status-2026-11.md` and file a new dated snapshot. In
   particular: has draft-ietf-cbor-serialization published (proposal
   024), and has draft-ietf-cose-hpke received IANA code points
   (proposal 029)?
8. **API stability (signature and semantics), per proposal 034.**
   `apidiff` against `v0.2.2` shows no removed, renamed or retyped
   exported identifiers in any module; the only accepted reports are
   appended `...Option` parameters, each listed in the migration guide.
   The v0.2.2 golden vectors from step 3 pass when existing identifiers
   are called with no new options, apart from documented contract-defect
   fixes.
9. **CI.** `make check` and `make fuzz` green on all modules. As of
   `6b37e45`, `make` lints and tests the sub-modules on macOS too.

## Why not v1.0

The proposals add API that hasn't had external use yet (COSE key/header
APIs, receipts, the EDHOC rewrite). v1.0 should follow at least one
v0.3.x cycle with real consumers.
