# Maintainer note — v0.30 release line

**Audience:** maintainers cutting releases. Not user-facing.
**Filed:** 2026-11-20. **Last release at filing:** `v0.2.2` (`00e1307`).

## Decision

Once the 2026-11 review proposals (021–034) are delivered, bump the
project to **at least `v0.30.0`**, not to `v0.3.x`. Those proposals
change a large share of the unstable API and wire behavior: reflection
defaults, `RawMessage` semantics, `StrictDecoder` tag policy, COSE
header/key APIs, CWT validation defaults, EAT claim keys, and the whole
EDHOC protocol core. The jump in the minor number signals "re-read the
migration guide" in a way a single-step bump does not.

"Delivered" means: every proposal in 021–034 is Closed, Rejected, or
explicitly deferred out of the v0.30 scope in `proposals/README.md`. If
a subset ships earlier, it goes out as `v0.2.x` only if it is purely
additive or a Defect fix under proposal 034. Anything else waits for
v0.30.0.

## Release checklist for v0.30.0

1. **Proposals.** All in-scope proposals Closed; index updated.
2. **Migration guide.** Write `engineering-docs/migration-v0.2-to-v0.30.md`
   in the style of `migration-v0.1-to-v0.2.md`. Per proposal 034 it must
   list every `Legacy…`, `Draft…`, policy selector and `CompatV02`
   bundle, with before/after bytes for each wire-visible change.
3. **Legacy golden vectors.** Before the first wire-changing PR merges,
   capture v0.2.2 outputs (EAT tokens, EDHOC transcripts, COSE messages
   with PBES2/HPKE, reflection output) as fixtures, so the legacy
   selectors are tested against real v0.2 bytes.
4. **Sub-module versioning.** `cose`, `cwt`, `eat` and `edhoc` currently
   `require github.com/jahkeup/corecbor v0.0.0` plus `replace ../` and
   have never been tagged, so they can't be consumed from outside this
   repo (`replace` is ignored for dependents). For v0.30.0:
   - drop the `replace` directives (use a `go.work` for local dev);
   - require real versions (`corecbor v0.30.0`, `cose v0.30.0`, …);
   - tag each module with its path prefix: `v0.30.0`, `cose/v0.30.0`,
     `cwt/v0.30.0`, `eat/v0.30.0`, `edhoc/v0.30.0`, in dependency order.
5. **EDHOC status.** If proposal 033 has not closed, keep `edhoc`
   marked experimental in its `doc.go` and the README, and leave it
   untagged at v0.30.0.
6. **Deprecation floor.** Record in the release notes that `Legacy…` and
   `CompatV02` selectors are removed no earlier than v0.32.0.
7. **Upstream re-check.** Re-run the survey behind
   `upstream-status-2026-11.md` and file a new dated snapshot. In
   particular: has draft-ietf-cbor-serialization published (proposal
   024), and has draft-ietf-cose-hpke received IANA code points
   (proposal 029)?
8. **CI.** `make check` and `make fuzz` green on all modules. As of
   `6b37e45`, `make` lints and tests the sub-modules on macOS too.

## Why not v1.0

The proposals add API that hasn't had external use yet (COSE key/header
APIs, receipts, the EDHOC rewrite). v1.0 should follow at least one
v0.30.x cycle with real consumers.
