# corecbor proposals — index

This file is the denormalized view of the `proposals/NNN-*.md` files.
The status header inside each proposal is the source of truth; this
table is the convenient summary.

See `../README.md` for tier definitions, status definitions, and
proposal lifecycle.

## Active proposals

| # | Tier | Status | Title | Owner | Depends on | Last update |
|---|---|---|---|---|---|---|
| [036](036-deferred-follow-ups-2026-11.md) | 2 | In-Progress | Deferred follow-ups from the 2026-11 batch (done items ship in v0.3; the rest are deferred out of v0.3, each waiting on its trigger) | corecbor maintainers | 021–035 | 2026-11-23 |
| [015](015-tinygo-support-and-profiling.md) | 2 | Draft | TinyGo latent support and performance profiling (root module only) | corecbor maintainers | 001 | 2026-11-22 |

## Closed proposals

| # | Tier | Status | Title | Owner | Closed | Outcome |
|---|---|---|---|---|---|---|
| [037](037-spec-departure-review-2026-11-23.md) | 1 | Closed | Specification-departure review before v0.3.0 | corecbor maintainers | 2026-11-23 | All ~110 findings fixed across all modules; no new Legacy selectors; RFC 9338, RFC 8746 and RFC 10013 completed |
| [018](018-opt-in-performance-extensions.md) | 2 | Closed | Opt-in performance extensions | corecbor maintainers | 2026-11-22 | All ten extensions implemented and opt-in; three perf/test gaps moved to 036 (items 18–20). |
| [019](019-encode-throughput-recovery.md) | 2 | Closed | Encode path throughput recovery | corecbor maintainers | 2026-11-22 | EncodeScalars ≈2.4 GiB/s (target ≥850 MB/s); deterministic EncodeNestedMap ≈300 MiB/s (target ≥200 MB/s); no API or unsafe changes. |
| [017](017-cose-encoder-reuse.md) | 2 | Closed | COSE encoder reuse strategy | corecbor maintainers | 2026-11-22 | Package-level NewShared encoder (concurrency-safe); MarshalSign1 3 allocs/op (target ≤9). |
| [016](016-value-tagged-union-struct.md) | 1 | Closed | Replace Value interface with tagged-union struct | corecbor maintainers | 2026-11-22 | Value is a struct with a Kind discriminator (v0.2.0); strict nested-map decode ≈124 MiB/s vs ≥80 MB/s target; sub-modules migrated. |
| [034](034-standards-currency-and-legacy-compatibility.md) | 1 | Closed | Standards currency and legacy-compatibility selection policy | corecbor maintainers | 2026-11-22 | Spec §14 + §12 rule; every 021–035 proposal classified; apicheck + v0.2.2 golden vectors gate make check; migration guide lists every selector. |
| [032](032-eat-rfc9711-conformance.md) | 3 | Closed | EAT: RFC 9711 conformance | corecbor maintainers | 2026-11-22 | IANA claim keys (test-verified), legacy draft-key selector, fail-closed submods under SubmodPolicy, Validate rules, DEB tag 602, media types, eat/psa (RFC 9783). Phase D → 036. |
| [031](031-cwt-hardening-and-integration.md) | 3 | Closed | CWT hardening and ACE / SCITT integration | corecbor maintainers | 2026-11-22 | Panic-free claims (PrivateClaims/ClaimKey), NumericDate, NewValidator standards defaults, VerifyToken/OpenToken/Seal with KeyResolver, tag 61, UCCS, RFC 9597 bridge, ACE claims, cnf completion; Private deprecated. |
| [030](030-cose-hash-envelope-and-receipts.md) | 3 | Closed | COSE Hash Envelope, COSE Receipts, and SCITT signed statements | corecbor maintainers | 2026-11-22 | RFC 9995 hash envelope; RFC 9942 receipts with RFC 9162 Merkle proofs (CT probes); new scitt module (RFC 9943). |
| [028](028-cose-signing-and-key-api.md) | 3 | Closed | COSE signing headers, detached payloads, and COSE_Key API | corecbor maintainers | 2026-11-22 | Protected/unprotected header options, detached signing, typed header accessors (IANA-verified), COSE_Key parse/marshal/prefix, KeySet, key_ops, thumbprint, JWK, KeyResolver, ContextSigner, RSA verify. |
| [026](026-tag-helpers-and-registry-refresh.md) | 2 | Closed | Tag helpers for published CBOR tag RFCs, and registry refresh | corecbor maintainers | 2026-11-22 | Helpers for tags 24/37/52/54/100/1004/1001–1003/110–112/55799–55801; COSE/CWT/UCCS/DEB constants; registry +10 tags with frozen names. Phases D/E → 036. |
| [025](025-value-accessors-and-reflection-ergonomics.md) | 2 | Closed | Value accessors and reflection ergonomics | corecbor maintainers | 2026-11-22 | Get/GetInt/GetText, checked Int64/Uint64, Equal, String, Kind.String; toarray, DisallowUnknownFields, Text/Binary unmarshalers, omitzero, opt-in Go field names. Phase C → 036. |
| [029](029-cose-algorithms-and-encryption-conformance.md) | 3 | Closed | COSE algorithm registry alignment and encryption conformance | corecbor maintainers | 2026-11-22 | RFC 9864 fully-specified algs (opt-in emission), ML-DSA (RFC 9964), RSA sign, AES-CCM, conformant ECDH-ES/PBES2, Encrypt0 IVs, HPKE draft-27 (Experimental), shared internal/aesccm. |
| [033](033-edhoc-rfc9528-conformance-rewrite.md) | 3 | Closed | EDHOC: RFC 9528 conformance rewrite | corecbor maintainers | 2026-11-22 | RFC 9529 traces byte-for-byte; all methods, suites 0–6/24; OSCORE export; RFC 9668 CoAP helpers; X.509 credentials; legacy pre-RFC selector. x/crypto only for ChaCha20-Poly1305. |
| [020](020-default-decode-recovery.md) | 1 | Closed | Default-path decode recovery | corecbor maintainers | 2026-11-21 | Internal auto-reset arena by default; all §9 targets met on the default path (re-verified 2026-11-21). |
| [035](035-invalid-utf8-text-policy.md) | 1 | Closed | Caller-selected representation of text that is not valid UTF-8 | corecbor maintainers | 2026-11-21 | Reject/Allow/Replace/Lossless on encoder and decoder; TextLossless/AsText; tags 272–274; nested-text validation fixed. |
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

Next available proposal number: **038**

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
  - Release: deliver as **v0.3.0** or later — see
    [`../release-notes-v0.3-maintainers.md`](../release-notes-v0.3-maintainers.md)

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
