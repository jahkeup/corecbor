# Changelog

All modules in this repository are versioned together: `vX.Y.Z` for
the root module and `cose/vX.Y.Z`, `cwt/vX.Y.Z`, `eat/vX.Y.Z`,
`edhoc/vX.Y.Z`, `scitt/vX.Y.Z` for the others.

## v0.3.1 — 2026-11-23

- **Performance:** decoding with a memory budget (`WithMemoryBudget`)
  keeps the fast path for short text map keys, charging them to the
  budget there. In v0.3.0 a budget sent every such key down the
  checked path, about 24% slower on key-heavy data. Decoding without a
  budget is unchanged, and the same budget accepts or rejects the same
  input as before.
- **License:** `LICENSE` is a fresh copy of the Apache License text.

## v0.3.0 — 2026-11-23

Upgrade guide: [`engineering-docs/migration-v0.2-to-v0.3.md`](engineering-docs/migration-v0.2-to-v0.3.md).
It lists every behavior change with what to do if you depended on the
old behavior.

**Compatibility.** No exported identifier is removed, renamed or
retyped (checked against v0.2.2 by `make apicheck`). Default encoder
output for ordinary data (text, bytes, integers, booleans, null,
arrays, maps with distinct keys) is byte-identical to v0.2.2, checked
by golden vectors. Defaults now follow the current RFCs; where that
changed behavior, a deprecated `Legacy…` / `CompatV02…` selector
restores v0.2, kept until **at least v0.5.0**. Selectors that weaken
verification are never part of a `CompatV02` bundle.

**First tagged release of the sub-modules.** `cose`, `cwt`, `eat`,
`edhoc` and `scitt` can now be required from outside this repository.

Highlights:

- **CBOR core:** safety fixes (concurrency, arena aliasing, resource
  limits, `Cursor` limit checks), raw-byte preservation (`DecodeRaw`,
  `RawMessage` gets the original bytes), a strict-decode tag policy
  with structured errors, caller-selected map key identity, preferred
  and deterministic serialization aligned with RFC 8949 and its errata,
  value accessors, tag helpers for published tag RFCs, a refreshed IANA
  registry, and a caller-selected policy for text that isn't valid
  UTF-8.
- **COSE:** verification hardening (`alg` bound to the key, `crit`
  honored), signing headers, detached payloads, a COSE_Key API,
  algorithm-registry alignment and encryption conformance (PBES2,
  ECDH-ES, HPKE draft), hash envelopes, receipts.
- **CWT:** validation hardening (`exp` boundary, duplicate claims,
  NumericDate range), ACE claims, `cnf` per RFC 8747, claims in COSE
  headers (RFC 9597).
- **EAT:** RFC 9711 claim keys and submodules, detached bundles, PSA
  (RFC 9783).
- **EDHOC:** rewritten for RFC 9528; the RFC 9529 traces pass.
- **SCITT:** signed statements.
- **No silent rewriting.** Data that re-encoding would change — a map
  key that is a bignum with an integer value, a NaN payload, a
  non-finite COSE_Key parameter — is rejected with a specific error
  (`cwt.ErrAmbiguousClaimKey`, `cwt.ErrNonCanonicalNaN`,
  `cose.ErrNonFiniteKeyParam`) naming the item, or kept byte for byte
  on request (`cwt.DecodeOptions.KeepAsReceived`,
  `eat.WithKeepAsReceived`, `cose.KeepParamsAsReceived`).

- **Specification-departure review (proposal 037).** Every module was
  checked against its RFCs and secure practice before release, and all
  findings are fixed:
  - crash, unbounded-work and data-loss defects in the core decoder
    (self-describe tag chains, indefinite-map duplicate checks, memory
    budget accounting, `MaxItemSize` for readers, stream truncation,
    hash flooding);
  - fail-open defaults in COSE, CWT, EAT, SCITT and EDHOC (key
    algorithm binding, HMAC/PBES2 strength, decode limits, audience,
    `cnf`, nested submodules, receipts, credential validation);
  - newly implemented: RFC 9338 countersignatures, RFC 8746 typed and
    multi-dimensional arrays, RFC 10013 measured components,
    multi-recipient CWTs and nested-recipient decryption.
  Defaults follow the RFCs. Where a caller may need the old behavior,
  a plainly named opt-in exists (`Allow…`, `Insecure…`, `Ignore…`).
  No new `Legacy…` selectors.

Design records: proposals 020–037 under
[`engineering-docs/proposals/`](engineering-docs/proposals/).

## v0.2.2 and earlier

See the git tags and
[`engineering-docs/migration-v0.1-to-v0.2.md`](engineering-docs/migration-v0.1-to-v0.2.md).
