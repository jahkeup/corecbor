# 030 — COSE Hash Envelope, COSE Receipts, and SCITT signed statements

## Header

| Field | Value |
|---|---|
| **Number** | 030 |
| **Tier** | 3 |
| **Status** | Closed |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 027 (raw protected bytes, policy), 028 (header options, detached, typed accessors), 029 (RFC 9054 hash identifiers); CWT proposal (031) for the `scitt` module only, 034 (compatibility policy) |
| **Supersedes** | none |
| **Spec sections touched** | none in `encoder-decoder-spec.md`; cose module plus a new `scitt` module |

---

## TL;DR

Three COSE RFCs published in 2026 define how transparency systems use
COSE:

- **RFC 9995, COSE Hash Envelope** (July 2026): sign a digest instead of
  the payload.
- **RFC 9942, COSE Receipts** (June 2026): Merkle-tree inclusion and
  consistency proofs carried as COSE_Sign1.
- **RFC 9943, SCITT Architecture** (June 2026): signed statements plus
  receipts.

corecbor implements none of them, and its current Sign1 surface cannot
express them: no custom protected headers, no detached payloads.

This proposal adds:

1. hash-envelope sign and verify helpers in `cose`;
2. a `cose/receipt` package that verifies (and, for log operators,
   issues) RFC 9162 SHA-256 receipts;
3. a small new `scitt` module that builds and checks SCITT signed
   statements using CWT Claims in the protected header (RFC 9597).

Acceptance: the RFC 9942 and RFC 9995 example messages verify, and an
end-to-end "issue statement → register → verify receipt" test passes
against a local Merkle log fixture.

---

## Motivation

Label values were checked against the IANA COSE Header Parameters
registry, fetched 2026-11-20.

### Hash Envelope (RFC 9995)

| Label | Name | Rule |
|---|---|---|
| 258 | payload-hash-alg | MUST be in protected; MUST NOT be in unprotected |
| 259 | preimage-content-type | MAY be in protected; MUST NOT be in unprotected |
| 260 | payload-location | MAY be in protected; MUST NOT be in unprotected |
| 3 | content type | MUST NOT appear in either bucket |

The payload is the digest of the preimage and may be attached or
detached. Consumers include SCITT issuers signing large artifacts (SBOMs,
container images), C2PA-style manifests, and any signer behind a KMS that
should not receive the full payload.

Today a caller cannot set label 258 in the protected bucket, because
`NewSigner` fixes it to `{1: alg}` (`cose/sign.go:49-51`; fixed in 028).
Nothing enforces the "MUST NOT" rules above.

### COSE Receipts (RFC 9942)

| Label | Name | Bucket (per RFC 9942) |
|---|---|---|
| 394 | receipts | unprotected header of the *statement*, array of receipts |
| 395 | vds | protected header of the *receipt*, verifiable data structure id |
| 396 | vdp | unprotected header of the *receipt*, map of proofs keyed by proof type |

Registered verifiable data structure: `RFC9162_SHA256 = 1`. Proof types
for it:

- inclusion (−1): `[tree-size, leaf-index, inclusion-path: [+ bstr]]`
- consistency (−2)

The receipt payload is detached and equals the Merkle root.
Verification:

1. Recompute the root from the leaf and the inclusion path
   (RFC 9162 §2.1.3.2).
2. Verify the Sign1 signature with that root as the payload.

RFC 9942 says receipts MUST be tagged COSE_Sign1 and recommends a single
boolean result. Today `UnmarshalSign1` accepts tagged input, but there is
no detached verify API (`sign.go:144`, fixed in 027/028) and no Merkle
code anywhere in the repository (`grep -rn Merkle` returns nothing).

### SCITT (RFC 9943)

A signed statement is a COSE_Sign1 that carries `alg`, an issuer key
identifier (`kid` and/or `x5chain`/`x5t`), and CWT Claims (15) with at
least `iss` and `sub` in the **protected** header. `typ`/`cty` are also
commonly set. A transparent statement is the signed statement with one or
more receipts in unprotected label 394.

The exact mandatory header set must be checked against the RFC 9943 text
during implementation; it is not vendored yet.

- Watch item: `draft-ietf-scitt-scrapi-11` (RFC Ed Queue), the HTTP
  registration API. We only provide data structures, not HTTP.
- Watch item: `draft-ietf-scitt-receipts-ccf-profile-06` (IESG
  Evaluation), the CCF tree algorithm. Its vds value will be added when
  registered.

---

## Proposal

### Package layout

| Package | Module | Why |
|---|---|---|
| `cose` (hash envelope helpers) | `cose` | Header rules and sign/verify only; no new deps |
| `cose/receipt` | `cose` | Depends only on `cose` and `crypto/sha256`. RFC 9942 is a COSE spec, and a separate module would duplicate the release cadence. |
| `cose/receipt/internal/merkle` | `cose` | RFC 9162 tree math, unexported |
| `scitt` | **new module** `github.com/jahkeup/corecbor/scitt` | Needs CWT claims (`cwt` module). `cwt` already imports `cose`, so placing this in `cose` would create a module cycle. |

### Public API surface

```go
// ---- package cose: Hash Envelope (RFC 9995)
const (
	HeaderPayloadHashAlg       int64 = 258
	HeaderPreimageContentType  int64 = 259
	HeaderPayloadLocation      int64 = 260
)

type HashEnvelope struct {
	HashAlg             Algorithm // RFC 9054 id, e.g. AlgSHA256 (-16)
	PreimageContentType any       // uint64 or string; optional
	Location            string    // optional
}

// SignHashEnvelope hashes preimage with env.HashAlg and signs the digest.
// detached=true leaves Payload nil.
func (s *Signer) SignHashEnvelope(preimage []byte, env HashEnvelope, detached bool) (*Sign1, error)
// SignHashEnvelopeDigest signs a caller-computed digest (KMS / streaming).
func (s *Signer) SignHashEnvelopeDigest(digest []byte, env HashEnvelope, detached bool) (*Sign1, error)

// VerifyHashEnvelope enforces RFC 9995 header rules, verifies the signature
// over the digest, and, if preimage != nil, checks digest == H(preimage).
func (v *Verifier) VerifyHashEnvelope(msg *Sign1, digest, preimage []byte) (HashEnvelope, error)

// ---- package cose/receipt (RFC 9942)
const (
	HeaderReceipts int64 = 394
	HeaderVDS      int64 = 395
	HeaderVDP      int64 = 396

	VDSRFC9162SHA256 int64 = 1

	ProofInclusion   int64 = -1
	ProofConsistency int64 = -2
)

type InclusionProof struct {
	TreeSize  uint64
	LeafIndex uint64
	Path      [][]byte
}

type ConsistencyProof struct {
	TreeSize1, TreeSize2 uint64
	Path                 [][]byte
}

// Receipt is a parsed RFC 9942 receipt (a tagged COSE_Sign1).
type Receipt struct {
	Msg        *cose.Sign1
	VDS        int64
	Inclusion  []InclusionProof
	Consistency []ConsistencyProof
}

func Parse(data []byte) (*Receipt, error)

// VerifyInclusion computes the RFC 9162 root for leaf under each inclusion
// proof and verifies the receipt signature with that root as the detached
// payload. leaf is the *entry* bytes; the RFC 9162 leaf hash
// SHA-256(0x00 || leaf) is applied internally.
func (r *Receipt) VerifyInclusion(ctx context.Context, leaf []byte, keys cose.KeyResolver, opts ...cose.VerifierOption) error

// VerifyConsistency verifies an append-only proof between two signed roots.
func VerifyConsistency(ctx context.Context, older, newer *Receipt, keys cose.KeyResolver) error

// Issue is for log operators: sign root with an inclusion proof.
func Issue(s *cose.Signer, root []byte, proof InclusionProof, protected cose.Headers) (*Receipt, error)

// Attach / Receipts manage label 394 on a statement's unprotected bucket.
func Attach(stmt *cose.Sign1, receipts ...*Receipt) error
func Receipts(stmt *cose.Sign1) ([]*Receipt, error)

// ---- module scitt
type Statement struct {
	Msg     *cose.Sign1
	Claims  *cwt.ClaimsSet // from protected label 15
	Type    any            // label 16, if present
}

type IssueOptions struct {
	Issuer, Subject string
	ContentType     any
	Type            any          // RFC 9596
	HashEnvelope    *cose.HashEnvelope // sign digest instead of payload
	Detached        bool
	X5Chain         [][]byte
	KeyID           []byte
}

func Issue(ctx context.Context, s *cose.Signer, payload []byte, o IssueOptions) (*Statement, error)
func ParseStatement(data []byte) (*Statement, error)

// VerifyTransparent verifies the issuer signature and at least `minReceipts`
// receipts from trusted transparency services.
func VerifyTransparent(ctx context.Context, data []byte, issuerKeys, serviceKeys cose.KeyResolver, minReceipts int) (*Statement, error)
```

### Behavior

1. **Hash envelope rules.** Verify rejects the message with `ErrMalformed`
   in any of these cases:
   - label 258 missing from protected, or present in unprotected;
   - label 259 or 260 in unprotected;
   - label 3 in either bucket;
   - a digest length that does not match `HashAlg`.

   Sign enforces the same rules before signing.
2. **Merkle math.**
   - Root computation and consistency checks follow RFC 9162 §2.1.3.2 and
     §2.1.4.2 exactly.
   - `LeafIndex >= TreeSize` is rejected.
   - The path length must match the tree height for
     (`LeafIndex`, `TreeSize`).
   - Each path element must be 32 bytes.
   - Path length is capped at 64 entries.
   - Hash comparisons use `subtle.ConstantTimeCompare`.
3. **Receipt parsing.**
   - The receipt must be tag 18.
   - `vds` must be in protected; a `vds` value we don't recognize returns
     `ErrUnsupportedAlgorithm`.
   - `vdp` must be in unprotected.
   - The payload must be `null` (detached).
   - The 027 decode limits and duplicate-label rule apply.
4. **Single boolean result.** `VerifyInclusion` returns `nil` only if
   *every* inclusion proof in the receipt verifies. That is the
   conservative reading of RFC 9942's single-result guidance; verify it
   against the RFC text during implementation.
5. **SCITT.**
   - `Issue` places CWT claims in **protected** label 15 using 028's
     `SetCWTClaims`.
   - `ParseStatement` rejects label 15 in the unprotected bucket.
   - `VerifyTransparent` resolves the issuer key through the
     `KeyResolver`, using protected `kid` and/or `x5t`/`x5chain` as hints.
   - X.509 path validation is the caller's job (028 Risk row).

### Failure modes

- No new `cose` sentinels; this package uses `ErrMalformed`,
  `ErrVerification` and `ErrUnsupportedAlgorithm` from 027.
- `receipt.ErrProof` covers a Merkle mismatch. It wraps
  `cose.ErrVerification`, so `errors.Is(err, cose.ErrVerification)` holds.
- `scitt.ErrInsufficientReceipts` is returned when fewer than
  `minReceipts` receipts verify.

---

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).
Everything here is new API built on published RFCs (9942, 9943, 9995),
so no existing identifier changes signature or semantics and no legacy
selector is needed. New `Signer`/`Verifier` methods are added to
existing struct types (allowed: no interface gains a method).

| Change | Class | Contract restored | Existing identifiers in v0.3 | Selector |
|---|---|---|---|---|
| `cose` hash envelope (RFC 9995): `SignHashEnvelope`, `SignHashEnvelopeDigest`, `VerifyHashEnvelope` | Additive (published RFC) | — | `Sign`/`Verify` unchanged | n/a |
| `cose/receipt` (RFC 9942), `scitt` signed statements (RFC 9943) | Additive (new packages) | — | n/a | n/a |
| Algorithm emission inside signed statements and receipts | Additive, current standards state | — | the caller's `*cose.Signer` decides, as everywhere in `cose` | godoc and examples build signers with `WithFullySpecifiedAlgorithms()` (029), the RFC 9864 path; verification accepts both families |
| SCRAPI (`draft-ietf-scitt-scrapi-11`), CCF receipt profile (`draft-ietf-scitt-receipts-ccf-profile-06`) | Draft | — | n/a | if implemented before publication: `WithDraftSCRAPI11()` / `WithDraftCCFProfile06()`, Experimental, never default |

No `CompatV02*` bundle content (nothing existed in v0.2). No `...Option`
parameters are appended to existing functions.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| RFC 9995 example hash-envelope Sign1 verifies; label-3-present and 258-unprotected variants rejected | `TestHashEnvelopeRFC9995` | Yes |
| Digest/preimage mismatch → `ErrVerification` | `TestHashEnvelopePreimage` | Yes |
| RFC 9942 example receipt verifies for its example leaf | `TestReceiptRFC9942Example` | Yes |
| RFC 9162 inclusion/consistency vectors (RFC 9162 test data or CT reference vectors) pass | `TestMerkleCTVectors`, `TestMerkleRootVectors`, `TestMerkleExhaustive` | Yes |
| Off-by-one leaf index, short path, 33-byte node → error, no panic | `TestMerkleMalformed` | Yes |
| Untagged receipt or non-null payload rejected | `TestReceiptShape` | Yes |
| E2E: `scitt.Issue` → local log `receipt.Issue` → `Attach` → `VerifyTransparent` | `TestSCITTEndToEnd` | Yes |
| CWT claims in unprotected bucket → `ParseStatement` error | `TestStatementClaimsBucket` | Yes |
| Fuzz: receipt parse and Merkle verify never panic (60s) | `FuzzReceiptParse`, `FuzzInclusionVerify`, `FuzzConsistencyVerify`, `FuzzParseStatement` | Yes |
| RFC 9942, 9943, 9995 (and RFC 9162 for Merkle) vendored under `engineering-docs/rfcs/` | files + README rows | Yes |
| Signed statements built with and without `WithFullySpecifiedAlgorithms()` both verify, and receipts over each verify | `TestSignedStatementAlgorithmEmission` | Yes |
| No draft-only behavior (SCRAPI, CCF profile) is reachable without a `WithDraft…` selector | API review | Yes |
| No exported identifier present in v0.2.2 is removed, renamed, or retyped, and no method is added to an exported interface (034 API stability) | `apidiff` against `v0.2.2` for this module, run in `make check` | Yes |
| Existing identifiers called with no new options reproduce the v0.2.2 golden vectors, except the contract-defect fixes listed under Compatibility selection | `testdata/legacy-v0.2.2/` golden tests | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | Hash envelope in `cose` (needs 028 Phase 1) | Done | hash-envelope rows green |
| 2 | `cose/receipt`: Merkle + parse + verify inclusion/consistency + issue | Done | receipt rows green |
| 3 | `scitt` module (needs CWT proposal 031 for `ClaimsSet` with protected-header helpers) | Done | E2E row green |

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestHashEnvelope*` | RFC 9995 rules | `cose/hash_envelope_test.go` |
| `TestReceipt*`, `TestMerkle*` | RFC 9942 / 9162 | `cose/receipt/receipt_test.go` |
| `FuzzReceiptParse`, `FuzzInclusionVerify` | adversarial input | `cose/receipt/fuzz_test.go` |
| `TestSCITT*` | statement issue/verify | `scitt/scitt_test.go` |

---

## Performance

| Metric | Target | Test mechanism |
|---|---|---|
| `BenchmarkVerifyInclusion` (tree size 2^20, path 20) | < 5 µs + one signature verify | `go test -bench Inclusion ./cose/receipt` |
| `BenchmarkSignHashEnvelopeDigest` | equals `Sign1` baseline (payload ≤ 64 B) | new bench |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Ambiguity over what the Merkle "leaf" is (statement bytes vs. a profile-specific leaf) | high | med | API takes leaf *bytes* explicitly; profile adapters (e.g. CCF) live in separate files once registered |
| SCITT mandatory-header set misread without vendored RFC 9943 | med | med | vendor first (acceptance row), then implement |
| New `scitt` module adds release overhead | low | low | mirrors existing `cwt`/`eat` module pattern |

---

## Alternatives considered

- **Receipts in a separate module.** Rejected because RFC 9942 is a
  COSE-WG spec with no dependencies beyond COSE. Keeping it in the cose
  module avoids another `replace` directive.
- **Put SCITT helpers in `cwt`.** Rejected. SCITT is an application
  profile, and `cwt` should stay focused on RFC 8392 and RFC 8747.
- **Generic Merkle library dependency (e.g. transparency-dev/merkle).**
  Rejected: it would be the cose module's first non-std dependency for
  about 150 lines of RFC 9162 math. We can revisit if CCF or other tree
  types multiply.

---

## Open questions

- Should `VerifyInclusion` accept a precomputed leaf *hash* for profiles
  whose leaf construction is not `SHA-256(0x00 || entry)`? Leaning yes,
  as a `VerifyInclusionHash` variant.
- Should `receipt.Issue` live here at all, or only verification? Log
  operators are a smaller audience, but issuing is needed for E2E tests.
  Keep it, but mark it experimental.

---

## Cross-references

- RFCs:
  - RFC 9995 (Hash Envelope)
  - RFC 9942 (Receipts)
  - RFC 9943 (SCITT Architecture)
  - RFC 9162 §2.1 (Merkle tree)
  - RFC 9597 (CWT Claims header)
  - RFC 9596 (typ)
  - RFC 9054 (hash algorithms)
- Drafts:
  - `draft-ietf-scitt-scrapi-11`
  - `draft-ietf-scitt-receipts-ccf-profile-06`
- Sibling proposals: 027, 028, 029, 031 (CWT)
- External: IANA COSE Header Parameters and Verifiable Data Structures
  registries (fetched 2026-11-20)

---

## Implementation notes

All three phases landed on `feat/030-receipts`. SCRAPI
(`draft-ietf-scitt-scrapi-11`) and the CCF receipt profile are still
watch items: nothing draft-only is implemented, so no `WithDraft…`
selector exists. Labels 258–260 and 394–396, VDS `RFC9162_SHA256` (1),
and proof types −1/−2 were checked against the live IANA COSE Header
Parameters and Verifiable Data Structure registries.

Interpretations and deviations from the API sketch above:

- **Examples.** The RFC 9995, 9942 and 9943 examples elide digests,
  hashes and signatures, so the tests rebuild them structurally
  (`TestHashEnvelopeRFC9995`, `TestReceiptRFC9942Example`,
  `TestReceiptsAttached`, `TestReceiptConsistency`). The proof bytes for
  tree size 8, leaf 7 match the RFC 9943 prefix `83080783`
  (`TestReceiptRFC9943ProofBytes`).
- **Merkle vectors.** RFC 9162 has no test vectors. The CT reference
  probes from transparency-dev/merkle (Apache-2.0) are vendored under
  `cose/receipt/internal/merkle/testdata/ct/` with provenance, along with
  the CT root hashes for 0–8 leaves. They are cross-checked with an
  exhaustive generate-and-verify run for trees up to 64 leaves. RFC 9162
  §2.1.4.2 requires `first < second`, so the two CT probes that accept
  an empty proof between equal sizes are rejected here on purpose.
- **Empty inclusion path.** The CDDL says `[+ bstr]`, but a tree of
  size 1 has an empty path. An empty path is accepted only when the tree
  shape calls for one. Every path length must match the shape exactly.
- **Hash envelope.** `SignHashEnvelopeMessage` and
  `VerifySign1HashEnvelope` were added so that envelopes can carry
  other protected parameters (CWT Claims) and use a `KeyResolver`.
  `HashEnvelopeFrom` exposes the header rules on their own. SHA-256,
  SHA-384, SHA-512 and SHA-512/256 are supported. The "Filter Only"
  hashes (SHA-1, SHA-256/64) are `ErrUnsupportedAlgorithm`.
- **Receipts.**
  - `Issue` and `IssueConsistency` take a `ctx` and are marked
    experimental (open question 2).
  - `VerifyInclusionHash` answers open question 1.
  - `VerifyConsistency(ctx, older, olderEntry, newer, keys, opts...)`
    takes the older receipt's entry, because the older root can only be
    recomputed from it. `VerifyConsistencyFrom` takes a known old root.
  - When a receipt carries several inclusion proofs, all of them must
    give the signed root, so the receipt yields one boolean result.
  - A receipt carrying both inclusion and consistency proofs is
    `ErrMalformed`.
  - Every receipt and Merkle failure wraps `cose.ErrVerification`
    through `receipt.ErrProof`.
  - `Receipts` reads label 394 from either bucket, and `Attach` writes
    it to the unprotected bucket.
  - `receipt.Tree` is an experimental in-memory log for tests and small
    operators.
- **SCITT.**
  - `ParseStatement` enforces RFC 9943 §6:
    - tag 18;
    - CWT Claims protected-only, with iss and sub;
    - a protected kid unless x5t or x5chain is protected;
    - with x5, an iss of 1–8192 characters that is a URI if it
      contains `:`.
  - `Entry` sets the unprotected bucket to `{}` before registration,
    which is the leaf that receipts prove.
  - Receipts must carry protected CWT Claims with iss and sub.
    `ReceiptHeaders` builds them.
  - `Verify` also takes detached payloads, preimages,
    `SkipIssuerSignature` (receipts only, §7.1) and per-party verifier
    options.
  - `IssueOptions` adds `Claims` (extra claims) and `X5T`.
    `Statement` adds `HashEnvelope`.
  - New sentinels: `scitt.ErrInvalidStatement` (wraps `cose.ErrMalformed`)
    and `scitt.ErrInsufficientReceipts` (wraps `cose.ErrVerification`).
- **034.** All changes are additive, and apicheck is clean. No cose
  sentinels were added, and the golden vectors are unchanged. The
  `cose/receipt` and `scitt` sentinels are not in the cose golden-error
  harness: `scitt` is a separate module, and importing `cose/receipt`
  from the cose harness would create an import cycle. Neither package
  has v0.2.2 vectors. `scitt` has no v0.2.2 baseline, so it is not in
  the apicheck module list.
- **Performance.** Recomputing an inclusion root for a 2^20-leaf tree
  (20-hash path) takes about 1.3 µs/op, 640 B and 20 allocations
  (`BenchmarkVerifyInclusionMerkle`), before the signature check.
  `BenchmarkSignHashEnvelopeDigest` was not added, because signing a
  digest is a plain `Sign1` call.

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
| 2026-11-20 | API stability (signature + semantics) per revised 034 | corecbor maintainers |
| 2026-11-21 | Phases 1–3 implemented; status In-Progress; implementation notes | corecbor maintainers |
| 2026-11-22 | Status: Closed (acceptance met) | corecbor maintainers |
