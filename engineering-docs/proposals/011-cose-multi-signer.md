# 011 — COSE_Sign and COSE_Mac (multi-signer / multi-recipient)

## Header

| Field | Value |
|---|---|
| **Number** | 011 |
| **Tier** | 3 |
| **Status** | Accepted |
| **Filed** | 2026-05-21 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 002 (closed) |
| **Supersedes** | none |
| **Spec sections touched** | none (extends cose module) |

---

## TL;DR

Add full COSE_Sign (tag 98, multiple signers) and COSE_Mac (tag 97,
multiple MAC recipients) support to the COSE module. Currently only
Sign1 (single signer) and Mac0 (single key) are implemented. Some
protocols (CMS-style multi-party signing, countersignatures) require
the multi-signer variants.

---

## Motivation

- RFC 9052 §4.1: COSE_Sign allows multiple signatures over the same
  payload (e.g., EdDSA + ECDSA for algorithm agility).
- RFC 9052 §6.1: COSE_Mac allows distributing the MAC key to multiple
  recipients (same pattern as COSE_Encrypt with recipients).
- Use cases: multi-authority signing (device + manufacturer attestation),
  algorithm migration (old + new sig in same message), notarization.

The `Sign` and `Mac` message types already exist in the cose module
(added in Phase B). This proposal adds the signing/verification and
MAC computation/verification operations.

---

## Proposal

### API additions to `cose/` module

```go
// Multi-signer operations
func SignMulti(payload []byte, signers []*Signer) (*Sign, error)
func VerifyMulti(msg *Sign, verifiers []*Verifier) ([]int, error)
// Returns indices of signers that verified successfully.

// Multi-recipient MAC
func ComputeMAC(payload []byte, key []byte, alg Algorithm, recipients []KeyDeriver) (*Mac, error)
func VerifyMAC(msg *Mac, recipient KeyDeriver, index int) error
```

### Sig_structure for COSE_Sign

Per RFC 9052 §4.4, the Sig_structure for multi-signer has 5 fields:
`["Signature", body_protected, sign_protected, external_aad, payload]`

This differs from Sign1's 4-field structure. Each signature has its
own protected headers (algorithm, kid, etc).

---

## Open questions

**All resolved:**

- ~~Partial vs all~~: **Partial success.** `VerifyMulti` returns indices
  of verified signatures. Requiring ALL would break algorithm-agility
  use cases (consumer verifies whichever algorithms they support).
- ~~Append-only signing~~: **Yes.** `(*Sign).AddSignature(signer)` adds
  a signature to an existing message. Enables notarization workflows
  where multiple parties sign sequentially.
- ~~Countersignatures~~: **Deferred.** RFC 9338 is complex and the old
  mechanism (RFC 8152) was deprecated. File as a separate proposal if
  demand materializes.

---

## Cross-references

- RFC 9052 §4.1 (COSE_Sign)
- RFC 9052 §6.1 (COSE_Mac)
- RFC 9338 (COSE Countersignatures)
- Existing cose module (Sign1, Mac0, Encrypt, multi-recipient Encrypt)

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-21 | Initial draft | corecbor maintainers |
