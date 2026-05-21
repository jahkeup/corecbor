# 012 — CWT Proof-of-Possession / Confirmation Claim (RFC 8747)

## Header

| Field | Value |
|---|---|
| **Number** | 012 |
| **Tier** | 3 |
| **Status** | Draft |
| **Filed** | 2026-05-21 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 003 (closed) |
| **Supersedes** | none |
| **Spec sections touched** | none (extends cwt module) |

---

## TL;DR

Add the "confirmation" claim (cnf, key 8) to the CWT module per
RFC 8747. This claim binds a CWT to a specific cryptographic key,
enabling proof-of-possession (PoP) tokens used in ACE-OAuth, FIDO,
and DPoP-style protocols.

---

## Motivation

A bearer token (plain CWT) can be used by anyone who holds it. A PoP
token proves the presenter holds a specific private key. The `cnf`
claim declares which key the token is bound to. The verifier then
challenges the presenter to prove possession.

Used in:
- ACE-OAuth (RFC 9200): access tokens bound to client keys
- FIDO/WebAuthn: attestation bound to device keys
- DPoP (RFC 9449 analog for CBOR): API tokens bound to ephemeral keys
- mTLS certificate binding

---

## Proposal

### API additions to `cwt/` module

```go
// Confirmation holds the cnf claim value (claim key 8).
type Confirmation struct {
    // Key is a COSE_Key (proof-of-possession key).
    Key *cose.Key
    // KeyID references a key by identifier (kid).
    KeyID []byte
    // Encrypted holds an encrypted COSE_Key.
    Encrypted []byte
}

// Add to ClaimsSet:
type ClaimsSet struct {
    // ... existing fields ...
    Confirmation *Confirmation  // claim key 8
}
```

### cnf claim encoding (RFC 8747 §3.1)

The cnf claim value is a CBOR map:
- Key 1 (COSE_Key): the raw public key
- Key 2 (Encrypted_COSE_Key): encrypted key
- Key 3 (kid): key identifier reference

### Validator extension

```go
type Validator struct {
    // ... existing fields ...
    RequireConfirmation bool  // reject tokens without cnf claim
}
```

---

## Open questions

- Should the CWT module verify proof-of-possession (challenge-response),
  or only parse/encode the cnf claim? PoP verification is protocol-
  specific (the challenge mechanism varies by protocol).
- Support for symmetric PoP keys (shared secret confirmation)?
- Should `Confirmation.Key` support key-by-reference (resolve kid)?

---

## Cross-references

- RFC 8747 (Proof-of-Possession Key Semantics for CWTs)
- RFC 9200 (ACE-OAuth)
- RFC 9201 (ACE-OAuth CoAP profile)
- Existing cwt module (ClaimsSet, Validator)
- EDHOC credential.go uses cnf claim internally (validates PoP)

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-21 | Initial draft | corecbor maintainers |
