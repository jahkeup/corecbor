# Upstream standards status — 2026-11-20 snapshot

Point-in-time survey of IETF work relevant to corecbor and its sibling
modules (`cose`, `cwt`, `eat`, `edhoc`), taken before filing proposals
021–033. Sources: IETF datatracker WG document lists (cbor, cose, jose,
lake, rats, scitt, ace), the RFC Editor errata database, and the IANA
CWT-claims and CBOR-tags registries (both fetched raw on 2026-11-20).

This file is informational. It does not change the spec; the proposals
listed in the "Handled by" column do, following the default/legacy
selection policy in proposal 034. Re-run the survey before closing
any proposal that depends on an Internet-Draft, and file a new dated
snapshot instead of editing this one.

## How to read the tables

- **Impact** — `breaking`: current code is non-conformant or
  non-interoperable; `gap`: published standard with no support;
  `watch`: Internet-Draft, do not anchor contracts on it yet (per
  `rfcs/README.md`, I-Ds are cited by URL and never vendored).
- **Handled by** — the proposal that owns the work.

## CBOR WG

| Document | State (2026-11) | Impact | Handled by |
|---|---|---|---|
| RFC 8949 erratum 8589 (§5.6.1) | Verified | breaking — NaN map-key equivalence must also compare the sign bit | 024 |
| draft-ietf-cbor-serialization-13 — "CBOR Serialization and Determinism" | IETF Last Call ends 2026-11-30; submitted to IESG | watch → likely gap soon. Defines *Preferred-Plus* and *Deterministic* serializations; Deterministic = RFC 8949 §4.2.1 except NaN (only `0xf97e00`); bignum reduction to major types 0/1; optional "checking decoders" | 024 |
| draft-ietf-cbor-cde-13 — Common Deterministic Encoding | Expired, parked | none — superseded in practice by the serialization draft | 024 (alternatives) |
| draft-ietf-cbor-edn-literals-29 — "Concise Diagnostic Notation (CDN)" | WG Last Call | watch — affects `Diagnostic()` output and `cmd/cbor-diag` | 026 (later phase) |
| draft-ietf-cbor-packed-19 | Expired | none | — |
| RFC 8943 (date tags 100/1004) | Published 2020 | gap — mDL (ISO 18013-5) uses tag 1004 | 026 |
| RFC 9090 (OID tags 111/112) | Published 2021 | gap — EAT profile OIDs | 026, 032 |
| RFC 9164 (IP address tags 52/54) | Published 2021 | gap | 026 |
| RFC 9277 (stable storage / magic numbers) | Published 2022 | gap | 026 |
| RFC 9581 (time/duration/period tags 1001–1003) | Published 2024 | gap | 026 |
| RFC 9682 (CDDL grammar updates) | Published 2024 | none (no CDDL support yet) | — |
| IANA CBOR tags registry | Updated; ~20 entries newer than `registry/registry.json` (e.g. 10/11/13 IXDTF, 600, 46010/46011) | gap — regenerate | 026 |

## COSE WG (+ JOSE WG registrations that touch COSE)

| Document | State | Impact | Handled by |
|---|---|---|---|
| RFC 9864 — Fully-Specified Algorithms | Published 2025-10 | breaking (policy) — ES256 (-7), ES384 (-35), ES512 (-36), EdDSA (-8) **deprecated**; new ESP256 (-9), ESP384 (-51), ESP512 (-52), Ed25519 (-19), Ed448 (-53), Brainpool ESB* | 029 |
| RFC 9964 — ML-DSA for JOSE/COSE | Published 2026-05 | gap — ML-DSA-44/65/87 = -48/-49/-50; key type AKP (kty 7), `pub` -1, `priv` -2 (32-byte seed only); empty ctx | 029, 028 (AKP key) |
| RFC 9360 — X.509 header params (x5bag/x5chain/x5t/x5u) | Published 2023 | gap — mDL, C2PA, SCITT | 028 |
| RFC 9596 — `typ` header | Published 2024 | gap | 028, 031 |
| RFC 9597 — CWT claims in COSE headers | Published 2024 | gap — SCITT signed statements | 028, 031 |
| RFC 9679 — COSE Key Thumbprint | Published 2024 | gap | 028 |
| RFC 9338 — Countersignatures | Published 2022 (part of STD 96) | gap, low demand | 028 (open question) |
| RFC 9459 — AES-CTR / AES-CBC | Published 2023; IANA marks the algorithms **Deprecated** | none — do not implement | 029 (rejected alternative) |
| RFC 9921 — RFC 3161 timestamp header params (labels 269, 270) | Published 2026-02 | gap — SCITT/C2PA | 028 |
| RFC 9942 — COSE Receipts | Published 2026-06 | gap — SCITT transparency | 030 |
| RFC 9995 — COSE Hash Envelope | Published 2026-07 | gap — SCITT/large payloads | 030 |
| draft-ietf-cose-hpke-27 | Waiting for AD go-ahead | breaking for current `cose` HPKE — ad-hoc `info`; alg 35 is the draft's *integrated* HPKE-0 but `cose` uses it for key encryption; no HPKE values in IANA yet (code points TBD) | 029 |
| draft-ietf-cose-cbor-encoded-cert-21 (C509) | RFC Editor queue | watch | — |
| draft-ietf-cose-sphincs-plus-11 (SLH-DSA) | IETF Last Call ends 2026-12-03 | watch | 029 |
| draft-ietf-cose-falcon, -pqc-kem, -hpke-pq-pqt, -cmac, -split-signing-algs | WG drafts | watch | 029 |
| draft-ietf-jose-pq-composite-sigs-06 | WG draft | watch | 029 |
| draft-ietf-jose-deprecate-none-rsa15 | RFC Editor queue | none for COSE today | — |

## RATS WG (EAT family)

| Document | State | Impact | Handled by |
|---|---|---|---|
| RFC 9711 — EAT | Published 2025-04 | **breaking** — `eat/claims.go` uses draft-era claim keys (see below); its "sw-components" map is actually RFC 9783 PSA claim 2399's shape | 032 |
| RFC 9711 errata 8528, 8771, 8776, 8782, 8783 (technical, verified) | Verified | test vectors / CDDL details (nonce naming in CWT examples, `oemboot` rename, `heading` nullable, ueid encoding) | 032 |
| RFC 9781 — UCCS tag (601) | Published 2025-05 | gap | 031, 026 |
| RFC 9782 — EAT media types | Published 2025-05 | gap | 032 |
| RFC 9783 — PSA attestation token (claims 2394–2400) | Published | gap | 032 |
| RFC 9999 — Conceptual Message Wrapper (claim 299) | Published 2026-07 | gap, later | 032 |
| RFC 10013 — EAT Measured Component | Published 2026-07 | gap — replaces the ad-hoc "sw-components" shape | 032 |
| draft-ietf-rats-ear-06, -corim-12 (WGLC), -coserv | Drafts | watch | 032 |

Authoritative EAT claim keys (IANA CWT registry, 2026-11-13):

| Key | Claim | `eat/claims.go` today |
|---|---|---|
| 10 | Nonce | 10 ✓ |
| 256 | UEID | 256 ✓ |
| 257 | SUEIDs | missing |
| 258 | Hardware OEM ID | 258 ✓ |
| 259 | Hardware Model | missing |
| 260 | Hardware Version | missing |
| 261 | Uptime | **security level** ✗ |
| 262 | OEM Authorized Boot | "secure boot" (same key, old name) |
| 263 | Debug Status | 263 ✓ |
| 264 | Location | missing |
| 265 | EAT Profile | 265 ✓ |
| 266 | Submodules | **uptime** ✗ |
| 267 | Boot Count | **sw-components** ✗ |
| 268 | Boot Seed | **submods** ✗ |
| 269–275 | DLOAs, SW Name, SW Version, SW Manifests, Measurements, Measurement Results, Intended Use | missing |

Note: an LLM-summarized rendering of RFC 9711 produced a *different*
(wrong) table during this survey. Always take code points from the raw
IANA XML, never from a summary.

## LAKE WG (EDHOC)

| Document | State | Impact | Handled by |
|---|---|---|---|
| RFC 9528 — EDHOC | Published 2024-03 | **breaking** — `edhoc` follows a pre-RFC key schedule and message layout | 033 |
| RFC 9529 — EDHOC traces | Published 2024-03 | gap — the golden test vectors that gate 033 | 033 |
| RFC 9668 — EDHOC + OSCORE over CoAP (CoRE WG) | Published | gap | 033 |
| draft-ietf-lake-edhoc-impl-cons-08, -app-profiles-07, -edhoc-grease-04 | Submitted to IESG | watch — implementation guidance to fold in | 033 |
| draft-ietf-lake-edhoc-psk-11 | WG consensus | watch | 033 |
| draft-ietf-lake-authz-08 (WGLC), -ra-07, -pqsuites-02, -authkem-edhoc, -private-use-ranges | Drafts | watch | 033 |

## ACE / SCITT / SPICE

| Document | State | Impact | Handled by |
|---|---|---|---|
| RFC 9200 claims: scope (9), ace_profile (38), cnonce (39), exi (40) | Published | gap | 031 |
| RFC 9203 OSCORE profile; draft-ietf-ace-edhoc-oscore-profile-12 | Published / draft | gap / watch — consumes 033's OSCORE export | 031, 033 |
| RFC 9943 — SCITT architecture | Published 2026-06 | gap — the consumer for 028/030/031 | 030 |
| draft-ietf-scitt-scrapi-11, -receipts-ccf-profile-06 | RFC Ed queue / IESG eval | watch | 030 |
| draft-ietf-spice-sd-cwt (claim 11 `vct`, temporary) | Draft | watch | 031 |

## Code-point collisions found in the current tree

These are not upstream changes, but the survey surfaced them while
cross-checking IANA:

- `cose` PBES2 uses alg **-11** (IANA: direct+HKDF-SHA-512) and header
  label **-21** for the iteration count (IANA/RFC 9053: PartyU identity).
  Proposal 002's planned **-100** is not in the private-use range either. → 029
- `cose` HPKE alg **35** — see the draft-ietf-cose-hpke row. → 029

## Toolchain notes

Go 1.27 standard library ships `crypto/mldsa` (RFC 9964) and
`crypto/hpke`; ChaCha20-Poly1305 and Ed448 remain outside std
(`golang.org/x/crypto`). → 029 open questions

## RFCs to vendor when the owning proposal is accepted

Per `rfcs/README.md`, add these to `rfcs/` (with an inventory row) when
the proposal that cites them moves to Accepted: 8943, 9053, 9090, 9164,
8392, 8747, 9200, 9277, 9360, 9528, 9529, 9581, 9596, 9597, 9668, 9679, 9711,
9781, 9782, 9783, 9864, 9942, 9943, 9964, 9995, 10013.
