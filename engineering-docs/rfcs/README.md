# Vendored RFC text

This directory holds offline copies of the RFCs corecbor's spec cites. They
are authoritative reference material — every `§X.Y` citation in
`engineering-docs/encoder-decoder-spec.md` and downstream proposals points
at one of these documents.

The files are checked in for three reasons:

1. **Offline access** — engineering work and code review shouldn't need
   network round-trips to `rfc-editor.org`.
2. **Pinned reference text** — the RFCs themselves are immutable once
   published, but the website's HTML rendering is not. Citations to "§4.2.1
   of RFC 8949" should resolve to the same words a year from now as they do
   today; vendoring the canonical `.txt` form guarantees that.
3. **Diff anchor** — when an erratum is published or a bis-RFC supersedes
   a current one, dropping the new file in alongside the old one makes the
   delta inspectable.

## Inventory

| File | Title | Status | Why corecbor cites it |
|---|---|---|---|
| `rfc8949.txt` | Concise Binary Object Representation (CBOR) | Internet Standard (STD 94) | Primary spec. Every encoder/decoder requirement traces here. |
| `rfc8742.txt` | Concise Binary Object Representation (CBOR) Sequences | Proposed Standard | Phase 5 streaming dependency. §3 of the spec. |
| `rfc9562.txt` | Universally Unique IDentifiers (UUIDs) | Proposed Standard | Tag-1 timestamp / UUIDv7 interplay for COSE consumers. |
| `rfc7049.txt` | Concise Binary Object Representation (CBOR) | Obsoleted by 8949 | Superseded but cited for "Canonical CBOR" mode (encoder-decoder-spec §2.1). |
| `rfc9052.txt` | CBOR Object Signing and Encryption (COSE) | Internet Standard | Downstream consumer; not in scope but referenced for tag-preservation requirements. |
| `rfc9528.txt` | Ephemeral Diffie-Hellman Over COSE (EDHOC) | Proposed Standard | The `edhoc` module's protocol (proposal 033). |
| `rfc9529.txt` | Traces of Ephemeral Diffie-Hellman Over COSE (EDHOC) | Informational | Golden test vectors; `edhoc/rfc9529_test.go` parses this file directly (proposal 033). |
| `rfc9360.txt` | COSE: Header Parameters for Carrying and Referencing X.509 Certificates | Proposed Standard | x5bag/x5chain/x5t/x5u accessors (proposal 028). |
| `rfc9596.txt` | COSE "typ" (type) Header Parameter | Proposed Standard | `typ` accessor (028). |
| `rfc9597.txt` | CBOR Web Token (CWT) Claims in COSE Headers | Proposed Standard | CWT Claims header label 15 (028, 031). |
| `rfc9679.txt` | COSE Key Thumbprint | Proposed Standard | `(*Key).Thumbprint` and its test vector (028). |
| `rfc9921.txt` | COSE Header Parameter for Timestamp Tokens as Defined in RFC 3161 | Proposed Standard | 3161-ttc / 3161-ctt accessors (028). |
| `rfc8943.txt` | CBOR Tags for Date | Proposed Standard | Tags 100/1004 helpers (proposal 026). |
| `rfc9090.txt` | CBOR Tags for Object Identifiers | Proposed Standard | Tags 110/111/112 helpers (proposal 026). |
| `rfc9164.txt` | CBOR Tags for IPv4 and IPv6 Addresses and Prefixes | Proposed Standard | Tags 52/54 helpers (proposal 026). |
| `rfc9277.txt` | On Stable Storage for Items in CBOR | Proposed Standard | Tags 55799/55800/55801 and content-format tags (proposal 026). |
| `rfc9581.txt` | CBOR Tags for Time, Duration, and Period | Proposed Standard | Tags 1001/1002 helpers and time map keys (proposal 026). |
| `rfc9781.txt` | A CBOR Tag for Unprotected CWT Claims Sets (UCCS) | Proposed Standard | Tag 601 constant (proposal 026; CWT work in 031). |
| `rfc8392.txt` | CBOR Web Token (CWT) | Proposed Standard | The `cwt` module's base spec: claims, tag 61, validation (031). |
| `rfc8747.txt` | Proof-of-Possession Key Semantics for CBOR Web Tokens (CWTs) | Proposed Standard | `cnf` claim: COSE_Key, Encrypted_COSE_Key, kid (031). |
| `rfc9200.txt` | Authentication and Authorization for Constrained Environments Using the OAuth 2.0 Framework (ACE-OAuth) | Proposed Standard | `aud` arrays, `scope`, `ace_profile`, `cnonce`, `exi` claims (031). |
| `rfc9668.txt` | Using EDHOC with CoAP and OSCORE | Proposed Standard | EDHOC + OSCORE combined request framing and the EDHOC option; the §3.4 example is a test vector (`edhoc/coap_test.go`, proposal 033). |
| `rfc9053.txt` | CBOR Object Signing and Encryption (COSE): Initial Algorithms | Informational | Algorithm definitions: ECDH-ES modes, COSE_KDF_Context, AES-CCM, RSA key parameters (proposal 029). |
| `rfc9338.txt` | CBOR Object Signing and Encryption (COSE): Countersignatures | Internet Standard | `cose` V2 countersignatures (labels 11, 12) and the Appendix A vectors (037 S20). |
| `rfc9864.txt` | Fully-Specified Algorithms for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE) | Proposed Standard | ESP256/384/512, Ed25519, Ed448 and the deprecation of ES*/EdDSA (029). |
| `rfc9964.txt` | ML-DSA for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE) | Proposed Standard | ML-DSA-44/65/87 and AKP keys; `cose/mldsa_go127_test.go` parses its Appendix A examples (029). |
| `rfc9711.txt` | The Entity Attestation Token (EAT) | Proposed Standard | `eat` claim numbering, value constraints, submods, detached bundle (032). |
| `rfc9782.txt` | Entity Attestation Token (EAT) Media Types | Proposed Standard | EAT media-type constants (032). |
| `rfc9783.txt` | Arm's Platform Security Architecture (PSA) Attestation Token | Informational | `eat/psa` claims 2394–2400 (032). |
| `rfc10013.txt` | Entity Attestation Token (EAT) Measured Component | Proposed Standard | Measured-component content carried in `measurements` (032 Phase D). |
| `rfc9162.txt` | Certificate Transparency Version 2.0 | Experimental | §2.1 Merkle Tree Hash, inclusion and consistency proof verification used by RFC9162_SHA256 receipts (030). |
| `rfc9942.txt` | CBOR Object Signing and Encryption (COSE) Receipts | Proposed Standard | `cose/receipt`: receipts (394), vds (395), vdp (396), RFC9162_SHA256 proofs (030). |
| `rfc9943.txt` | An Architecture for Trustworthy and Transparent Digital Supply Chains | Proposed Standard | `scitt` module: signed and transparent statements (030). |
| `rfc9995.txt` | CBOR Object Signing and Encryption (COSE) Hash Envelope | Proposed Standard | `cose` hash envelope: labels 258/259/260 and their bucket rules (030). |

## Refresh procedure

These files SHOULD NOT be edited. To refresh from the canonical source
(e.g., to pick up an updated erratum-list footer):

```bash
cd engineering-docs/rfcs
for rfc in 8949 8742 9562 7049 9052 9528 9529 9360 9596 9597 9679 9921 8943 9090 9164 9277 9581 9781 8392 8747 9200 9668 9053 9864 9964 9711 9782 9783 10013 9162 9942 9943 9995; do
  curl -sSL -o "rfc${rfc}.txt" "https://www.rfc-editor.org/rfc/rfc${rfc}.txt"
done
```

If the body changes meaningfully (the RFCs themselves don't, but the
boilerplate footers occasionally do), commit with a message naming the
diff so a future reader can audit.

## Adding a new RFC

When a downstream proposal needs to cite a new RFC:

1. Fetch the `.txt` form from `https://www.rfc-editor.org/rfc/rfcNNNN.txt`.
2. Add a row to the inventory table above.
3. Reference it from the proposal with the same `§X.Y` citation style the
   spec uses.

Do not vendor I-Ds (Internet Drafts) here — they're moving targets and
shouldn't anchor the spec's contracts. Cite by URL in the proposal that
needs them, and replace with the RFC `.txt` form once the I-D promotes.
