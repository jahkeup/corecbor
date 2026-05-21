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

## Refresh procedure

These files SHOULD NOT be edited. To refresh from the canonical source
(e.g., to pick up an updated erratum-list footer):

```bash
cd engineering-docs/rfcs
for rfc in 8949 8742 9562 7049 9052; do
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
