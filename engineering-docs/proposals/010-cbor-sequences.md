# 010 — CBOR Sequences (RFC 8742)

## Header

| Field | Value |
|---|---|
| **Number** | 010 |
| **Tier** | 2 |
| **Status** | Draft |
| **Filed** | 2026-05-21 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001 (closed) |
| **Supersedes** | none |
| **Spec sections touched** | none (formalizes existing Stream API) |

---

## TL;DR

Formalize CBOR Sequences (RFC 8742) as a named type and explicit
encode/decode API, distinct from the single-value `Encode`/`Decode`.
The existing `Stream` iterator already handles sequences at the wire
level; this proposal adds the semantic type and convenience functions.

---

## Motivation

CBOR Sequences are "a sequence of zero or more CBOR data items, not
wrapped in an outer array." They're used in:
- CoAP block-wise transfers
- EDHOC messages (which ARE sequences, not arrays)
- CBOR-over-WebSocket framing
- Log/telemetry streaming (one item per event)

Our `Stream` API already handles this at the io.Reader level. What's
missing is the typed representation and the `[]byte`-oriented API:

```go
type Sequence []Value

func EncodeSequence(dst []byte, items ...Value) ([]byte, error)
func DecodeSequence(src []byte) (Sequence, error)
```

---

## Proposal

### Types and functions

```go
type Sequence []Value

func EncodeSequence(dst []byte, items ...Value) ([]byte, error)
func DecodeSequence(src []byte) (Sequence, error)
func (e *Encoder) EncodeSequence(dst []byte, items ...Value) ([]byte, error)
func (d *Decoder) DecodeSequence(src []byte) (Sequence, error)
```

`DecodeSequence` differs from `Decode` in that it does NOT reject
trailing bytes — it consumes all items until EOF.

### Content-Type

The media type for CBOR sequences is `application/cbor-seq` (RFC 8742
§3). Expose as a constant:

```go
const MediaTypeCBORSeq = "application/cbor-seq"
```

---

## Open questions

- Should `Sequence` support the `Marshaler`/`Unmarshaler` interfaces
  from proposal 008?
- Should `EncodeSequence` accept `...any` (reflection-based) in
  addition to `...Value`?
- Is a separate `DecodeSequence` needed given that `Stream` already
  exists for io.Reader-based consumption?

---

## Cross-references

- RFC 8742 (CBOR Sequences)
- Existing `Stream` API in corecbor (Phase 2)
- EDHOC messages are CBOR sequences (proposal 004)

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-21 | Initial draft | corecbor maintainers |
