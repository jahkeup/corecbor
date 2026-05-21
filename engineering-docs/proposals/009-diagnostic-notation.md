# 009 — CBOR Diagnostic Notation (RFC 8949 §8)

## Header

| Field | Value |
|---|---|
| **Number** | 009 |
| **Tier** | 2 |
| **Status** | Draft |
| **Filed** | 2026-05-21 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001 (closed) |
| **Supersedes** | none |
| **Spec sections touched** | none (quality-of-life tooling) |

---

## TL;DR

Implement a CBOR diagnostic notation formatter per RFC 8949 §8 that
converts CBOR bytes (or a Value tree) to human-readable text. Expose
as both a library function (`Diagnostic([]byte) string`) and a CLI
tool (`cmd/cbor-diag`). Invaluable for debugging, test failure output,
and protocol trace inspection.

---

## Motivation

CBOR is binary. When tests fail, when protocol captures are inspected,
when developers debug wire data — they see hex. Diagnostic notation
transforms `a2 6161 01 6162 82 02 03` into `{"a": 1, "b": [2, 3]}`,
making the structure immediately legible.

Every mature CBOR ecosystem has this:
- cbor.me (web tool)
- cbor-diag (Ruby gem)
- cbor2 (Python `cbor2.loads(b)` repr)
- fxamacker/cbor `Diagnose()` function

corecbor should provide this as first-class tooling.

---

## Proposal

### Library API (in root `corecbor` package)

```go
func Diagnostic(data []byte) (string, error)
func DiagnosticValue(v Value) string
```

### CLI tool (`cmd/cbor-diag`)

```
Usage: cbor-diag [file...]
  Reads CBOR from stdin or named files, prints diagnostic notation.
  Supports CBOR sequences (multiple top-level items).

Flags:
  -hex       Input is hex-encoded (not raw binary)
  -compact   Omit spaces after colons/commas
  -sequence  Treat input as CBOR sequence (multiple items)
```

### Notation format (RFC 8949 §8)

| CBOR type | Diagnostic form |
|---|---|
| Uint | `0`, `23`, `1000000` |
| NegInt | `-1`, `-1000` |
| Bytes | `h'01020304'` |
| Text | `"hello"` (with escapes for non-printable) |
| Array | `[1, 2, 3]` |
| Map | `{"a": 1, "b": 2}` or `{1: "x", 2: "y"}` |
| Tag | `1(1363896240)` |
| Bool | `true`, `false` |
| Null | `null` |
| Undefined | `undefined` |
| Float | `1.5`, `Infinity`, `-Infinity`, `NaN` |
| Simple | `simple(16)` |

### Encoding indicators (§8.1)

Optionally show the encoding width: `1.5_1` (float16), `1.0_2`
(float32), `1000000_3` (64-bit encoded integer). Default: off.
Enable via option or CLI flag.

---

## Open questions

- Should `Diagnostic` accept options (compact, encoding indicators,
  max depth for truncation)? Or separate functions?
- Should the CLI support output to JSON (for piping to jq)?
- Should indefinite-length items show their chunked form or the
  reassembled form in diagnostic output?

---

## Cross-references

- RFC 8949 §8 (Diagnostic Notation)
- cbor.me: https://cbor.me/
- cbor-diag gem: https://github.com/cabo/cbor-diag

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-21 | Initial draft | corecbor maintainers |
