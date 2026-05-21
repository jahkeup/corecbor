# 013 — Diagnostic CLI Tool (`cmd/cbor-diag`)

## Header

| Field | Value |
|---|---|
| **Number** | 013 |
| **Tier** | 2 |
| **Status** | Closed |
| **Filed** | 2026-05-21 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 009 (diagnostic notation library) |
| **Supersedes** | none |
| **Spec sections touched** | none (tooling) |

---

## TL;DR

A CLI tool at `cmd/cbor-diag` that reads CBOR (binary or hex) from
stdin or files and prints RFC 8949 §8 diagnostic notation. Depends on
proposal 009 for the library implementation; this proposal covers the
CLI UX and distribution.

---

## Motivation

Developers working with CBOR need a quick way to inspect binary data:

```bash
# From a file:
cbor-diag payload.cbor

# From hex (clipboard paste):
echo "a26161016162820203" | cbor-diag -hex

# From a pipe (protocol capture):
tcpdump -X | extract-cbor | cbor-diag

# CBOR sequence (multiple items):
cbor-diag -sequence messages.cbor
```

This is the `jq` equivalent for CBOR. Without it, developers resort
to cbor.me (requires network) or ad-hoc hex-decoding scripts.

---

## Proposal

### Usage

```
cbor-diag [flags] [file...]

Flags:
  -hex          Input is hex-encoded text (not raw binary)
  -sequence     Treat input as CBOR sequence (print each item)
  -compact      No whitespace in output
  -indicators   Show encoding indicators (e.g., 1.5_1 for float16)
  -one-line     Each top-level item on a single line (for grep)

With no files, reads from stdin. Multiple files are concatenated.
Exit code 0 on success, 1 on decode error (with error message to stderr).
```

### Installation

```bash
go install github.com/jahkeup/corecbor/cmd/cbor-diag@latest
```

### Output format

Default (pretty):
```
{"a": 1, "b": [2, 3]}
```

Compact:
```
{"a":1,"b":[2,3]}
```

With indicators:
```
{"a": 1, "b": [2, 3]}_0
```

Sequence mode:
```
1
"hello"
[1, 2, 3]
```

### Error handling

Malformed input prints a partial diagnostic up to the error point,
then the error to stderr:
```
{"a": 1, "b": <ERROR at offset 9: unexpected end of input>
```

---

## Open questions

**All resolved:**

- ~~Reverse direction (diag→cbor)~~: **Deferred.** Parsing diagnostic
  notation is significantly harder than printing (requires a full
  text parser for the notation grammar). File as separate proposal if
  demand materializes.
- ~~JSON output~~: **No.** Same as proposal 009 — diagnostic notation
  is CBOR-native inspection format. JSON is a different domain.
- ~~Validation levels~~: **Yes.** Add `-validate` flag that reports
  alongside diagnostic output: `[well-formed]`, `[valid]`, or
  specific issues (non-shortest, duplicate keys, etc.).

---

## Cross-references

- Proposal 009 (diagnostic notation library — the dependency)
- cbor-diag Ruby gem: https://github.com/cabo/cbor-diag
- cbor.me web tool
- RFC 8949 §8

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-21 | Initial draft | corecbor maintainers |
