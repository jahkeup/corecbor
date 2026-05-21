# 014 — RawMessage, RawTag, and declarative tag wrapping

## Header

| Field | Value |
|---|---|
| **Number** | 014 |
| **Tier** | 1 |
| **Status** | Closed |
| **Filed** | 2026-05-21 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 008 (Marshal/Unmarshal) |
| **Supersedes** | none |
| **Spec sections touched** | §4 (value model extension for raw/tagged representation) |

---

## TL;DR

Add three mechanisms for callers who need control over tagged values
and deferred decoding in the reflective Marshal/Unmarshal API:

1. **`RawMessage`** — opaque pre-encoded CBOR bytes (json.RawMessage
   equivalent). Passes through marshal/unmarshal without re-encoding.
2. **`RawTag`** — a tagged value with opaque inner content. The caller
   controls both the tag ID and the inner encoding.
3. **`cbor:",tag=N"` struct tag option** — declaratively wraps a
   field's normal encoding in Tag(N) without requiring a custom type.

These solve the gap between "automatic reflection" and "full Marshaler
interface" — the common middle ground where a caller knows the wire
format but doesn't want to hand-implement encode/decode.

---

## Motivation

### Problem 1: Deferred decoding (RawMessage)

A protocol envelope contains a versioned payload. The outer struct is
decoded first; the inner payload is decoded later based on a version
discriminator:

```go
type Envelope struct {
    Version int `cbor:"1"`
    Payload ???  `cbor:"2"`  // decode later based on Version
}
```

Without `RawMessage`, the caller must either:
- Decode into `any` (loses type safety, allocates map[any]any)
- Decode the full bytes twice (once to get Version, again for Payload)
- Use the Value-tree API directly (defeats the purpose of Marshal)

With `RawMessage`:
```go
type Envelope struct {
    Version int                 `cbor:"1"`
    Payload corecbor.RawMessage `cbor:"2"`
}

var env Envelope
corecbor.Unmarshal(data, &env)
switch env.Version {
case 1:
    var p PayloadV1
    corecbor.Unmarshal(env.Payload, &p)
case 2:
    var p PayloadV2
    corecbor.Unmarshal(env.Payload, &p)
}
```

This is identical to `json.RawMessage` — the most-used type in the
encoding/json ecosystem for exactly this pattern.

### Problem 2: Opaque tagged values (RawTag)

A consumer receives COSE-signed data (Tag 18) but doesn't want to
import the COSE module or decode the COSE structure — just hold it:

```go
type Document struct {
    Signature corecbor.RawTag `cbor:"sig"`
}
// sig.ID == 18, sig.Content holds the raw COSE_Sign1 bytes
```

Or a proxy relays tagged data without understanding it:
```go
type RelayMessage struct {
    From    string           `cbor:"from"`
    Payload corecbor.RawTag  `cbor:"payload"`  // forward without decode
}
```

### Problem 3: Simple tag wrapping (struct tag)

Many CBOR protocols use tags to annotate values (Tag 32 = URI, Tag 37
= UUID, Tag 24 = nested CBOR). When the inner encoding is the field's
natural encoding, a struct tag suffices:

```go
type Resource struct {
    URI      string   `cbor:"uri,tag=32"`      // → Tag(32, Text("https://..."))
    ID       [16]byte `cbor:"id,tag=37"`       // → Tag(37, Bytes([16]byte))
    Embedded []byte   `cbor:"nested,tag=24"`   // → Tag(24, Bytes(cbor...))
}
```

Without `tag=N`, the caller must define a custom type with Marshaler
for each of these — pure boilerplate for what is a one-line annotation.

### Problem 4: Conflicting type vs tag semantics

`time.Time` defaults to Tag(1, epoch integer). But some protocols
require Tag(0, RFC 3339 text string). The struct tag `cbor:",tag=0"`
would naively produce Tag(0, Tag(1, epoch)) — nonsense.

Resolution: `cbor:",tag=N"` is a **dumb wrapper** that wraps whatever
the field produces. For conflicting cases, the caller uses one of:
- A newtype with `Marshaler` that produces the correct inner encoding
- A `RawTag` field with manual content construction
- A `RawMessage` field with pre-encoded bytes

The struct tag does NOT try to be smart about inner encoding. This is
intentional — being smart requires knowing every tag's semantics, which
is an unbounded problem. Being dumb is predictable and composable.

---

## Proposal

### RawMessage

```go
// RawMessage is pre-encoded CBOR that is passed through Marshal and
// Unmarshal without modification. It implements Marshaler and
// Unmarshaler.
//
// On Marshal: the bytes are emitted directly (no re-encoding).
// On Unmarshal: the raw CBOR bytes for the value are captured as-is.
//
// This is the CBOR equivalent of json.RawMessage.
type RawMessage []byte

func (r RawMessage) MarshalCBOR() ([]byte, error) {
    if r == nil {
        // nil RawMessage marshals as CBOR null
        return Marshal(Null{})
    }
    return []byte(r), nil
}

func (r *RawMessage) UnmarshalCBOR(data []byte) error {
    *r = append((*r)[:0], data...)
    return nil
}
```

**Semantics:**
- Zero value (`nil`): marshals as CBOR null, unmarshals to nil
- Empty but non-nil (`RawMessage{}`): invalid CBOR, marshal returns error
- Valid CBOR bytes: passed through verbatim on marshal, captured on unmarshal

**Validation:** `RawMessage` does NOT validate that its content is
well-formed CBOR on marshal. The bytes are emitted as-is. If the caller
puts garbage in, garbage comes out. Validation happens when the bytes
are eventually decoded (by the consumer or a subsequent Unmarshal call).

### RawTag

```go
// RawTag is a CBOR tagged value where the caller controls both the
// tag ID and the raw encoding of the inner content.
//
// On Marshal: emits Tag(ID, <Content decoded as Value>). If Content
// is nil, emits Tag(ID, Null).
// On Unmarshal: captures the tag ID and the raw encoded inner value.
//
// Use RawTag when you need to hold a tagged value without decoding
// the inner content, or when you need to control the exact inner
// encoding (avoiding conflicts between Go type defaults and tag
// semantics).
type RawTag struct {
    ID      uint64
    Content RawMessage
}

func (t RawTag) MarshalCBOR() ([]byte, error) {
    // Encode as: Tag header + raw content bytes
    // Does NOT re-encode Content — emits it verbatim after the tag header
}

func (t *RawTag) UnmarshalCBOR(data []byte) error {
    // Decode tag header, capture ID, capture inner bytes as Content
}
```

**Key behavior:** The Content field holds the encoded CBOR of the
inner value — NOT the outer tagged encoding. On marshal, the tag
header is prepended. On unmarshal, the tag header is consumed and
only the inner bytes are stored.

### Struct tag `cbor:",tag=N"`

```go
type Example struct {
    URI    string   `cbor:"uri,tag=32"`
    ID     [16]byte `cbor:"id,tag=37"`
    Nested []byte   `cbor:"nested,tag=24"`
}
```

**Marshal behavior:**
1. Encode the field using its normal Go→CBOR type mapping
2. Wrap the encoded Value in Tag(N, encodedValue)

**Unmarshal behavior:**
1. Expect a Tag with ID == N (error if wrong tag or no tag)
2. Decode the inner value into the field using normal CBOR→Go mapping

**Error cases:**
- If the CBOR value at this position is NOT a Tag: error (tag expected)
- If the Tag ID doesn't match N: error (wrong tag ID)
- If the inner value can't decode into the field type: normal type error

### When each mechanism is appropriate

| Situation | Use |
|---|---|
| Defer decoding until runtime type is known | `RawMessage` field |
| Forward/relay without understanding content | `RawMessage` field |
| Hold a tagged value without decoding inner | `RawTag` field |
| Emit a specific tag with caller-controlled inner | `RawTag` field |
| Wrap a field's natural encoding in a tag | `cbor:",tag=N"` struct tag |
| Tag requires different inner encoding than type default | Implement `Marshaler` on a newtype |
| Full custom wire format | Implement `Marshaler`/`Unmarshaler` |

### The conflict case: time.Time + Tag(0)

```go
// WRONG: produces Tag(0, Tag(1, epoch)) — double-tagged nonsense
type Bad struct {
    When time.Time `cbor:"when,tag=0"`
}

// CORRECT option 1: newtype with Marshaler
type RFC3339Time time.Time
func (t RFC3339Time) MarshalCBOR() ([]byte, error) { /* Tag(0, Text(RFC3339)) */ }
type Good1 struct {
    When RFC3339Time `cbor:"when"`
}

// CORRECT option 2: RawTag with manual construction
type Good2 struct {
    When corecbor.RawTag `cbor:"when"`
}
// Before marshal: s.When = corecbor.RawTag{ID: 0, Content: encodedRFC3339Text}

// CORRECT option 3: RawMessage (you handle it entirely)
type Good3 struct {
    When corecbor.RawMessage `cbor:"when"`
}
```

The library does NOT try to be clever about tag-vs-type conflicts.
The `cbor:",tag=N"` option is explicitly DUMB — it wraps whatever
comes out. When that's not what you want, you reach for the next tool
(Marshaler, RawTag, RawMessage). This layering is intentional and
mirrors how encoding/json's `json.RawMessage` + `json.Marshaler`
compose without magic.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| `RawMessage` round-trips through Marshal/Unmarshal | TestRawMessage_RoundTrip | Yes |
| `RawMessage(nil)` marshals as CBOR null | TestRawMessage_Nil | Yes |
| `RawMessage` in struct field defers decoding | TestRawMessage_DeferredDecode | Yes |
| `RawTag` round-trips with correct tag ID | TestRawTag_RoundTrip | Yes |
| `RawTag` preserves inner bytes exactly | TestRawTag_InnerPreserved | Yes |
| `cbor:",tag=N"` wraps field in Tag on marshal | TestStructTag_TagWrap | Yes |
| `cbor:",tag=N"` unwraps Tag on unmarshal | TestStructTag_TagUnwrap | Yes |
| `cbor:",tag=N"` errors on wrong tag ID during unmarshal | TestStructTag_WrongTagID | Yes |
| `cbor:",tag=N"` errors on non-tagged value during unmarshal | TestStructTag_NotATag | Yes |
| Conflict case (time.Time + tag=0) produces double-tagged output (documented, not magic) | TestStructTag_ConflictDocumented | Yes |
| `RawMessage` as map value | TestRawMessage_InMap | Yes |
| `RawTag` as slice element | TestRawTag_InSlice | Yes |
| `make check` clean | CI gate | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | `RawMessage` type + Marshal/Unmarshal support | Pending | Deferred decode tests pass |
| B | `RawTag` type + Marshal/Unmarshal support | Pending | Tag preservation tests pass |
| C | `cbor:",tag=N"` struct tag option | Pending | Wrap/unwrap tests pass |

Each phase is independently shippable. Phase A alone solves the most
common need (deferred decoding). Phase C depends on the struct tag
parsing already in place from proposal 008.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| RawMessage containing invalid CBOR causes downstream errors | medium | low | Document that RawMessage is not validated on marshal. Validation is the consumer's responsibility (same as json.RawMessage). |
| `cbor:",tag=N"` surprise with types that already produce tags (time.Time) | high | medium | Document explicitly. Add a test demonstrating the double-tag behavior. Users who hit this reach for Marshaler/RawTag. |
| RawTag.Content holding bytes from a different encoder (incompatible CBOR) | low | low | Content is just bytes — corecbor doesn't validate provenance. Same model as RawMessage. |
| Feature interaction: `cbor:",tag=N,omitempty"` — what's "zero" for a tagged field? | medium | low | Zero is the field's zero value (before tagging). An empty string tagged with 32 is still omitted if omitempty is set. |

---

## Alternatives considered

### Generic `Tagged[T]` wrapper type

```go
type Tagged[T any] struct {
    ID    uint64
    Value T
}
```

Rejected for the general case. The problem: `Tagged[time.Time]` with
ID=0 would encode as Tag(0, Tag(1, epoch)) because `time.Time`'s
default encoding already produces a tag. The generic wrapper can't
intercept T's encoding to change it. `Tagged[T]` only works when T's
natural encoding IS the correct inner content — which is the same
constraint as `cbor:",tag=N"`. The struct tag is simpler (no extra type).

For the rare case where you need a standalone tagged type (not in a
struct), use `RawTag` + manual content encoding.

### Validate RawMessage on marshal

Rejected. json.RawMessage doesn't validate either. Validation on
marshal would require a full decode pass — expensive and defeats the
purpose (the caller may have pre-validated or constructed the bytes
from a trusted source). Validation happens on unmarshal when the bytes
are eventually consumed.

### Auto-detect tag conflicts (time.Time + tag=0 → smart encoding)

Rejected. This requires the marshal layer to know the semantics of
every tag number and how each Go type should be differently encoded
for each tag. This is an unbounded problem (IANA registers new tags
continuously). The dumb-wrapper approach is predictable: the caller
knows what `tag=N` does (wraps the output), and if that's not what
they want, they use a more explicit mechanism.

### Single `Raw` type that handles both untagged and tagged

Rejected. The semantics are too different:
- `RawMessage` holds bytes that could be ANY CBOR value (no tag assumed)
- `RawTag` specifically represents a tagged value (always emits a tag header)

Combining them makes the API confusing — "does this field expect a tag
or not?" Being explicit (two types) makes the wire format predictable
from the struct definition alone.

---

## Cross-references

- Proposal 008 (Marshal/Unmarshal — the foundation this extends)
- `encoding/json.RawMessage` — direct precedent for `RawMessage`
- `fxamacker/cbor.RawMessage` — prior art in the Go CBOR ecosystem
- RFC 8949 §3.4 (tagging of items — what Tag(N, ...) means on wire)
- COSE structures use integer-keyed maps with tagged inner values —
  RawTag is useful for holding COSE fragments without importing cose/

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-21 | Initial draft | corecbor maintainers |
