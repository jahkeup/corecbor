# 008 — Reflective Marshal/Unmarshal API

## Header

| Field | Value |
|---|---|
| **Number** | 008 |
| **Tier** | 1 |
| **Status** | Closed |
| **Filed** | 2026-05-21 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001 (closed) |
| **Supersedes** | none |
| **Spec sections touched** | §10 Phase 5 (reflective marshal/unmarshal surface) |

---

## TL;DR

Add `Marshal(v any) ([]byte, error)` and `Unmarshal(data []byte, v any) error`
to the corecbor ecosystem — the standard Go `encoding/json`-shaped interface
that every consumer expects. This is the difference between a library that is
technically correct and one that is actually usable.

The implementation lives in a dedicated package (e.g., `corecbor/cbor/reflect`
or `corecbor/encoding`) and is re-exported through the root prelude so that
`corecbor.Marshal(myStruct)` works directly. Alternatively, it may live
directly in the root package if the reflection dependency doesn't bloat
callers who only want the Value-tree API.

This is tier-1 because it changes what the prelude exports and how consumers
interact with the library. Without it, the library is expert-only — a
technically sound implementation that nobody can use in normal Go code.

---

## Motivation

Every Go encoding library provides:
```go
data, err := cbor.Marshal(myStruct)
err := cbor.Unmarshal(data, &myStruct)
```

Today, using corecbor requires:
```go
enc := corecbor.New(corecbor.ModeCoreDeterministic)
val := corecbor.Map{
    {Key: corecbor.Text("name"), Value: corecbor.Text(s.Name)},
    {Key: corecbor.Text("age"), Value: corecbor.Uint(uint64(s.Age))},
    // ... manually for every field
}
data, err := enc.Encode(nil, val)
```

This is unacceptable for a production library. The Value-tree API is the
correct primitive layer for COSE/CWT/EDHOC/EAT (they need precise control
over the CBOR structure), but application code needs reflection-based
marshaling.

### Prior art (what Go developers expect)

| Library | Marshal signature | Tag format |
|---|---|---|
| `encoding/json` | `Marshal(v any) ([]byte, error)` | `json:"name,omitempty"` |
| `fxamacker/cbor` | `Marshal(v any) ([]byte, error)` | `cbor:"name,omitempty"` |
| `encoding/xml` | `Marshal(v any) ([]byte, error)` | `xml:"name,attr"` |
| `gopkg.in/yaml.v3` | `Marshal(v any) ([]byte, error)` | `yaml:"name"` |

The interface shape is non-negotiable. The struct tag key is `cbor`.

---

## Proposal

### Package placement options

| Option | Import path | Pros | Cons |
|---|---|---|---|
| **A: Root package** | `corecbor.Marshal(v)` | Single import for everything | Pulls `reflect` into all importers |
| **B: Sub-package + re-export** | `corecbor/encoding` defines, root re-exports | Callers who want only Value-tree don't pay for reflect | Two packages to maintain, type alias dance |
| **C: Standalone sub-package** | `corecbor/encoding.Marshal(v)` | Clean separation | Users must import a second package |

**Recommendation: Option A** (root package). Rationale:
- `reflect` is already in the Go runtime; importing it adds no binary size
  to speak of on modern Go.
- Every competing CBOR library puts Marshal/Unmarshal at the top-level import.
- The Value-tree API and the Marshal API coexist naturally — they serve
  different callers in the same package.
- If a consumer truly needs zero-reflect (e.g., TinyGo), they import
  `corecbor/cbor` + `corecbor/wire` + `corecbor/rfc8949` directly —
  those packages remain reflect-free.

If we discover that the `reflect` import causes problems for constrained
targets, we can split later via Option B without breaking the API (add
the sub-package, keep the root re-exports).

### Public API surface

```go
package corecbor

// Marshaler is implemented by types that produce their own CBOR encoding.
type Marshaler interface {
    MarshalCBOR() ([]byte, error)
}

// Unmarshaler is implemented by types that consume CBOR into themselves.
type Unmarshaler interface {
    UnmarshalCBOR([]byte) error
}

// Marshal returns the CBOR encoding of v using CoreDeterministic mode.
// Struct fields are encoded as a CBOR map with text-string keys (or
// integer keys if the struct tag specifies a numeric key).
func Marshal(v any) ([]byte, error)

// Unmarshal decodes CBOR-encoded data into the value pointed to by v.
// v must be a non-nil pointer.
func Unmarshal(data []byte, v any) error

// Encoder.Marshal encodes v using the encoder's configured mode.
func (e *Encoder) Marshal(v any) ([]byte, error)

// Decoder.Unmarshal decodes data into v using the decoder's strictness knobs.
func (d *Decoder) Unmarshal(data []byte, v any) error
```

### Struct tag format

```go
type Example struct {
    Name    string    `cbor:"name"`           // text key "name"
    Age     int       `cbor:"age,omitempty"`  // omit if zero
    ID      uint64    `cbor:"1"`              // INTEGER key Uint(1), not text "1"
    Secret  []byte    `cbor:"-"`              // skip field
    Payload any       `cbor:"payload"`        // encodes whatever is inside
    created time.Time                         // unexported: skipped
}
```

**Tag options:**
- `cbor:"name"` — field name override
- `cbor:"-"` — skip field entirely
- `cbor:",omitempty"` — skip if zero value
- `cbor:"N"` (where N is an integer) — use integer CBOR map key
- `cbor:",toarray"` (struct-level) — encode struct as CBOR array instead of map (field order = positional)

### Type mapping

**Marshal (Go → CBOR):**

| Go type | CBOR type | Notes |
|---|---|---|
| `bool` | `Bool` | |
| `int`, `int8`...`int64` | `Uint` or `NegInt` | Positive → Uint, negative → NegInt |
| `uint`, `uint8`...`uint64` | `Uint` | |
| `float32` | `Float32` | Deterministic: shortened if lossless |
| `float64` | `Float64` | Deterministic: shortened if lossless |
| `string` | `Text` | |
| `[]byte` | `Bytes` | |
| `[]T` | `Array` | |
| `[N]T` | `Array` | |
| `map[K]V` | `Map` | Keys sorted in deterministic mode |
| `struct` | `Map` | Keys from field names/tags |
| `*T` | value or `Null` | nil → Null |
| `time.Time` | `Tag{1, epoch}` | Integer seconds; sub-second → float |
| `*big.Int` | `Tag{2, bytes}` or `Tag{3, bytes}` | |
| `Marshaler` impl | custom | `MarshalCBOR()` called |
| `encoding.BinaryMarshaler` | `Bytes` | fallback |

**Unmarshal (CBOR → Go):**

| CBOR type | Go target | Notes |
|---|---|---|
| `Uint` | `uint*`, `int*` | Overflow check |
| `NegInt` | `int*` | Overflow check |
| `Bool` | `bool` | |
| `Text` | `string` | |
| `Bytes` | `[]byte` | |
| `Float*` | `float32`, `float64` | Precision loss check for f64→f32 |
| `Array` | `[]T` | Recursive decode |
| `Map` | `map[K]V` or `struct` | Key matching for structs |
| `Tag{1, ...}` | `time.Time` | If target is `time.Time` |
| `Tag{2/3, ...}` | `*big.Int` | If target is `*big.Int` |
| `Null` | zero value / nil pointer | |
| any → `any` | inferred | uint→uint64, text→string, array→[]any, map→map[any]any |

### Decoding into `any` (interface{})

When the target type is `any` or `interface{}`, the decoder infers Go
types from CBOR types:
- `Uint` → `uint64`
- `NegInt` → `int64` (if fits) or error
- `Bool` → `bool`
- `Text` → `string`
- `Bytes` → `[]byte`
- `Float32`/`Float64` → `float64`
- `Array` → `[]any`
- `Map` → `map[any]any` (or `map[string]any` if all keys are text)
- `Null` → `nil`
- `Tag` → `corecbor.Tag` (preserves as-is)

### Encoder/Decoder integration

```go
// Mode-aware marshal:
enc := corecbor.New(corecbor.ModeCanonical)
data, err := enc.Marshal(myStruct)  // uses Canonical mode

// Strict-aware unmarshal:
dec := corecbor.StrictDecoder()
err := dec.Unmarshal(data, &myStruct)  // rejects non-canonical inputs
```

### Behavior with Value types

If the input to `Marshal` is already a `corecbor.Value` (or a concrete
type like `corecbor.Uint`), it encodes directly without reflection.
This allows mixing reflection-based and Value-tree-based code:

```go
data, _ := corecbor.Marshal(corecbor.Array{
    corecbor.Uint(1),
    corecbor.Text("hello"),
})
```

### Failure modes

```go
var (
    ErrUnsupportedType = errors.New("cbor: unsupported type")
    ErrOverflow        = errors.New("cbor: integer overflow")
    ErrTypeMismatch    = errors.New("cbor: cannot unmarshal X into Y")
    ErrNotPointer      = errors.New("cbor: unmarshal requires pointer")
)
```

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| `Marshal(struct)` produces same bytes as hand-built Value tree | `TestMarshal_MatchesValueTree`: marshal struct, encode equivalent Value, compare bytes | Yes |
| `Marshal` → `Unmarshal` round-trip for all Go primitive types | `TestRoundTrip_Primitives` | Yes |
| `Marshal` → `Unmarshal` round-trip for nested structs | `TestRoundTrip_NestedStruct` | Yes |
| `Marshal` → `Unmarshal` round-trip for maps, slices, pointers | `TestRoundTrip_Containers` | Yes |
| Struct tag `cbor:"name"` controls key name | `TestStructTag_Name` | Yes |
| Struct tag `cbor:"-"` skips field | `TestStructTag_Skip` | Yes |
| Struct tag `cbor:",omitempty"` skips zero values | `TestStructTag_Omitempty` | Yes |
| Struct tag `cbor:"1"` (integer) uses integer map key | `TestStructTag_IntegerKey` | Yes |
| `time.Time` marshals as Tag 1 epoch | `TestMarshal_Time` | Yes |
| `*big.Int` marshals as Tag 2/3 | `TestMarshal_BigInt` | Yes |
| `Marshaler` interface is called | `TestMarshalerInterface` | Yes |
| `Unmarshaler` interface is called | `TestUnmarshalerInterface` | Yes |
| Unmarshal into `any` infers correct Go types | `TestUnmarshal_IntoAny` | Yes |
| Integer overflow returns `ErrOverflow` | `TestUnmarshal_Overflow` | Yes |
| Unmarshal into non-pointer returns `ErrNotPointer` | `TestUnmarshal_NotPointer` | Yes |
| `Encoder.Marshal` respects mode | `TestEncoder_Marshal_Mode` | Yes |
| `Decoder.Unmarshal` respects strictness | `TestDecoder_Unmarshal_Strict` | Yes |
| Cross-compat: `Marshal` output decodes with fxamacker/cbor | Compat fixture test | Yes |
| `make check` clean | CI gate | Yes |
| FuzzMarshalUnmarshalRoundTrip | 30s fuzz | Yes |
| Zero allocs for scalar marshal (pre-allocated encoder) | Benchmark | No |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | Marshal: primitives + structs + maps + slices + pointers + tags | Pending | Marshal round-trips all Go primitive types + structs |
| B | Unmarshal: all types + struct tag matching + overflow checks | Pending | Full round-trip: Marshal → Unmarshal for all types |
| C | Interfaces (Marshaler/Unmarshaler) + `toarray` + integer keys + `any` inference | Pending | Interface tests + integer-key struct tests pass |
| D | Performance: field cache, struct codec cache | Pending | Zero-alloc scalar marshal benchmark |

---

## Open questions

**All resolved:**

- ~~Package placement~~: **Root package.** Reflect import is negligible;
  Value-tree-only consumers use `cbor/` + `wire/` + `rfc8949/` directly.

- ~~Nil slice vs empty slice~~: **Empty array (`0x80`).** Matches
  encoding/json precedent. `nil` map → `Null` (distinct semantics: a
  map that doesn't exist vs an empty collection).

- ~~Field ordering~~: **Sorted (deterministic) by default.** In
  CoreDeterministic/Canonical/CTAP2, struct field keys are sorted by
  their encoded CBOR form (mandatory per §4.2.1). In Permissive mode,
  the default is ALSO sorted (predictable output), but callers can opt
  into declaration order via `WithFieldOrder(OrderDeclaration)`:

  ```go
  // Default: sorted in all modes (deterministic, predictable)
  enc := corecbor.New(corecbor.ModePermissive)
  data, _ := enc.Marshal(myStruct) // keys sorted

  // Opt-in: declaration order (only allowed in Permissive mode)
  enc := corecbor.New(corecbor.ModePermissive, WithFieldOrder(OrderDeclaration))
  data, _ := enc.Marshal(myStruct) // keys in struct declaration order

  // Error: cannot use declaration order in deterministic modes
  enc := corecbor.New(corecbor.ModeCoreDeterministic, WithFieldOrder(OrderDeclaration))
  // → returns ErrInvalidMode on Marshal (deterministic requires sorted)
  ```

- ~~Map key types~~: `string`, `int*`, `uint*`. Others →
  `ErrUnsupportedType`.

- ~~`encoding.TextMarshaler`/`TextUnmarshaler`~~: Yes, supported as
  fallback (marshals as Text string).

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Reflection overhead makes Marshal slower than competitors | medium | medium | Phase D: struct codec cache (reflect once, reuse). fxamacker/cbor uses the same pattern. |
| API shape locks in before we discover edge cases | medium | medium | Phase A ships primitives; edge cases surface in B/C. Tag format matches fxamacker for migration ease. |
| Integer key tags (`cbor:"1"`) conflict with text key "1" | low | low | Document clearly: bare integer = integer key; quoted = text key (follow fxamacker convention) |
| `toarray` structs are order-dependent (fragile) | medium | low | Document that field reordering breaks wire compat for toarray structs |

---

## Alternatives considered

### Keep Marshal/Unmarshal out of corecbor (separate library)

Rejected. This fragments the ecosystem. If `corecbor` is the CBOR
library for Go, it must provide the interface Go developers expect.
Telling users "import a second library for basic marshaling" is a
non-starter for adoption.

### Copy fxamacker/cbor's exact API

Partially accepted. We match the struct tag format (`cbor:"..."`)
and the `Marshal`/`Unmarshal` signatures for migration ease, but
our internals are different (Value-tree intermediate, not direct-to-
bytes reflection). This means users can migrate by changing imports
without changing struct tags.

### Direct-to-bytes reflection (skip Value tree intermediate)

Deferred to Phase D optimization. The initial implementation builds
a Value tree from reflection and then encodes it. This is simpler
to implement correctly. Phase D can optimize hot paths to emit bytes
directly from reflected values (skipping the intermediate tree).

---

## Cross-references

- Spec: encoder-decoder-spec.md §10 Phase 5 (reflective marshal/unmarshal)
- Prior art: `fxamacker/cbor` v2 — the Go CBOR library most likely
  to be migrated from. Tag format compatibility is intentional.
- Prior art: `encoding/json` — the interface shape every Go dev knows.
- Sibling proposals: all higher-layer modules (COSE, CWT, EDHOC, EAT)
  continue using the Value-tree API internally; Marshal/Unmarshal is
  for application code consuming those modules' outputs.

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-21 | Initial draft | corecbor maintainers |
