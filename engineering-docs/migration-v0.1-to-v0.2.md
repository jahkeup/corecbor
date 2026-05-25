# Migrating to corecbor v0.2 (struct-based Value)

corecbor v0.2 replaces the `cbor.Value` **interface** with a **struct**.
This eliminates per-value heap allocations (the dominant cost in decode)
but changes how callers construct, inspect, and pattern-match Values.

This guide covers every pattern that needs updating, with before/after
examples drawn from real-world usage.

---

## Quick reference

| v0.1 (interface) | v0.2 (struct) |
|---|---|
| `v.(corecbor.Text)` | `v.TextVal()` |
| `v.(corecbor.Bytes)` | `v.BytesVal()` |
| `v.(corecbor.Bool)` | `v.BoolVal()` |
| `v.(corecbor.Map)` | `v.Map()` (returns `[]MapEntry`) |
| `v.(corecbor.Array)` | `v.Array()` (returns `[]Value`) |
| `make(corecbor.Array, n)` | `make([]corecbor.Value, n)` |
| `make(corecbor.Map, 0, n)` | `make([]corecbor.MapEntry, 0, n)` |
| `corecbor.Map{{Key: k, Value: v}}` | `corecbor.MakeMap(corecbor.MapEntry{Key: k, Value: v})` |
| `return nil, err` (Value return) | `return corecbor.Value{}, err` |
| `string(textVal)` | `textVal` (already a `string`) |
| `[]byte(bytesVal)` | `bytesVal` (already a `[]byte`) |
| `bool(boolVal)` | `boolVal` (already a `bool`) |

---

## 1. Type assertions → Kind checks + accessors

**Before (v0.1):**
```go
func decodePayload(v corecbor.Value) (string, error) {
    t, ok := v.(corecbor.Text)
    if !ok {
        return "", fmt.Errorf("expected text, got %T", v)
    }
    return string(t), nil
}
```

**After (v0.2):**
```go
func decodePayload(v corecbor.Value) (string, error) {
    if v.Kind() != corecbor.KindText {
        return "", fmt.Errorf("expected text, got kind %d", v.Kind())
    }
    return v.TextVal(), nil
}
```

The accessor returns the native Go type directly — no type conversion
needed (`TextVal()` returns `string`, `BytesVal()` returns `[]byte`,
`BoolVal()` returns `bool`).

---

## 2. Type switches → Kind switches

**Before (v0.1):**
```go
switch payload := v.(type) {
case corecbor.Text:
    return string(payload), nil
case corecbor.Bytes:
    return []byte(payload), nil
case corecbor.Bool:
    return bool(payload), nil
default:
    return nil, fmt.Errorf("unexpected type %T", v)
}
```

**After (v0.2):**
```go
switch v.Kind() {
case corecbor.KindText:
    return v.TextVal(), nil
case corecbor.KindBytes:
    return v.BytesVal(), nil
case corecbor.KindBool:
    return v.BoolVal(), nil
default:
    return nil, fmt.Errorf("unexpected kind %d", v.Kind())
}
```

---

## 3. Constructing arrays

**Before (v0.1):**
```go
// Array was a named type: type Array []Value
out := make(corecbor.Array, len(items))
for i, item := range items {
    out[i] = corecbor.Text(item)
}
return wrapInMap(tag, out), nil
```

**After (v0.2):**
```go
// Array is no longer a type — use []corecbor.Value, then wrap
out := make([]corecbor.Value, len(items))
for i, item := range items {
    out[i] = corecbor.Text(item)
}
return wrapInMap(tag, corecbor.MakeArrayFromSlice(out)), nil
```

Key difference: `corecbor.Array` is no longer a type you can `make()`.
Build a `[]corecbor.Value` slice, then pass it to `MakeArrayFromSlice`
(or use `MakeArray(item1, item2, ...)` for small inline arrays).

---

## 4. Constructing maps

**Before (v0.1):**
```go
// Map was a named type: type Map []MapEntry
out := make(corecbor.Map, 0, len(m))
for k, v := range m {
    val, _ := encode(v)
    out = append(out, corecbor.MapEntry{
        Key:   corecbor.Text(k),
        Value: val,
    })
}
return out, nil
```

**After (v0.2):**
```go
out := make([]corecbor.MapEntry, 0, len(m))
for k, v := range m {
    val, _ := encode(v)
    out = append(out, corecbor.MapEntry{
        Key:   corecbor.Text(k),
        Value: val,
    })
}
return corecbor.MakeMapFromSlice(out), nil
```

The `MapEntry` struct is unchanged — only the outer slice type changes
from `corecbor.Map` to `[]corecbor.MapEntry`, with a final
`MakeMapFromSlice` call to wrap it as a `Value`.

---

## 5. Map/Array literals (single-expression construction)

**Before (v0.1):**
```go
wrapped := corecbor.Map{{Key: corecbor.Text(tag), Value: payload}}
```

**After (v0.2):**
```go
wrapped := corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Text(tag), Value: payload})
```

---

## 6. Iterating decoded maps

**Before (v0.1):**
```go
m, ok := v.(corecbor.Map)
if !ok { return err }
for _, entry := range m {
    k, ok := entry.Key.(corecbor.Text)
    if !ok { return err }
    processKey(string(k), entry.Value)
}
```

**After (v0.2):**
```go
if v.Kind() != corecbor.KindMap { return err }
for _, entry := range v.Map() {
    if entry.Key.Kind() != corecbor.KindText { return err }
    processKey(entry.Key.TextVal(), entry.Value)
}
```

---

## 7. Iterating decoded arrays

**Before (v0.1):**
```go
arr, ok := v.(corecbor.Array)
if !ok { return err }
out := make([]string, len(arr))
for i, e := range arr {
    t, ok := e.(corecbor.Text)
    if !ok { return err }
    out[i] = string(t)
}
```

**After (v0.2):**
```go
if v.Kind() != corecbor.KindArray { return err }
items := v.Array()
out := make([]string, len(items))
for i, e := range items {
    if e.Kind() != corecbor.KindText { return err }
    out[i] = e.TextVal()
}
```

---

## 8. Nil Values → zero Values

`Value` is now a struct. You cannot assign `nil` to it or compare with
`nil`. The zero value (`Value{}`) has `Kind() == KindInvalid`.

**Before (v0.1):**
```go
func encode(v Attribute) (corecbor.Value, error) {
    if v == nil {
        return nil, ErrNilValue
    }
    // ...
}
```

**After (v0.2):**
```go
func encode(v Attribute) (corecbor.Value, error) {
    if v == nil {
        return corecbor.Value{}, ErrNilValue
    }
    // ...
}
```

To check if a decoded Value is the zero/invalid value:
```go
if val.IsZero() { /* was nil in v0.1 */ }
```

---

## 9. Function signatures returning specific types

If your functions returned `corecbor.Map` or `corecbor.Array` as
concrete types, they now return `corecbor.Value`:

**Before (v0.1):**
```go
func buildMap(m map[string]Thing) (corecbor.Map, error) {
    out := make(corecbor.Map, 0, len(m))
    // ...
    return out, nil
}
```

**After (v0.2):**
```go
func buildMap(m map[string]Thing) (corecbor.Value, error) {
    out := make([]corecbor.MapEntry, 0, len(m))
    // ...
    return corecbor.MakeMapFromSlice(out), nil
}
```

---

## 10. Error messages with `%T`

Type-assertion failure messages that used `%T` to print the concrete
type need updating:

**Before:** `fmt.Errorf("expected text, got %T", v)` → prints `cbor.Bytes`
**After:** `fmt.Errorf("expected text, got kind %d", v.Kind())` → prints `3`

For readable names, add a `Kind.String()` switch or use the constants
directly in your error messages.

---

## 11. Scalar constructors (unchanged)

These work identically in both versions — no migration needed:

```go
corecbor.Text("hello")       // was type conversion, now constructor — same syntax
corecbor.Uint(42)            // same
corecbor.NegInt(0)           // same (represents -1)
corecbor.Bytes([]byte{...})  // same
corecbor.Bool(true)          // same
corecbor.Float64(3.14)       // same
```

---

## 12. New opt-in performance features (v0.2)

These are additive — no migration required, but available for callers
who need maximum throughput:

```go
// Zero-alloc decode with arena + zero-copy:
arena := rfc8949.NewArena(1024, 64)
dec := corecbor.NewDecoder(
    corecbor.WithArena(arena),
    corecbor.WithZeroCopy(),
)
for msg := range stream {
    arena.Reset()
    val, _ := dec.Decode(msg)
    process(val) // must complete before next Reset()
}

// Pre-computed map key order for hot-path encode:
keys := []cbor.Value{cbor.Text("alg"), cbor.Text("kid")}
order, _ := rfc8949.PrecomputeMapOrder(keys, rfc8949.SortBytewiseLex, opts)
// ... then in hot loop:
rfc8949.EncodeMapPreordered(buf[:0], header, order, opts)

// Streaming without Value construction:
s := enc.Stream(w)
s.BeginMap(2)
s.WriteText("id")
s.WriteUint(42)
s.WriteText("data")
s.WriteBytes(payload)
s.EndContainer()

// Memory budget for untrusted input:
dec := corecbor.NewDecoder(corecbor.WithMemoryBudget(64 * 1024))
```

---

## Mechanical migration checklist

1. `go build ./...` — fix all compile errors (the compiler catches every
   type assertion and named-type usage)
2. Replace `v.(corecbor.X)` with Kind check + accessor
3. Replace `make(corecbor.Array, n)` with `make([]corecbor.Value, n)` + `MakeArrayFromSlice`
4. Replace `make(corecbor.Map, 0, n)` with `make([]corecbor.MapEntry, 0, n)` + `MakeMapFromSlice`
5. Replace `corecbor.Map{{...}}` literals with `corecbor.MakeMap(...)`
6. Replace `return nil, err` in Value-returning functions with `return corecbor.Value{}, err`
7. Replace `string(textVal)` / `[]byte(bytesVal)` / `bool(boolVal)` with direct use (accessors return native types)
8. Replace `%T` in error messages with `v.Kind()`
9. `go test ./...` — verify behavior unchanged
