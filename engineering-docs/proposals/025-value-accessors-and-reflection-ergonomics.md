# 025 — Value accessors and reflection ergonomics

## Header

| Field | Value |
|---|---|
| **Number** | 025 |
| **Tier** | 2 |
| **Status** | In-Progress |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 016 (struct Value), 008 (Marshal/Unmarshal), 021 (core codec safety fixes — embedded-struct index paths), 034 (compatibility policy) |
| **Supersedes** | none |
| **Spec sections touched** | §4.1 (Value accessors, additive); §8.2 (known caller use cases) |

---

## TL;DR

Every protocol layer built on corecbor (`cose`, `cwt`, `eat`, `edhoc`)
and every anticipated external consumer (WebAuthn/CTAP2, mDL/ISO 18013-5,
SCITT, ACE) re-implements the same handful of operations on `cbor.Value`:
look up a map entry by integer or text label, convert an integer to
`int64` with an overflow check, compare two values, and print a value for
debugging. Reflection-based users additionally lack array-shaped structs
(`toarray`), strict unknown-field rejection, `encoding.TextUnmarshaler` /
`BinaryUnmarshaler` symmetry, and `omitzero`.

This proposal adds those helpers, and four reflection features,
additively. Phase D adds an **opt-in** for keying untagged struct fields
by the Go field name as-is (the `encoding/json` and `fxamacker/cbor`
convention). The default stays `strings.ToLower(f.Name)`: no standard
decides field-name casing, so per proposal 034 the existing behavior is
kept and the alternative is opt-in.

**Acceptance:** the `cose`, `cwt`, `eat`, and `edhoc` modules can delete
their private label-lookup / integer-conversion helpers in favor of the
new API with no behavior change, and every new reflection feature
round-trips through `Marshal`/`Unmarshal` under the existing fuzz targets.

---

## Motivation

### Duplicated lookup and conversion code

`cbor.Value` (`cbor/value.go:34-41`) exposes raw accessors only
(`UintVal`, `NegIntVal`, `Map`, ...). There is no keyed lookup and no
checked integer conversion, so each consumer hand-rolls them:

- `cose/headers.go:211` (`cborToGo`) turns every label into `any`,
  and wraps uint values above `math.MaxInt64` into negative numbers.
- `cwt/claims.go:264` (`fromValue`) and its `switch` on claim keys
  repeat the same pattern. Its `[]byte` return for byte-string keys is
  what makes `DecodeClaimsSet` panic on a bstr claim key (see 021).
- `reflect_decode.go:299` and `reflect_decode.go:379` show the in-tree
  version of the same overflow mistake: `-1 - int64(n)` silently wraps
  for `n >= 2^63`.

Consumers that are *not* in this repo will make the same mistakes:

| Consumer | Needs |
|---|---|
| WebAuthn / CTAP2 | `authData` COSE_Key lookup by labels `1, 3, -1, -2, -3`; checked `int64` for `alg` |
| mDL (ISO 18013-5) | text-keyed `nameSpaces` maps; tag-24 wrapped items; `toarray` for `DeviceAuthentication` |
| SCITT / COSE | integer-keyed header maps; value equality for duplicate-label detection across protected / unprotected |
| ACE / CWT | mixed int/text claim keys; `DisallowUnknownFields` for profile-strict tokens |

### Equality is already implemented, privately

`rfc8949/decode.go:675` (`valuesEqual`) implements CBOR data-model
equality for duplicate-key detection. Consumers need the same function
(COSE RFC 9052 §3 forbids a label in both protected and unprotected
buckets) and currently cannot reach it.

### Reflection gaps

- **No array-shaped structs.** COSE structures (`Sig_structure`,
  `Enc_structure`), EDHOC messages, and mDL `DeviceAuthentication` are
  CBOR arrays. `getStructFields` (`reflect_encode.go:278`) supports
  maps only, so every one of these is hand-built from `Value`s.
- **No unknown-field rejection.** `decodeMapToStruct`
  (`reflect_decode.go:303`) silently `continue`s on unknown keys.
- **Asymmetric marshaler support.** Encode honors
  `encoding.BinaryMarshaler` and `TextMarshaler`
  (`reflect_encode.go:80-110`), but decode has no counterpart, so
  `netip.Addr`, `uuid.UUID`, and `big.Float` encode but never decode.
- **No field metadata cache.** `getStructFields` runs on every
  `Marshal`/`Unmarshal` and rebuilds two maps per struct
  (`reflect_decode.go:268-278`). Proposal 008's risk table already
  anticipated a "struct codec cache".
- **Field-name casing diverges from the ecosystem.** With no `cbor`
  tag, the key is `strings.ToLower(f.Name)` (`reflect_encode.go:303`).
  `encoding/json` and `fxamacker/cbor` both use the field name as-is.
  A `UserID` field is `"userid"` here and `"UserID"` everywhere else.
- **No `omitzero`.** Go 1.24 `encoding/json` added `omitzero` (uses
  `IsZero() bool` when present). `time.Time` is special-cased in
  `isZero` (`reflect_encode.go:344`), but user types with an `IsZero`
  method are not.

---

## Proposal

### Phase A — `cbor.Value` accessors (additive)

```go
// Get returns the value associated with key in a Map, comparing keys by
// CBOR data-model equality (see Equal). It returns false if v is not a
// Map or the key is absent. If the map contains duplicate keys, the
// first match wins — callers that must reject duplicates decode with
// RejectDuplicateMapKeys.
func (v Value) Get(key Value) (Value, bool)

// GetInt is Get with an integer key: Uint for n >= 0, NegInt for n < 0.
// This is the common case for COSE header labels and CWT claim keys.
func (v Value) GetInt(n int64) (Value, bool)

// GetText is Get with a Text key.
func (v Value) GetText(s string) (Value, bool)

// Int64 returns the integer value of a Uint or NegInt Value. It returns
// ErrOverflow if the value is outside [math.MinInt64, math.MaxInt64]
// and ErrTypeMismatch if v is not an integer kind.
func (v Value) Int64() (int64, error)

// Uint64 returns the value of a Uint. It returns ErrTypeMismatch for
// any other kind, including NegInt.
func (v Value) Uint64() (uint64, error)

// Equal reports whether v and w are equal in the CBOR data model
// (RFC 8949 §2): same kind, same value, element-wise for containers,
// order-sensitive for maps. Float NaNs compare equal iff their bit
// patterns match, including the sign bit (RFC 8949 erratum 8589).
func (v Value) Equal(w Value) bool

// String returns the compact diagnostic-notation form of v
// (RFC 8949 §8). It implements fmt.Stringer.
func (v Value) String() string
```

```go
// String returns the kind's name ("uint", "negint", "bytes", "text",
// "array", "map", "tag", "bool", "null", "undefined", "float32",
// "float64", "simple", or "invalid"); unknown values print as
// "Kind(N)". It implements fmt.Stringer, so %v and %s print names
// where they printed numbers.
func (k Kind) String() string
```

`Kind.String()` was requested by a downstream consumer whose v0.2
migration replaced `%T` with `kind %d` in error messages and asked for
a readable form. Adding a `String` method changes what `%v`/`%s` print for a
`Kind`; `%d` is unchanged. Per 034 that is additive (no existing
identifier's documented behavior changes), and callers that need the
number keep using `%d`.

Sentinels: `ErrOverflow` and `ErrTypeMismatch` move into `cbor/errors.go`
next to the existing catalog. The root package keeps aliases
(`corecbor.ErrOverflow` already exists at `marshal.go:21`;
`rfc8949.ErrTypeMismatch` at `rfc8949/cursor.go:18` becomes an alias of
the `cbor` sentinel). Per §5, every error wraps a sentinel.

**Moving `valuesEqual`.** `rfc8949` imports `cbor`, so `cbor` cannot
call into `rfc8949`. The implementation moves to `cbor` as `Equal`, and
`rfc8949/decode.go:675` calls `a.Equal(b)`. The erratum 8589 sign-bit
rule is folded in at the same time (cross-ref 023).

**Resolving the `String()` import cycle.** The diagnostic writer
(`diagWrite`, `diagnostic.go:52`) lives in the root package and
depends only on `cbor` and the standard library. It moves to
`cbor/diag.go` as an unexported `appendDiag(b *strings.Builder, v Value,
compact, indicators bool)`. The root package keeps `Diagnostic(data, ...)`
(which needs the decoder) and `DiagnosticValue(v, ...)`, which delegates.
No exported symbol is removed. `cbor` remains import-free of `rfc8949`.

### Phase B — Reflection features (additive)

1. **Struct-level `toarray`.** A blank-named field `_ struct{} \`cbor:",toarray"\``
   switches the struct to array encoding: exported fields in declaration
   order, no keys. This is the `fxamacker/cbor` spelling, which
   consumers migrating from that library already know. `omitempty` is
   rejected inside a `toarray` struct with `ErrUnsupportedType` (position
   is the identity, so a field cannot be omitted). Decode requires
   `len(array) == NumFields`, or `<=` when trailing fields are pointers
   (models CDDL `? optional` tail items).

2. **`DisallowUnknownFields()` decoder option.** A new `DecoderOption`
   that makes `decodeMapToStruct` return a new
   `ErrUnknownField` (wrapped with the offending key in diagnostic
   form) instead of skipping it. Default remains forgiving (§3.1).

3. **Unmarshaler symmetry.** In `valueToGo`, after the `Unmarshaler`
   check: `encoding.BinaryUnmarshaler` accepts `KindBytes`;
   `encoding.TextUnmarshaler` accepts `KindText`. Precedence mirrors
   encode (`reflect_encode.go:80-110`): Marshaler, then the special
   types (`time.Time`, `big.Int`), then Binary, then Text. This restores
   proposal 008's documented support (`008-reflective-marshal-unmarshal.md:315-316`:
   "`TextMarshaler`/`TextUnmarshaler`: Yes, supported") and the
   `Marshal`→`Unmarshal` round-trip for `BinaryMarshaler` types
   (008:170). The only v0.2.2 behavior that changes is a `[]byte`- or
   `string`-kinded type that also implements the Unmarshaler: v0.2
   stored the raw bytes/text directly, v0.30 calls the method.
   `WithLegacyNoTextBinaryUnmarshal() DecoderOption` (Deprecated)
   restores v0.2.

4. **Field metadata cache with index paths.** Replace `getStructFields`
   with a `sync.Map`-backed cache keyed by `reflect.Type`, storing
   `[]fieldInfo` plus prebuilt `byText map[string]int` and
   `byInt map[int64]int` lookup tables. `fieldInfo.index int` becomes
   `index []int`, used with `FieldByIndex`. That is the fix for the
   embedded-struct defect landed by 021; this phase carries the cache
   and keeps the index paths. The cache is safe for concurrent use
   (`sync.Map`, values immutable after store).

5. **`omitzero`.** Field option that omits when the value has an
   `IsZero() bool` method returning true, else when
   `reflect.Value.IsZero()` is true. `omitempty` semantics are
   unchanged.

**Why no `keyasint`.** `fxamacker/cbor` needs a `keyasint` option
because its tag name is a string by default. Here, a tag name that
parses as an integer *is* the integer key (`reflect_encode.go:317`),
so `cbor:"1"` already encodes as `Uint(1)` and `cbor:"-7"` as
`NegInt(6)`. Adding `keyasint` would be a no-op alias. The one edge
case — a caller who wants the *text* key `"1"` — is out of scope; they
can use a `Marshaler`. Document this behavior in the package godoc.

### Phase C — Consumer migration

Replace private helpers in `cose`, `cwt`, `eat`, and `edhoc` with
`Get`/`GetInt`/`Int64`/`Equal`. This is mechanical and gated on Phase A
only. It is the acceptance check that the API is sufficient.

### Phase D — Opt-in Go field-name casing (additive)

The untagged default stays `strings.ToLower(f.Name)`, as proposal 008
and v0.2.2 define it. No standard decides this, so per proposal 034
(precedence step 3) existing behavior is kept and the ecosystem
convention is an opt-in:

```go
// WithGoFieldNames keys untagged struct fields by the Go field name
// as-is ("UserID", not "userid"), matching encoding/json and
// fxamacker/cbor. Without it, untagged fields use
// strings.ToLower(field name), as in v0.2.
func WithGoFieldNames() Option

// WithCaseInsensitiveFieldNames makes struct decoding match a map key
// against untagged field names exactly first, then case-insensitively
// (the encoding/json rule). Without it, only the exact key for the
// encoder's default naming matches, as in v0.2.
func WithCaseInsensitiveFieldNames() DecoderOption

// CompatV02 applies every encoder-side Legacy selector needed to
// reproduce v0.2.x Marshal/Encode output: WithLegacyBignumPassthrough
// (024).
//
// Deprecated: migrate to explicit selectors; removed no earlier than v0.32.0.
func CompatV02() Option

// CompatV02Decoding applies every decoder-side Legacy selector needed
// to reproduce v0.2.x acceptance: WithLegacyFloatKeyEquality (024) and
// WithLegacyNoTextBinaryUnmarshal (this proposal).
//
// Deprecated: migrate to explicit selectors; removed no earlier than v0.32.0.
func CompatV02Decoding() DecoderOption
```

1. Default untagged key is unchanged (lowercase).
2. `WithGoFieldNames()` changes only encoders it is passed to. Callers
   decoding such output pair it with `WithCaseInsensitiveFieldNames()`.
3. When a map carries two keys that differ only by case,
   `WithCaseInsensitiveFieldNames` prefers the exact match; with
   `DisallowUnknownFields` the other one is an error.
4. The package-level `Marshal`/`Unmarshal` are unchanged.

### Implementation notes (2026-11-21)

Phases A, B and D are implemented. Decisions taken while implementing:

- **`Equal` is the data-model rule, not order-sensitive.** The text
  above says maps compare order-sensitively; RFC 8949 §2 maps are
  unordered, and 024 made the decoder's default key identity the data
  model (±0 equal, cross-width floats equal, NaN by payload and sign).
  `Value.Equal` is that rule, and `rfc8949` delegates to it for
  non-legacy key comparison (text and integer keys stay inline for
  speed).
- **`String()` without an import cycle.** The diagnostic primitives
  live in `internal/diagfmt` (no module imports); the `Value` walk is in
  `cbor` and registers itself with `diagfmt` at init, which the root
  package's `DiagnosticValue` calls. `Diagnostic`/`DiagnosticValue`
  output is unchanged (golden vectors).
- **`Kind.String()`** changed one golden-harness record that formatted
  a `Kind` with `%v`; the harness now prints `%d`, so the recorded
  output is unchanged.
- **`Get`** returns the first match (open question resolved as leaned).
- **`toarray`**: a too-long array is `ErrArrayLength` (open question
  resolved: strict; a forward-compatible tail can be modeled with a
  trailing `[]cbor.Value`-typed field later). Fields under a nil
  embedded pointer encode as null. `toarray` works on the raw
  (`RawMessage`/`Unmarshaler`) decode path too. A map into a `toarray`
  struct, or an array into a map-shaped struct, is a type mismatch.
- **Field cache**: already present since 021 (index paths, `sync.Map`);
  025 adds one cache per naming mode. `BenchmarkMarshalStruct` allocs
  are unchanged from main (13), so the "≥30% fewer allocs" target was
  already met by 021 relative to v0.2.2's per-call `getStructFields`.
- **Text/Binary unmarshalers**: checked only for text and byte-string
  values, and skipped for predeclared/unnamed non-struct target types,
  which can't have methods.
- **Phase C deferred.** The private conversions in `cwt` and `eat`
  (`int64(v.UintVal())`, `-1-int64(v.NegIntVal())`) wrap on overflow;
  switching them to `Int64()` turns wrapping into errors, which is a
  behavior change pinned by golden vectors and is the defect 031/032
  fix. Migrating them belongs with 031/032; `cose`/`edhoc` with
  028/033. The Phase A API covers every site.

### Behavior

Phases A, C and D are purely additive; no existing output or
acceptance changes unless the caller passes a new option. Phase B
item 3 (Text/Binary Unmarshaler symmetry) is a contract-defect fix; see
Compatibility selection.

### Failure modes

| Sentinel | When |
|---|---|
| `ErrOverflow` (moved to `cbor`) | `Int64()` outside range; existing reflect overflow paths |
| `ErrTypeMismatch` (moved to `cbor`) | `Int64()`/`Uint64()` on a non-integer kind |
| `ErrUnknownField` (new, root) | `DisallowUnknownFields` and an unmatched key |
| `ErrUnsupportedType` (existing) | `omitempty` used inside a `toarray` struct |
| `ErrArrayLength` (new, root) | `toarray` decode with too few/many items |

---

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).
No exported identifier changes signature. `ErrOverflow` moves to
`cbor` with the root keeping `var ErrOverflow = cbor.ErrOverflow` (same
value, so `errors.Is` matches either). The package-level `Marshal`
default (lowercase untagged keys) is unchanged.

| Change | Class | Contract restored | Existing identifiers in v0.30 | Selector |
|---|---|---|---|---|
| `encoding.TextUnmarshaler`/`BinaryUnmarshaler` called on decode | Contract defect | `008-reflective-marshal-unmarshal.md:315-316` (TextUnmarshaler "supported"); 008:170 + round-trip of `BinaryMarshaler` types | called; only `[]byte`/`string`-kinded implementers behave differently | `func WithLegacyNoTextBinaryUnmarshal() DecoderOption` — Deprecated, in `CompatV02Decoding()` |
| Untagged struct field key = Go field name as-is | Additive (opt-in) | — (no standard; 034 step 3) | lowercase, unchanged | `func WithGoFieldNames() Option` (not deprecated) |
| Case-insensitive field-name match on decode | Additive (opt-in) | — | exact match only, unchanged | `func WithCaseInsensitiveFieldNames() DecoderOption` |
| `Value` accessors, `toarray`, `DisallowUnknownFields`, `omitzero`, field cache | Additive | — | unchanged | n/a |

Root bundles defined here: `CompatV02() Option` = `WithLegacyBignumPassthrough()`
(024). `CompatV02Decoding() DecoderOption` = `WithLegacyFloatKeyEquality()`
(024) + `WithLegacyNoTextBinaryUnmarshal()`. 021–023 contribute nothing
(see their sections). No `...Option` parameters are appended to
existing functions.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| `GetInt(-1)` finds a `NegInt(0)` key; `GetInt(1)` does not match a `Text("1")` key | table test in `cbor/value_test.go` | Yes |
| `Int64()` returns `ErrOverflow` for `Uint(1<<63)` and `NegInt(1<<63)`; exact at `MinInt64`/`MaxInt64` | table test | Yes |
| `Equal` agrees with the old `valuesEqual` for every pair in the compat vector set | test over `testdata/` vectors | Yes |
| NaN keys with different sign bits are *not* equal (erratum 8589) | unit test | Yes |
| `fmt.Sprint(v)` equals `DiagnosticValue(v, DiagCompact())` | `FuzzValueString` consistency target | Yes |
| `cbor` package does not import `rfc8949` | `go list -deps` check in test | Yes |
| `toarray` struct round-trips `Sig_structure` and matches RFC 9052 App. C vector bytes | test in `marshal_test.go` | Yes |
| `DisallowUnknownFields` rejects an extra key with `errors.Is(err, ErrUnknownField)` | unit test | Yes |
| `netip.Addr` and a `TextMarshaler` type round-trip via `Marshal`/`Unmarshal` | unit test | Yes |
| Struct metadata is computed once per type (no per-call `getStructFields`) | `BenchmarkMarshalStruct` allocs/op drops; race test with 8 goroutines | Yes |
| `cose`, `cwt`, `eat`, `edhoc` compile with private lookup helpers removed | Phase C PR | Yes (Phase C) |
| Default still encodes `UserID` as `"userid"` (v0.2.2 bytes); `WithGoFieldNames()` encodes `"UserID"` | `TestFieldNamesDefaultUnchanged`, `TestWithGoFieldNames` vs `testdata/legacy-v0.2.2/` | Yes (Phase D) |
| Default decode matches exactly as v0.2.2 (a `"UserID"` key does not populate an untagged `UserID` field); with `WithCaseInsensitiveFieldNames()` it does | `TestDecodeCaseDefault`, `TestDecodeCaseInsensitive` | Yes (Phase D) |
| `WithLegacyNoTextBinaryUnmarshal()` reproduces v0.2.2 for `[]byte`/`string`-kinded Unmarshaler types | `TestLegacyNoTextBinaryUnmarshal` | Yes |
| `New(ModeCoreDeterministic, CompatV02()).Marshal(x)` equals v0.2.2 `Marshal(x)` byte-for-byte over the legacy fixture set (excluding 021 defect fixtures) | `TestCompatV02MarshalGolden` vs `testdata/legacy-v0.2.2/` | Yes |
| `CompatV02` and `CompatV02Decoding` carry `// Deprecated:` with removal floor v0.32.0 | staticcheck SA1019 fixture | Yes |
| No exported identifier present in v0.2.2 is removed, renamed, or retyped, and no method is added to an exported interface (034 API stability) | `apidiff` against `v0.2.2` for this module, run in `make check` | Yes |
| Existing identifiers called with no new options reproduce the v0.2.2 golden vectors, except the contract-defect fixes listed under Compatibility selection | `testdata/legacy-v0.2.2/` golden tests | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | `Get`/`GetInt`/`GetText`/`Int64`/`Uint64`/`Equal`/`String`, diag move | Done | Phase A rows green |
| B | `toarray`, `DisallowUnknownFields`, Unmarshaler symmetry, cache, `omitzero` | Done | Phase B rows green |
| C | Migrate sibling modules to Phase A API | Deferred to 028/031/032/033 | Helpers deleted, tests green |
| D | Opt-in `WithGoFieldNames()` / `WithCaseInsensitiveFieldNames()` + root `CompatV02`/`CompatV02Decoding` bundles | Done | Phase D rows green; migration guide entry |

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestValueGet*`, `TestValueInt64` | lookup + checked conversion | `cbor/value_test.go` |
| `TestValueEqual`, `TestValueEqualNaNSign` | equality incl. erratum 8589 | `cbor/value_test.go` |
| `FuzzValueString` | `String()` never panics; equals compact diagnostic | `cbor/fuzz_test.go` (new) |
| `TestMarshalToArray`, `TestUnmarshalToArrayLength` | `toarray` | `marshal_test.go` |
| `TestDisallowUnknownFields` | strict struct decode | `marshal_test.go` |
| `TestTextBinaryUnmarshaler` | symmetry | `marshal_test.go` |
| `FuzzUnmarshalStructNeverPanics` | extends §7.1 catalog with a struct target containing `toarray` and embedded fields | `fuzz_test.go` |
| `TestStructCacheConcurrent` | cache under `-race` | `marshal_test.go` |

---

## Performance

| Metric | Target | Test mechanism |
|---|---|---|
| `Marshal` of a 6-field struct | ≥ 30% fewer allocs/op than today | `go test -bench BenchmarkMarshalStruct -benchmem` |
| `Value.GetInt` on 8-entry map | 0 allocs | `BenchmarkValueGetInt` |
| §9 encode/decode benchmarks | no regression beyond noise (±3%) | `make bench` vs `bench-020-baseline.txt` |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `Get` linear scan is slow on large maps | med | low | Document O(n); large-map users index once via `AsStringMap` or their own map |
| `String()` on huge values allocates heavily inside `%v` logging | med | low | Document; no truncation by default; `DiagnosticValue` remains for control |
| Lowercase default keeps corecbor out of step with other Go encoders | high | low | `WithGoFieldNames()` documented prominently in package godoc and the migration guide |
| `toarray` + embedded struct ordering surprises | low | med | Define order as flattened declaration order; test it |
| Moving `ErrTypeMismatch` changes `errors.Is` identity | low | med | Root/`rfc8949` names become aliases of the same variable |

---

## Alternatives considered

- **Generic `Lookup[K]` helper.** `func Lookup[K int64 | string](v Value, k K)`
  reads well but cannot be a method, and the int/text split covers every
  known consumer. Rejected for API surface; revisit if a third key kind
  (bstr labels) becomes common.
- **Map index on decode** (attach a hash index to `Value`). Speeds up
  `Get` but grows `Value` (already 104 bytes per 016/020) for every
  caller. Rejected.
- **Separate `diag` package** imported by both. Still a cycle if `cbor`
  imports it for `String()`. Moving the writer into `cbor` is the
  smallest fix.
- **Flip the default to as-is, with a `WithLowercaseFieldNames()`
  selector.** Matches every other Go encoder, but silently changes the
  bytes `Marshal` emits for unchanged callers. Rejected under proposal
  034: existing identifiers keep their semantics, and no standard
  requires the change. Revisit only at a major version.

---

## Open questions

- Should `Get` return the *last* match instead, mirroring "last one
  wins" duplicate handling in the forgiving decoder? Current lean:
  first match, and push duplicate-sensitive callers to
  `RejectDuplicateMapKeys`.
- Should `toarray` decoding of a too-long array be an error or ignore
  trailing items (forward compatibility for CDDL `* any` tails)?

---

## Cross-references

- Spec: §4.1, §5, §7.1, §8.2 of `encoder-decoder-spec.md`
- RFCs: `rfcs/rfc8949.txt` §2 (data model), §5.6.1 (+ erratum 8589), §8 (diagnostic notation); RFC 9052 §3, §4.4
- Proposals: 008 (Marshal/Unmarshal, field naming), 016 (Value struct), 021 (embedded-struct fix), 023 (NaN equality / strict decode)
- External: `fxamacker/cbor` struct tags (`toarray`, `keyasint`); Go 1.24 `encoding/json` `omitzero`

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
| 2026-11-20 | API stability (signature + semantics) per revised 034 | corecbor maintainers |
| 2026-11-20 | Add `Kind.String()` (downstream request) to Phase A | corecbor maintainers |
| 2026-11-21 | Phases A, B, D implemented; Phase C deferred to 028/031/032/033; implementation notes | corecbor maintainers |
