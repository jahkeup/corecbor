# 006 — IANA CBOR registry sync, codegen, and embedding

## Header

| Field | Value |
|---|---|
| **Number** | 006 |
| **Tier** | 2 |
| **Status** | Closed |
| **Filed** | 2026-05-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001 (corecbor primitives) |
| **Supersedes** | none |
| **Spec sections touched** | §4.3 (tag handling informs registry usage) |

---

## TL;DR

Provide a periodically-synchronized local cache of the IANA CBOR
registries (Tags, Simple Values, and optionally COSE Algorithms) with
a code generator that produces typed Go constants, documentation, and
optional validation helpers.  The generated output is **opt-in** — it
lives in a separate package that callers import only when they want
registry-aware tag handling.  Callers who need minimal binary size
(constrained clients, embedded) never import it.

Additionally, support **subset selection** (generate only the tags a
project uses) and **override/external registry files** (for private
tag ranges, pre-release IANA assignments, or air-gapped environments).

---

## Motivation

The IANA CBOR Tags registry (https://www.iana.org/assignments/cbor-tags/)
currently has 60+ registered tags with semantics ranging from date/time
(tags 0, 1) to bignums (2, 3) to COSE structures (16–18, 96–98) to
geographic coordinates (103) to CBOR-encoded data (24) and many more.

Today, CBOR libraries handle this in one of three ways:

1. **Hard-code a snapshot** — the library has a static list of known
   tags baked in at release time.  Goes stale between releases.
   Consumers can't add private tags without forking.
2. **Ignore the registry entirely** — treat all tags as opaque
   `Tag{ID, Inner}`.  Correct but unhelpful: no documentation, no
   constants, no validation.
3. **Manual maintenance** — developers hand-maintain a constants file.
   Error-prone, drifts from IANA.

This proposal provides a fourth option:

4. **Machine-synchronized, codegen'd, opt-in** — a tool fetches the
   registry, caches it, generates Go code, and the output is a
   package you import only if you want it.  Private tags, subsets,
   and overrides are first-class.

### Use cases

- **Tag documentation in IDE** — generated constants carry godoc
  linking the tag to its RFC and semantics.  `registry.TagDateTime`
  is self-documenting; `uint64(0)` is not.
- **Validation helpers** — "is this tag ID registered?" without
  hard-coding a list.
- **COSE/CWT/EAT alignment** — the COSE algorithms registry and CBOR
  tags registry are both IANA-managed.  Same sync mechanism serves
  both.
- **Private/enterprise tags** — organizations with private tag ranges
  (first-come-first-served above 256, or specification-required
  ranges) can maintain an override file that the generator merges.
- **Air-gapped builds** — the cached registry file is checked into
  the repo; no network access required at build time.
- **Constrained clients** — projects that don't need registry
  awareness never import the generated package; zero binary size
  cost.

---

## Proposal

### Architecture

```
github.com/jahkeup/corecbor/
├── cmd/
│   └── cbor-registry-gen/           # CLI tool: fetch + cache + generate
│       ├── main.go
│       ├── fetch.go                 # IANA registry fetcher (CSV/XML)
│       ├── cache.go                 # Local cache management
│       ├── generate.go              # Go code generator
│       ├── subset.go                # Subset/filter logic
│       └── override.go             # Override file merging
├── registry/                        # Generated package (opt-in import)
│   ├── doc.go                      # Package doc (notes generation source)
│   ├── tags.go                     # Generated: tag constants + docs
│   ├── simplevalues.go             # Generated: simple value constants
│   ├── registry.go                 # Lookup/query API
│   └── registry.json               # Cached registry data (checked in)
└── registry.json                    # Default cache location (workspace root alt)
```

### Registry data format

The canonical cache is a JSON file combining IANA sources:

```json
{
  "fetched_at": "2026-05-20T10:30:00Z",
  "source": "https://www.iana.org/assignments/cbor-tags/cbor-tags.xml",
  "tags": [
    {
      "tag": 0,
      "data_item": "text string",
      "semantics": "Standard date/time string; see Section 3.4.1",
      "reference": "RFC 8949",
      "status": "standards-track"
    },
    {
      "tag": 1,
      "data_item": "integer or float",
      "semantics": "Epoch-based date/time; see Section 3.4.2",
      "reference": "RFC 8949",
      "status": "standards-track"
    }
  ],
  "simple_values": [
    {
      "value": 20,
      "semantics": "false",
      "reference": "RFC 8949"
    }
  ]
}
```

### Override file format

Users maintain an override file (same schema, merged on top):

```json
{
  "tags": [
    {
      "tag": 60000,
      "data_item": "array",
      "semantics": "Internal: MyCompany telemetry envelope",
      "reference": "internal",
      "status": "private"
    }
  ]
}
```

The generator merges overrides by tag number (override wins on
conflict).  This enables:

- Private enterprise tags.
- Pre-release IANA assignments not yet in the published registry.
- Corrections/annotations for tags the project interprets differently.

### Subset selection

A config file (or CLI flags) specifies which tags to include in the
generated output:

```json
{
  "include_tags": [0, 1, 2, 3, 24, 32, 55799],
  "include_ranges": [{"min": 16, "max": 18}, {"min": 96, "max": 98}],
  "exclude_tags": [],
  "include_all": false
}
```

When `include_all` is false (the default for constrained builds), only
explicitly listed tags appear in the generated code.  This produces
a minimal binary with only the tag constants the project uses.

### CLI tool (`cbor-registry-gen`)

```
Usage: cbor-registry-gen [flags]

Flags:
  -fetch              Fetch latest registry from IANA (updates cache)
  -cache PATH         Path to registry cache JSON (default: ./registry/registry.json)
  -override PATH      Path to override file (merged on top of cache)
  -config PATH        Path to subset config (default: generate all)
  -out PATH           Output directory for generated Go code
  -package NAME       Go package name for generated code (default: registry)
  -cose               Also generate COSE algorithm constants
  -dry-run            Print what would be generated without writing

Examples:
  # Fetch and regenerate everything:
  cbor-registry-gen -fetch -out ./registry/

  # Generate subset for a constrained project:
  cbor-registry-gen -config tags-subset.json -out ./internal/tags/

  # Merge private tags:
  cbor-registry-gen -override my-tags.json -out ./registry/

  # Just update the cache (CI periodic job):
  cbor-registry-gen -fetch -cache ./registry/registry.json
```

### Generated code shape

```go
// Code generated by cbor-registry-gen. DO NOT EDIT.
// Source: IANA CBOR Tags registry, fetched 2026-05-20T10:30:00Z.

package registry

// Tag constants from the IANA CBOR Tags registry.
// Each constant's godoc describes the tag's semantics and references
// the defining RFC.
const (
    // TagDateTimeString is CBOR tag 0: Standard date/time string (RFC 3339).
    // Data item: text string.
    // Reference: RFC 8949 §3.4.1.
    TagDateTimeString uint64 = 0

    // TagEpochDateTime is CBOR tag 1: Epoch-based date/time.
    // Data item: integer or float.
    // Reference: RFC 8949 §3.4.2.
    TagEpochDateTime uint64 = 1

    // TagUnsignedBignum is CBOR tag 2: Unsigned bignum.
    // Data item: byte string.
    // Reference: RFC 8949 §3.4.3.
    TagUnsignedBignum uint64 = 2

    // TagNegativeBignum is CBOR tag 3: Negative bignum.
    // Data item: byte string.
    // Reference: RFC 8949 §3.4.3.
    TagNegativeBignum uint64 = 3

    // TagEncodedCBOR is CBOR tag 24: Encoded CBOR data item.
    // Data item: byte string.
    // Reference: RFC 8949 §3.4.5.1.
    TagEncodedCBOR uint64 = 24

    // TagSelfDescribe is CBOR tag 55799: Self-Described CBOR.
    // Data item: any.
    // Reference: RFC 8949 §3.4.6.
    TagSelfDescribe uint64 = 55799

    // ... (generated for all included tags)
)
```

### Lookup API (in the generated `registry` package)

```go
package registry

// TagInfo describes a registered CBOR tag.
type TagInfo struct {
    Tag       uint64
    DataItem  string // expected data item type
    Semantics string // human-readable description
    Reference string // RFC or specification reference
    Status    string // "standards-track", "specification-required", "private"
}

// LookupTag returns the registry entry for a tag number.
// Returns nil if the tag is not in the (possibly subset) registry.
func LookupTag(tag uint64) *TagInfo

// IsRegistered reports whether a tag number has a registry entry.
func IsRegistered(tag uint64) bool

// AllTags returns all tag entries in the registry, sorted by tag number.
func AllTags() []TagInfo

// SimpleValueInfo describes a registered CBOR simple value.
type SimpleValueInfo struct {
    Value     uint8
    Semantics string
    Reference string
}

// LookupSimpleValue returns the registry entry for a simple value.
func LookupSimpleValue(v uint8) *SimpleValueInfo
```

### Opt-in integration with corecbor

The generated `registry` package is **informational only** — it does
not change corecbor's encoding or decoding behavior.  It provides
constants and documentation for callers who want them:

```go
import (
    "github.com/jahkeup/corecbor"
    "github.com/jahkeup/corecbor/registry"
)

// Use registry constants for self-documenting code:
tag := corecbor.Tag{ID: registry.TagEpochDateTime, Inner: corecbor.Uint(1363896240)}

// Check if a decoded tag is registered:
if info := registry.LookupTag(decoded.ID); info != nil {
    fmt.Printf("Tag %d: %s (%s)\n", info.Tag, info.Semantics, info.Reference)
}
```

Callers who don't import `registry` pay nothing — it's a separate
package with no init-time cost to the core library.

### Periodic sync strategy

The cache is refreshed by:

1. **CI job** (recommended) — a scheduled GitHub Action runs
   `cbor-registry-gen -fetch` weekly, commits if changed, opens a PR.
   Human reviews the diff (new tags, changed semantics) before merge.

2. **Developer invocation** — `make registry-update` runs the fetch
   locally.  The diff is reviewable in git.

3. **Air-gapped** — no fetch; the checked-in `registry.json` is the
   source of truth.  Override file adds any needed entries.

The cache file is checked into the repo.  Generated code is also
checked in (not generated at build time) — this means consumers of
the package don't need the tool, and the generated code is auditable
in code review.

### COSE algorithms registry (optional flag)

When `-cose` is passed, the tool also fetches the IANA COSE Algorithms
registry and generates constants for the COSE module:

```go
package registry

// COSE Algorithm constants from IANA COSE Algorithms registry.
const (
    // COSEAlgEdDSA is COSE algorithm -8: EdDSA.
    // Reference: RFC 9053.
    COSEAlgEdDSA int64 = -8

    // COSEAlgES256 is COSE algorithm -7: ECDSA w/ SHA-256.
    // Reference: RFC 9053.
    COSEAlgES256 int64 = -7

    // ... (all registered algorithms)
)
```

This complements proposal 002's hand-maintained algorithm constants
with a machine-synchronized source of truth.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| `cbor-registry-gen -fetch` downloads IANA CBOR Tags registry successfully | Integration test (network, skipped in CI short mode) | Yes |
| Cached `registry.json` parses without error | `TestCacheParse` | Yes |
| Generated constants match cached data | `TestGeneratedMatchesCache`: parse generated Go, compare to JSON cache | Yes |
| Override file merges correctly (override wins on conflict) | `TestOverrideMerge` | Yes |
| Subset selection generates only requested tags | `TestSubsetGeneration`: config with 5 tags → output has exactly 5 constants | Yes |
| Generated code compiles | `go build ./registry/` after generation | Yes |
| `LookupTag` returns correct info for known tags | `TestLookupTag` | Yes |
| `LookupTag` returns nil for unknown tags | `TestLookupTag_Unknown` | Yes |
| `IsRegistered` matches `LookupTag != nil` | `TestIsRegistered` | Yes |
| Zero import cost for callers who don't use registry | Build corecbor without importing registry; assert no registry symbols in binary | Yes |
| Air-gapped mode works (no network, uses checked-in cache) | `TestAirGapped`: generate from cache file only, no -fetch | Yes |
| Generated godoc is well-formed | `go doc ./registry/` produces readable output | Yes |
| COSE algorithms generation (with -cose flag) | `TestCOSEAlgorithms`: generated constants match IANA COSE registry | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | Fetcher + cache format + basic generator (CBOR tags only) + subset selection | Pending | `cbor-registry-gen -fetch -out ./registry/` produces compilable Go |
| B | Override file support + Lookup API + air-gapped mode | Pending | Override merges correctly; LookupTag works |
| C | COSE algorithms registry + CI periodic sync job | Pending | `-cose` flag generates algorithm constants; CI action template provided |
| D | Makefile integration + documentation | Pending | `make registry-update` works; README documents workflow |

Phase A is independently useful — it provides the constants and godoc.

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestFetchIANA` | Network fetch (skipped in short mode) | `cmd/cbor-registry-gen/fetch_test.go` |
| `TestCacheParse` | JSON cache parsing | `cmd/cbor-registry-gen/cache_test.go` |
| `TestGenerate` | Code generation output | `cmd/cbor-registry-gen/generate_test.go` |
| `TestSubsetGeneration` | Subset filtering | `cmd/cbor-registry-gen/subset_test.go` |
| `TestOverrideMerge` | Override file merging | `cmd/cbor-registry-gen/override_test.go` |
| `TestLookupTag` | Lookup API correctness | `registry/registry_test.go` |
| `TestGeneratedMatchesCache` | Generated code ↔ cache consistency | `registry/registry_test.go` |

---

## Performance

Not performance-sensitive.  The generator runs offline; the lookup API
is a map lookup (O(1)).  The only constraint is binary size:

| Metric | Target | Test mechanism |
|---|---|---|
| Full registry package size (all ~60 tags) | ≤ 20 KiB in binary | `go build` + `go tool nm` size measurement |
| Subset registry (5 tags) | ≤ 2 KiB in binary | Same |
| Lookup latency | ≤ 50ns | `BenchmarkLookupTag` |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| IANA registry format changes (XML/CSV schema) | low | medium | Pin to known schema version; fetcher validates structure before caching |
| Registry adds tags that conflict with private ranges | low | low | Override file wins on conflict; document that private ranges should use first-come-first-served space (≥256) |
| Generated code becomes stale if CI sync is neglected | medium | low | The code works fine when stale — it just doesn't know about new tags. A stale-check reminder in `make check` can warn |
| Binary size bloat from importing full registry | medium | medium | Subset selection is the mitigation; document the opt-in pattern |
| Network dependency for fetch | low | low | Cache is checked in; air-gapped mode is first-class |

---

## Alternatives considered

### Generate at build time (go generate) instead of checking in

Rejected.  Checking in generated code means:
- Consumers don't need the tool.
- Code review catches unexpected registry changes.
- Air-gapped builds work without network.
- No `go generate` ordering issues.

The tradeoff is a larger repo (one JSON file + one Go file), which
is negligible.

### Embed the registry in the core corecbor package

Rejected.  Forces all corecbor consumers to carry registry data even
when they only need raw encode/decode.  Separate package = opt-in.

### Use build tags instead of a separate package for opt-in

Rejected.  Build tags are awkward for "I want this data available" —
they're better for platform-specific code.  A separate `registry/`
package with an explicit import is clearer and more Go-idiomatic.

### Support only CBOR tags (skip simple values and COSE algorithms)

Rejected as the full scope, but accepted as phasing.  Phase A is
CBOR tags only; Phase C adds COSE algorithms.  The infrastructure
(fetcher, cache, generator) is the same for all registries, so
expanding is cheap once the tool exists.

### Use the XML format directly instead of a JSON cache

Rejected.  IANA's XML schema is complex and ties the tool to their
specific format.  An intermediate JSON cache decouples the fetch
(which deals with IANA's format) from the generator (which reads a
simple, stable schema).  If IANA changes their format, only the
fetcher changes.

---

## Open questions

- **Generated package location**: Should the registry package live at
  `github.com/jahkeup/corecbor/registry` (importable by anyone) or
  `github.com/jahkeup/corecbor/internal/registry` (only usable within
  the corecbor tree)?  Lean: public — downstream consumers benefit
  from the constants and lookup API.

- **Registry versioning**: Should the generated package carry a
  version/timestamp so consumers can detect staleness?  Lean: yes,
  as a constant `RegistryFetchedAt` in the generated code.

- **Multiple output packages**: Should the tool support generating
  into multiple packages (e.g., `registry/tags`, `registry/cose`)
  or a single flat package?  Lean: single flat package for simplicity;
  split only if binary size becomes a problem with the full set.

- **go:embed for the JSON**: Should the registry package embed the
  JSON at runtime (for dynamic lookup) or compile constants only
  (for zero-runtime-cost)?  Lean: compile constants + a small lookup
  map.  `go:embed` of the JSON is a Phase B enhancement for callers
  who want full dynamic access to all fields (semantics, references).

---

## Cross-references

- IANA CBOR Tags registry:
  https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
- IANA CBOR Simple Values registry:
  https://www.iana.org/assignments/cbor-simple-values/
- IANA COSE Algorithms registry:
  https://www.iana.org/assignments/cose/cose.xhtml
- Sibling proposals: `001` (corecbor — tag handling), `002` (COSE —
  algorithm constants that this could machine-generate).
- RFCs: `../rfcs/rfc8949.txt` §9.2 (CBOR Tags registry rules),
  §9.1 (Simple Values registry rules).

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-20 | Initial draft | corecbor maintainers |
