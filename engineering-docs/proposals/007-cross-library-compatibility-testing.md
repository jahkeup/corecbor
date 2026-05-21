# 007 — Cross-library compatibility testing

## Header

| Field | Value |
|---|---|
| **Number** | 007 |
| **Tier** | 2 |
| **Status** | Accepted |
| **Filed** | 2026-05-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001 |
| **Supersedes** | none |
| **Spec sections touched** | none — informational only |

---

## TL;DR

Establish a compatibility test suite that exercises corecbor against
other CBOR libraries — both Go-native (fxamacker/cbor, ugorji/go) and
foreign (libcbor via cgo, and potentially others such as QCBOR, cn-cbor,
tinycbor).  The suite confirms that corecbor's specified and implemented
functionality produces wire-compatible output and correctly consumes
input from peer libraries.  Where corecbor supports capabilities beyond
what earlier-RFC libraries implement (e.g., RFC 8949 features absent
from RFC 7049-era libraries for specific use cases), those cases are not
treated as failures but are recorded in a periodically refreshed
compatibility matrix documenting what is known to work across the
libraries and clients available for use.

---

## Motivation

A CBOR library is only useful if it interoperates.  corecbor targets
strict RFC 8949 conformance, but that means nothing in isolation — the
wire bytes must be consumable by peer implementations, and corecbor must
correctly consume theirs.

Concrete gaps this addresses:

1. **Silent incompatibilities** — subtle encoding choices (indefinite
   length vs definite, canonical ordering, tag nesting) that are
   technically valid per the RFC but trip up parsers with less coverage.
   These only surface when you actually cross-test.

2. **Regression detection** — a change to corecbor's encoder that is
   spec-compliant might break a downstream consumer that relies on a
   specific byte pattern.  Cross-library tests catch this before release.

3. **Consumer confidence** — users choosing a CBOR library want evidence
   of interop, not just RFC-section citations.  A published compatibility
   matrix answers "will this work with my existing system?"

4. **Superset feature documentation** — corecbor may implement RFC 8949
   features (deterministic encoding §4.2, preferred serialization §4.1,
   tag 24 encoded CBOR §3.4.5.1, etc.) that RFC 7049-era libraries do
   not handle.  These are not bugs — they are recorded capability
   differences that inform adopters about what is portable and what is
   corecbor-specific for a given use case.

### Why "greater capability" is not a failure

When corecbor implements a feature specified in RFC 8949 that a peer
library does not support (because it targets RFC 7049, or simply hasn't
implemented that section), the compatibility test must not fail.  The
correct behavior is:

- **Record** the capability gap in the matrix.
- **Classify** it: "corecbor produces valid output that library X cannot
  consume for this specific use case."
- **Skip** or **expect-fail** the test vector for that library, with a
  clear annotation.
- **Periodically re-check** — libraries evolve; what was unsupported in
  v2.3 may land in v2.4.

This ensures the matrix is a living document of cross-library reality,
not a lowest-common-denominator constraint on corecbor's feature set.

---

## Proposal

### Target libraries

#### Go-native (pure Go, in-process)

| Library | Import path | RFC target | Notes |
|---|---|---|---|
| fxamacker/cbor | `github.com/fxamacker/cbor/v2` | RFC 8949 | Most widely used Go CBOR library; COSE/CWT aware |
| ugorji/go | `github.com/ugorji/go/codec` | RFC 7049+ | Multi-codec; CBOR is one mode |

#### Foreign (via cgo or subprocess)

| Library | Language | Integration | Notes |
|---|---|---|---|
| libcbor | C | cgo bindings | Reference C implementation; broad coverage |
| QCBOR | C | cgo bindings | Qualcomm; optimized for constrained devices; strict |
| cn-cbor | C | cgo bindings | Minimal C implementation; good baseline |
| tinycbor | C | cgo bindings | Intel; embedded-focused; limited tag support |

#### Future candidates (not in initial scope)

- cbor-ruby, cbor-python (subprocess with stdin/stdout exchange)
- cbor-diag (Ruby; useful as a diagnostic reference)
- libcbor-rs (Rust; via cgo or subprocess)

### Test architecture

```
github.com/jahkeup/corecbor/
├── compat/                          # Compatibility test module (separate go.mod)
│   ├── go.mod                       # Dependencies on peer libraries
│   ├── go.sum
│   ├── doc.go
│   ├── vectors/                     # Shared test vectors (CBOR bytes + expected values)
│   │   ├── roundtrip.json           # Encode/decode round-trip vectors
│   │   ├── edge_cases.json          # Boundary conditions, large values
│   │   ├── rfc8949_appendix_a.json  # RFC 8949 Appendix A diagnostic examples
│   │   └── extended_features.json   # Features beyond RFC 7049 baseline
│   ├── matrix/                      # Matrix output (generated)
│   │   └── compatibility.json       # Machine-readable results
│   ├── corecbor_test.go             # corecbor encode/decode of all vectors
│   ├── fxamacker_test.go            # fxamacker/cbor encode/decode
│   ├── ugorji_test.go              # ugorji/go codec encode/decode
│   ├── cgo_libcbor_test.go          # libcbor via cgo
│   ├── cgo_qcbor_test.go           # QCBOR via cgo
│   ├── cross_test.go               # Cross-library: A encodes → B decodes
│   ├── matrix_test.go              # Generates the compatibility matrix
│   └── testutil/                    # Shared harness code
│       ├── harness.go              # Library abstraction interface
│       ├── vectors.go              # Vector loading/parsing
│       └── matrix.go              # Matrix generation logic
```

### Library abstraction

Each library implements a common interface for the test harness:

```go
package testutil

// Library represents a CBOR library under test.
type Library interface {
    // Name returns the library identifier for matrix reporting.
    Name() string

    // Version returns the library version string.
    Version() string

    // RFCTarget returns the primary RFC the library targets ("7049", "8949").
    RFCTarget() string

    // Encode serializes a test value to CBOR bytes.
    // Returns ErrUnsupported if the library cannot represent the value.
    Encode(v TestValue) ([]byte, error)

    // Decode deserializes CBOR bytes into a test value.
    // Returns ErrUnsupported if the library cannot interpret the encoding.
    Decode(data []byte) (TestValue, error)

    // Capabilities reports which optional features the library supports.
    Capabilities() CapabilitySet
}

// CapabilitySet describes what a library can do.
type CapabilitySet struct {
    DeterministicEncoding bool
    PreferredSerialization bool
    IndefiniteLength      bool
    TagSupport            TagCapability
    MapKeyOrdering        bool
    BigNumbers            bool
    // ... extended as the matrix grows
}

type TagCapability struct {
    MaxTag     uint64   // highest tag number supported
    KnownTags  []uint64 // explicitly handled tags
}

// ErrUnsupported indicates a library cannot handle a specific feature.
// This is NOT a test failure — it's a matrix data point.
var ErrUnsupported = errors.New("compat: unsupported by library")
```

### Test vector format

Vectors are JSON files describing CBOR values with their expected
wire encoding:

```json
{
  "vectors": [
    {
      "id": "uint-zero",
      "description": "Unsigned integer 0",
      "rfc_section": "3.1",
      "rfc_minimum": "7049",
      "value": {"type": "uint", "data": 0},
      "canonical_cbor_hex": "00",
      "category": "baseline"
    },
    {
      "id": "tag-datetime",
      "description": "Tag 0: date/time string",
      "rfc_section": "3.4.1",
      "rfc_minimum": "8949",
      "value": {"type": "tag", "tag": 0, "inner": {"type": "text", "data": "2013-03-21T20:04:00Z"}},
      "canonical_cbor_hex": "c074323031332d30332d32315432303a30343a30305a",
      "category": "extended"
    }
  ]
}
```

The `rfc_minimum` field drives the "greater capability" logic: if a
library targets RFC 7049 and the vector requires RFC 8949, a decode
failure is classified as a **known gap**, not a **test failure**.

### Cross-library test patterns

The core tests operate in three modes:

**Mode 1: Self round-trip** — each library encodes and decodes its own
output.  Validates internal consistency.

**Mode 2: Cross encode/decode** — library A encodes → library B decodes.
Every ordered pair (A, B) is tested for every vector.  This is the
primary interop signal.

**Mode 3: Canonical comparison** — for vectors with a known canonical
encoding, verify each library produces the expected bytes (or a valid
alternative encoding if non-deterministic).

```go
func TestCrossCompatibility(t *testing.T) {
    libraries := []testutil.Library{
        newCorecborLib(),
        newFxamackerLib(),
        newUgorjiLib(),
        newLibcborLib(),
    }
    vectors := testutil.LoadVectors(t, "vectors/roundtrip.json")

    for _, v := range vectors {
        for _, encoder := range libraries {
            encoded, err := encoder.Encode(v.Value)
            if errors.Is(err, testutil.ErrUnsupported) {
                recordGap(encoder, v, "encode-unsupported")
                continue
            }
            require.NoError(t, err, "%s failed to encode %s", encoder.Name(), v.ID)

            for _, decoder := range libraries {
                decoded, err := decoder.Decode(encoded)
                if errors.Is(err, testutil.ErrUnsupported) {
                    recordGap(decoder, v, "decode-unsupported")
                    continue
                }
                if err != nil && v.RFCMinimum > decoder.RFCTarget() {
                    // Greater capability: corecbor encodes a feature
                    // the decoder doesn't support. Record, don't fail.
                    recordCapabilityGap(encoder, decoder, v, err)
                    continue
                }
                require.NoError(t, err,
                    "%s→%s failed on %s", encoder.Name(), decoder.Name(), v.ID)
                assertValuesEqual(t, v.Value, decoded,
                    "%s→%s value mismatch on %s", encoder.Name(), decoder.Name(), v.ID)
            }
        }
    }
}
```

### Compatibility matrix

The test suite produces a machine-readable matrix after each run:

```json
{
  "generated_at": "2026-05-20T15:00:00Z",
  "corecbor_version": "v0.1.0",
  "libraries": [
    {"name": "corecbor", "version": "v0.1.0", "rfc": "8949"},
    {"name": "fxamacker/cbor", "version": "v2.7.0", "rfc": "8949"},
    {"name": "ugorji/go", "version": "v1.2.12", "rfc": "7049"},
    {"name": "libcbor", "version": "0.11.0", "rfc": "8949"}
  ],
  "results": {
    "corecbor→fxamacker/cbor": {
      "pass": 142,
      "fail": 0,
      "unsupported": 3,
      "capability_gap": 0
    },
    "corecbor→ugorji/go": {
      "pass": 128,
      "fail": 0,
      "unsupported": 8,
      "capability_gap": 6
    },
    "corecbor→libcbor": {
      "pass": 140,
      "fail": 0,
      "unsupported": 5,
      "capability_gap": 0
    }
  },
  "capability_gaps": [
    {
      "encoder": "corecbor",
      "decoder": "ugorji/go",
      "vector": "deterministic-map-ordering",
      "reason": "ugorji/go does not enforce deterministic map key ordering on decode",
      "rfc_section": "4.2",
      "classification": "rfc8949-feature-not-in-7049"
    }
  ]
}
```

### Periodic refresh

The matrix is refreshed on a schedule to track library evolution:

1. **CI (weekly or on release)** — a GitHub Action runs the full
   compatibility suite against pinned versions of peer libraries.
   The resulting `compatibility.json` is committed if changed.

2. **Dependency bumps** — when `compat/go.mod` updates a peer library
   version, CI re-runs the suite.  Capability gaps that resolve (the
   peer library added support) are automatically promoted from
   "capability_gap" to "pass."

3. **Published matrix** — a rendered Markdown table (generated from
   the JSON) can be included in project documentation or a GitHub
   wiki page, giving adopters a current view of interop status.

4. **Alerting on regressions** — if a vector that previously passed
   begins failing after a corecbor change, CI blocks the PR.  This
   is distinct from a capability gap (which is expected and stable).

### cgo integration for foreign libraries

Foreign C libraries are wrapped with minimal cgo shims:

```go
// +build cgo

package compat

/*
#cgo LDFLAGS: -lcbor
#include <cbor.h>
#include <stdlib.h>
*/
import "C"

type libcborLib struct{}

func (l *libcborLib) Name() string      { return "libcbor" }
func (l *libcborLib) Version() string   { return C.GoString(C.cbor_version_string()) }
func (l *libcborLib) RFCTarget() string { return "8949" }

func (l *libcborLib) Encode(v testutil.TestValue) ([]byte, error) {
    // Minimal cgo encode shim — convert TestValue → cbor_item_t → bytes
    // ...
}

func (l *libcborLib) Decode(data []byte) (testutil.TestValue, error) {
    // Minimal cgo decode shim — bytes → cbor_item_t → TestValue
    // ...
}
```

cgo tests are gated behind a build tag (`//go:build compat_cgo`) so
the standard `go test ./...` does not require C library installation.
CI runs the cgo tests in a dedicated job with the libraries installed.

### Separate module rationale

The `compat/` directory is a separate Go module (`go.mod`) to avoid
polluting corecbor's dependency tree with peer libraries.  Consumers
of corecbor never transitively depend on fxamacker/cbor or ugorji/go.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| corecbor round-trips all RFC 8949 Appendix A vectors | `TestSelfRoundTrip_Corecbor` | Yes |
| fxamacker/cbor successfully decodes all baseline corecbor output | `TestCross_Corecbor_Fxamacker` passes on "baseline" category | Yes |
| libcbor (via cgo) successfully decodes all baseline corecbor output | `TestCross_Corecbor_Libcbor` passes on "baseline" category | Yes |
| Capability gaps are recorded, not failures | Extended-feature vectors with RFC 8949 minimum produce `capability_gap` entries, not test failures, when peer library targets RFC 7049 | Yes |
| Matrix JSON is generated and valid | `TestMatrixGeneration` produces parseable `compatibility.json` | Yes |
| Peer library encode → corecbor decode succeeds for baseline vectors | `TestCross_Fxamacker_Corecbor`, `TestCross_Libcbor_Corecbor` | Yes |
| cgo tests skippable without C deps | `go test ./compat/...` without cgo tag skips C library tests cleanly | Yes |
| No corecbor dependency pollution | `go mod graph` from corecbor root shows no peer library dependencies | Yes |
| CI generates updated matrix on peer library bumps | GitHub Action workflow exists and produces committed matrix diff | No (process criterion) |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | Test vector suite + corecbor self round-trip + harness interface | Pending | Vectors cover RFC 8949 Appendix A; corecbor passes self round-trip |
| 2 | Go-native cross-tests (fxamacker, ugorji) + matrix generation | Pending | Cross-tests run; matrix JSON produced with pass/gap classification |
| 3 | cgo integration (libcbor, QCBOR) + build-tag gating | Pending | cgo tests pass in dedicated CI job; skippable otherwise |
| 4 | CI periodic refresh + published matrix + alerting | Pending | Weekly CI produces updated matrix; regressions block PRs |

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestSelfRoundTrip_*` | Each library encodes→decodes its own output | `compat/*_test.go` |
| `TestCrossCompatibility` | All (encoder, decoder) pairs over all vectors | `compat/cross_test.go` |
| `TestCapabilityGapClassification` | Gaps recorded correctly, not as failures | `compat/cross_test.go` |
| `TestMatrixGeneration` | JSON matrix output is valid and complete | `compat/matrix_test.go` |
| `TestVectorParsing` | Test vector JSON loads correctly | `compat/testutil/vectors_test.go` |
| `TestCgoLibcbor` | libcbor cgo shim works | `compat/cgo_libcbor_test.go` |

---

## Performance

Not performance-sensitive — the compatibility suite is a CI/offline
artifact, not a hot path.  The only operational constraint is CI time:

| Metric | Target | Test mechanism |
|---|---|---|
| Full Go-native suite runtime | ≤ 30s | `go test -v -count=1 ./compat/...` (no cgo) |
| Full suite including cgo | ≤ 120s | CI job with C libraries installed |
| Matrix generation | ≤ 5s | `TestMatrixGeneration` |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Peer library API changes break compat shims | medium | low | Pin versions in `compat/go.mod`; update on schedule, not reactively |
| cgo complexity (build environments, cross-platform) | medium | medium | cgo tests are opt-in via build tag; CI uses a controlled container image |
| False confidence from passing matrix | low | medium | Matrix reports what's tested, not "all CBOR works" — document scope clearly |
| Maintenance burden of vector suite | medium | low | Vectors are additive; RFC Appendix A provides a stable baseline; extended vectors added per-feature |
| C library installation varies across platforms | medium | low | Provide a Dockerfile / Nix flake for reproducible cgo test environment |
| Peer libraries have bugs that look like our incompatibility | low | medium | Classify as "peer-library-bug" in matrix; link to upstream issue; retest on their fix |

---

## Alternatives considered

### Test only against one peer library

Rejected.  A single peer gives false confidence — different libraries
make different implementation choices.  At minimum, one Go-native and
one C library covers the most common integration patterns (in-process Go
consumer vs. C/C++/embedded consumer reading corecbor's wire output).

### Use subprocess IPC instead of cgo for C libraries

Considered but deferred.  Subprocess (pipe CBOR bytes to a C test
harness binary) avoids cgo complexity but adds process-management code
and makes debugging harder.  cgo gives direct, in-process encode/decode
calls.  Subprocess may be revisited for Rust or Python libraries where
cgo isn't natural.

### Make the compatibility suite part of the main module

Rejected.  Importing peer libraries into corecbor's `go.mod` would
force all corecbor consumers to download those dependencies.  A separate
`compat/` module isolates the dependency graph.

### Fail on any decode error regardless of RFC level

Rejected.  This would constrain corecbor to the lowest common
denominator of all tested libraries.  The entire point of targeting
RFC 8949 is to support features that older libraries may not — those
differences are informational, not regressions.

### Publish only a static matrix (no CI refresh)

Rejected.  A stale matrix is misleading.  Peer libraries evolve; the
matrix must reflect current reality.  CI refresh is the mechanism that
keeps it honest.

---

## Open questions

- **Minimum peer library set for Phase 2**: Is fxamacker/cbor +
  ugorji/go sufficient for the Go-native phase, or should
  `github.com/pion/cbor` or other niche libraries be included?
  Lean: start with fxamacker + ugorji; expand based on user demand.

- **Vector provenance**: Should we adopt the cbor-test-vectors
  community set (https://github.com/cbor/test-vectors) as a baseline,
  or maintain our own?  Lean: adopt the community set as a baseline,
  augment with corecbor-specific extended vectors.

- **Matrix rendering**: Where does the human-readable matrix live?
  Options: repo README, GitHub wiki, dedicated `COMPATIBILITY.md`,
  or auto-published GitHub Pages.  Lean: `compat/COMPATIBILITY.md`
  generated alongside the JSON.

- **Threshold for "regression"**: If corecbor changes encoding in a
  spec-compliant way but a peer library's decode breaks, is that a
  corecbor regression or a peer-library gap?  Lean: if the peer
  library previously decoded it, it's a corecbor regression (we broke
  real-world interop); if the peer never supported it, it's a gap.

---

## Cross-references

- RFC 8949 Appendix A: diagnostic examples (primary vector source)
- RFC 7049: legacy CBOR (defines the "baseline" feature set)
- `encoder-decoder-spec.md` §4 (tag handling), §2 (encoding modes)
- Proposal 001 (foundational primitives — the implementation to test)
- cbor/test-vectors: https://github.com/cbor/test-vectors
- fxamacker/cbor: https://github.com/fxamacker/cbor
- libcbor: https://github.com/PJK/libcbor
- QCBOR: https://github.com/laurencelundblade/QCBOR
- tinycbor: https://github.com/niclas-iiot/tinycbor

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-20 | Initial draft | corecbor maintainers |
