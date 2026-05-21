# 015 — TinyGo latent support and performance profiling

## Header

| Field | Value |
|---|---|
| **Number** | 015 |
| **Tier** | 2 |
| **Status** | Draft |
| **Filed** | 2026-05-21 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001 (foundational primitives) |
| **Supersedes** | none |
| **Spec sections touched** | §9 (performance requirements — extended for constrained targets) |

---

## TL;DR

Ensure corecbor compiles and passes tests under TinyGo (targeting
WASM and ARM Cortex-M), establish a performance baseline on those
targets, and fix any compatibility issues that surface. "Latent
support" means TinyGo compatibility is maintained going forward via CI
gating, not that TinyGo becomes the primary development target.
Acceptance: `tinygo test ./...` passes for the root module and all
sub-modules on `wasm` and `thumbv7em` targets; benchmark numbers are
recorded and tracked.

---

## Motivation

CBOR (RFC 8949) is the wire format for constrained IoT protocols:
CoAP (RFC 7252), OSCORE (RFC 8613), EDHOC (RFC 9528), and SUIT
manifests (RFC 9019). These protocols run on microcontrollers and in
WASM edge functions where TinyGo is the dominant Go compiler.

Today corecbor makes no guarantees about TinyGo compatibility.
Accidental use of `reflect`, `encoding/binary` features unsupported by
TinyGo, or runtime assumptions (e.g., `runtime.GC` semantics) could
silently break constrained consumers. Proactive testing surfaces these
gaps before they become downstream blockers.

Secondary motivation: binary size. A CBOR codec on a Cortex-M4 with
256 KiB flash cannot afford megabyte binaries. Profiling under TinyGo
reveals which code paths pull in oversized dependencies (fmt, reflect,
etc.) so they can be guarded or refactored.

---

## Proposal

### Phase 1 — Compilation and test pass

1. Add a CI job (or local Makefile target) that runs:
   ```bash
   tinygo test -target=wasm ./...
   tinygo test -target=thumbv7em-none-eabi ./...
   ```
   for the root module. Sub-modules (`cose/`, `cwt/`, `eat/`, `edhoc/`)
   are tested on `wasm` only (crypto on bare-metal requires separate
   consideration).

2. Fix any compilation failures:
   - Replace unsupported stdlib usage with build-tag-guarded alternatives.
   - Gate `reflect`-heavy paths (e.g., `reflect_encode.go`,
     `reflect_decode.go`) behind `//go:build !tinygo` if they use
     features TinyGo doesn't support, and provide stub implementations
     that return a clear error.

3. Add `//go:build tinygo` constraint files only where strictly
   necessary — prefer fixing the code to work on both compilers.

### Phase 2 — Performance profiling

1. Record TinyGo benchmark baselines for the four core benchmarks
   (`BenchmarkEncodeScalars`, `BenchmarkEncodeNestedMap`,
   `BenchmarkDecodeScalars`, `BenchmarkDecodeNestedMapStrict`) on the
   `wasm` target using `tinygo test -bench`.

2. Record binary size for a minimal encode-decode program:
   ```go
   package main
   import "github.com/jahkeup/corecbor"
   func main() {
       enc := corecbor.New(corecbor.ModeCoreDeterministic)
       buf, _ := enc.Encode(nil, corecbor.Uint(42))
       dec := corecbor.NewDecoder()
       dec.Decode(buf)
   }
   ```
   Built with `tinygo build -target=wasm -no-debug -o out.wasm`.

3. Identify and document the top binary-size contributors via
   `tinygo build -print-allocs=. ...` and symbol-size analysis.

### Phase 3 — CI gating and regression tracking

1. Add a `tinygo` Makefile target:
   ```makefile
   .PHONY: tinygo
   tinygo: ## compile + test under TinyGo (wasm target)
   	tinygo test -target=wasm ./...
   ```

2. Gate CI on `make tinygo` so regressions are caught before merge.

3. Optionally track binary size in CI and fail if it regresses beyond
   a threshold (e.g., +10 KiB).

### Behavior

No public API change. Callers using standard `go build` see no
difference. Callers using `tinygo build` get a library that compiles
and passes tests. The reflective marshal/unmarshal layer may be
unavailable under TinyGo (returns `ErrUnsupported`) if TinyGo's
reflect support is insufficient.

### Failure modes

| Scenario | Behavior |
|---|---|
| Caller uses `Marshal`/`Unmarshal` under TinyGo | Returns `ErrUnsupported` with explanation (if gated) |
| TinyGo lacks a required stdlib package | Build fails in CI, caught before release |

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| `tinygo test -target=wasm ./...` passes (root module) | CI job | Yes |
| `tinygo test -target=wasm ./...` passes (cose, cwt sub-modules) | CI job | Yes |
| Binary size of minimal program ≤ 150 KiB (wasm, no-debug) | `tinygo build` + `wc -c` | Yes |
| Core benchmarks run and produce numbers under TinyGo/wasm | `tinygo test -bench` output recorded | No (informational) |
| No `//go:build !tinygo` files unless justified in PR description | Code review | Yes |

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| CI: `tinygo test -target=wasm ./...` | Full test suite under TinyGo | `.github/workflows/ci.yml` |
| `make tinygo` | Local developer verification | `Makefile` |
| Binary size check | Ensures no bloat regression | CI script or Makefile target |

No new fuzz targets — TinyGo doesn't support `testing.F`.

---

## Performance

| Metric | Target | Test mechanism |
|---|---|---|
| EncodeScalars (wasm/TinyGo) | ≥ 100 MB/s (informational, no gate) | `tinygo test -bench BenchmarkEncodeScalars` |
| DecodeScalars (wasm/TinyGo) | ≥ 80 MB/s (informational, no gate) | `tinygo test -bench BenchmarkDecodeScalars` |
| Binary size (minimal, wasm) | ≤ 150 KiB | `tinygo build -no-debug -target=wasm` |
| Binary size (with cose, wasm) | ≤ 300 KiB (informational) | Same |

TinyGo performance targets are informational baselines, not gating.
The §9 targets remain authoritative for standard Go only.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| TinyGo's reflect support is too limited for marshal/unmarshal | High | Med — those paths are opt-in | Gate behind build tag; core encode/decode doesn't use reflect |
| TinyGo's crypto/ecdsa or crypto/ed25519 are incomplete | Med | Med — blocks cose/edhoc sub-modules | Test on wasm only (which has fuller crypto); bare-metal deferred |
| TinyGo compiler bugs cause spurious test failures | Low | Low — flaky CI | Pin TinyGo version in CI; skip known-broken tests with `//go:build` |
| Maintaining TinyGo compat adds friction to future development | Med | Low — build tag surface is small | Minimize `!tinygo` files; fix code to be dual-compiler by default |

---

## Alternatives considered

**1. WASI-only (no bare-metal)**

Test only `wasip1`/`wasip2` targets. Simpler — WASI has more stdlib
coverage. Rejected because the primary constrained use case (IoT
devices running EDHOC/OSCORE) needs bare-metal ARM, and testing only
WASM would miss those gaps. Compromise: gate bare-metal on Phase 1
success; defer `thumbv7em` to post-WASM-green.

**2. Separate `corecbor-tiny` module**

Fork the core into a stripped-down module that imports no problematic
packages. Rejected because it creates maintenance divergence. The
better path is ensuring the main module compiles cleanly — it's
already allocation-conscious and avoids heavy dependencies.

**3. Do nothing, let downstream consumers file bugs**

Reactive approach. Rejected because CBOR's primary use case *is*
constrained environments — if we break TinyGo users silently, we
fail the library's core audience.

---

## Open questions

1. **Which TinyGo version to pin?** The latest stable (0.34.x as of
   filing) or track latest? Pinning avoids churn; tracking latest
   catches regressions in both directions.

2. **Should the `eat/` and `edhoc/` modules gate on TinyGo?** They
   pull in `golang.org/x/crypto` which may have TinyGo gaps.
   Conservative: start with root + cose + cwt; add others later.

3. **WASM runtime for benchmarks?** Wasmtime, wazero, or browser V8?
   Affects absolute numbers. Proposal: standardize on wasmtime for
   reproducibility.

---

## Cross-references

- Spec: §9 of `encoder-decoder-spec.md` (performance requirements)
- TinyGo supported packages: https://tinygo.org/docs/reference/lang-support/stdlib/
- RFC 8949 — CBOR
- RFC 7252 — CoAP (constrained application protocol)
- RFC 9528 — EDHOC
- Proposal 001 — foundational primitives (dependency)
- Proposal 008 — reflective marshal/unmarshal (affected by reflect gating)

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-21 | Initial draft | corecbor maintainers |
