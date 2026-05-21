# corecbor

A strict-RFC-conformant CBOR encoder plus a forgiving CBOR decoder, with
the same primitives serving both storage / cryptographic-AAD use cases
and wire-protocol implementation use cases.

**Status:** Skeleton. No implementation yet. Phase 1 (foundational
primitives) is the first work; see
[`engineering-docs/proposals/001-phase-1-foundational-primitives.md`](engineering-docs/proposals/001-phase-1-foundational-primitives.md).

## Documentation

The contract, design, and process all live under
[`engineering-docs/`](engineering-docs/):

- [`encoder-decoder-spec.md`](engineering-docs/encoder-decoder-spec.md) —
  tier-1 spec (encoder modes, decoder strictness, value model, error
  catalog, fuzz targets, performance targets, phased roadmap).
- [`engineering-docs/README.md`](engineering-docs/README.md) — proposal-
  driven development discipline (tiers, lifecycle, velocity rules,
  citation conventions).
- [`engineering-docs/proposals/`](engineering-docs/proposals/) — in-flight
  and historical proposals.
- [`engineering-docs/rfcs/`](engineering-docs/rfcs/) — vendored RFC text
  for offline citation (RFC 8949 CBOR, RFC 8742 sequences, RFC 9562
  UUID, RFC 7049 legacy CBOR, RFC 9052 COSE).

## Repository layout

```
.
├── README.md                     — this file
├── LICENSE
├── go.mod / go.sum
├── Makefile                      — fmt / lint / test / bench / fuzz / check
├── .golangci.yml                 — lint config (default linter set + gofumpt)
├── .github/workflows/ci.yml      — gate on `make check` + `make fuzz` (60s)
├── doc.go                        — package-level godoc
├── engineering-docs/             — see "Documentation" above
└── (encode.go, decode.go, value.go, errors.go, ... — added during Phase 1)
```

## Build

```bash
make help           # list available targets
make check          # fmt-check + vet + lint + test (CI gate)
make fuzz           # run every Fuzz* target for FUZZTIME (default 30s)
make bench          # all benchmarks
```

`gofumpt` ships as a Go tool (`go get -tool` already wired in `go.mod`).
`golangci-lint` is opportunistic in invocation but strict in findings:
when it's on PATH, it gates; when it isn't, `make lint` skips with a
hint. CI installs it; developer machines may skip.

## License

See `LICENSE`. (TODO: pick one before any release.)
