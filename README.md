# corecbor

> **Note:** This project was developed with the assistance of AI/LLM tools,
> with the relevant IETF RFCs as primary reference material throughout.
> All design decisions, code, and tests were validated against the
> specifications directly.

A strict-RFC-conformant CBOR encoder plus a forgiving CBOR decoder, with
the same primitives serving both storage / cryptographic-AAD use cases
and wire-protocol implementation use cases.

**Status:** Pre-1.0, active development. Core codec (encode, decode,
streaming, deterministic modes), COSE signing/encryption, CWT, EAT,
EDHOC and SCITT sub-modules are implemented. See closed proposals under
[`engineering-docs/proposals/`](engineering-docs/proposals/) for history.

## Install

Each directory below is its own Go module, versioned together
(`v0.3.0`, `cose/v0.3.0`, …):

```sh
go get github.com/jahkeup/corecbor@v0.3.0         # CBOR codec
go get github.com/jahkeup/corecbor/cose@v0.3.0    # COSE (RFC 9052/9053)
go get github.com/jahkeup/corecbor/cwt@v0.3.0     # CWT (RFC 8392)
go get github.com/jahkeup/corecbor/eat@v0.3.0     # EAT (RFC 9711)
go get github.com/jahkeup/corecbor/edhoc@v0.3.0   # EDHOC (RFC 9528)
go get github.com/jahkeup/corecbor/scitt@v0.3.0   # SCITT signed statements
```

Upgrading from v0.2: read
[`migration-v0.2-to-v0.3.md`](engineering-docs/migration-v0.2-to-v0.3.md).
Defaults follow the current RFCs; each changed default has a selector
for the previous behavior, deprecated and kept until at least v0.5.0.

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
├── LICENSE                       — Apache-2.0
├── go.mod / go.sum
├── Makefile                      — fmt / lint / test / bench / fuzz / check
├── .golangci.yml                 — lint config (golangci-lint v2 + gofumpt)
├── .github/workflows/ci.yml      — gate on `make check` + `make fuzz` (60s)
├── *.go                          — core codec (encoder, decoder, streaming, marshal, diagnostic)
├── cbor/                         — shared value types and helpers
├── wire/                         — low-level wire format (heads, float16)
├── rfc8949/                      — RFC 8949 encode/decode internals
├── registry/                     — IANA CBOR tag registry (codegen'd)
├── cose/                         — COSE sign/encrypt/MAC (RFC 9052, separate module)
├── cwt/                          — CWT claims + validation (RFC 8392, separate module)
├── eat/                          — EAT entity attestation (RFC 9711, separate module)
├── edhoc/                        — EDHOC key exchange (RFC 9528, separate module)
├── cmd/                          — CLI tools (cbor-diag, cbor-registry-gen)
├── tools/                        — pinned dev tools module (golangci-lint)
├── testdata/                     — fuzz corpora + compatibility fixtures
└── engineering-docs/             — see "Documentation" above
```

## Build

```bash
make help           # list available targets
make check          # fmt-check + vet + lint + test (CI gate)
make fuzz           # run every Fuzz* target for FUZZTIME (default 30s)
make bench          # all benchmarks
```

Both linters ship as Go tools, so `make check` needs nothing beyond a Go
toolchain:

- `gofumpt` is wired into the root `go.mod` (`go tool gofumpt`).
- `golangci-lint` is pinned in a separate `tools/go.mod` so its large
  dependency graph stays out of the library's module graph. Run it
  directly with `go tool -modfile=tools/go.mod golangci-lint run ./...`;
  bump it with `go get -modfile=tools/go.mod -tool
  github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`.

CI and local runs use the same pinned version.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
