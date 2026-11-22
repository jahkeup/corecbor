# 036 — Deferred follow-ups from the 2026-11 batch

## Header

| Field | Value |
|---|---|
| **Number** | 036 |
| **Tier** | 2 |
| **Status** | In-Progress |
| **Filed** | 2026-11-22 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 018, 021–035 |
| **Supersedes** | none |
| **Spec sections touched** | none until an item is picked up |

---

## TL;DR

Proposals 020–035 closed with their gating criteria met. This proposal
collects the non-gating items they deferred, so they stay visible
instead of being buried in closed documents. Each item is picked up by
its own proposal (or a phase here) when its trigger happens; until then
none blocks a release.

## Items

| # | Item | From | Trigger | Notes |
|---|---|---|---|---|
| 1 | Strict decode of maps with >16 entries is ~15% slower (`DecodeStrictLargeMap100/1000`), `DecodeNestedMapStrict` ~5% | 024 (accepted trade-off) | perf work | Per-key cost in the strict hashed path (`find`/`mapInsert`, `DecodeOpts` size) |
| 2 | `RawMessage` struct decode +3–4% vs pre-025 main | 022, 025 | perf work | Decoder-recorded item offsets would remove the span walk |
| 3 | ~~Sibling modules adopt `Value.Int64`/`Uint64`/`Get*`~~ **Done (cwt, eat) 2026-11-22** | 025 Phase C | — | Every integer narrowing site in cwt/eat was already range-checked by 031/032 (no wrapping left), so adoption is behavior-identical: `claimKeyOf`, `fromValue`, `parseNumericDate`, ACE `exi`, eat `intKey`/`parseUintClaim`, `psa.intOf` now use `Int64`/`Uint64`; boundary tests added; no golden changes. Map loops dispatch every entry, so `Get*` doesn't apply. cose/edhoc sites not in scope here |
| 4 | RFC 8746 typed arrays | 026 Phase D | consumer request | — |
| 5 | Concise Diagnostic Notation alignment | 026 Phase E | draft-ietf-cbor-edn-literals publishes | `DiagCDN()` reserved |
| 6 | Ed448 / X448 sign, verify and ECDH | 028, 029, 033 | standard library support | Parse/marshal only today; EDHOC suite 25 and HPKE-5/6 blocked on it |
| 7 | `BenchmarkParseKeyEC2` 20 allocs vs target 10 | 028 | perf work | About half is the required on-curve check |
| 8 | mDL issuer-auth interop vector | 028 | vector with a confirmed license | Non-gating |
| 9 | `cose.NewKeyFromPublic` accepting `*ecdh.PublicKey` (X25519) | 033 follow-ups | — | edhoc keeps a small local builder |
| 10 | RFC 10013 measured component helpers | 032 Phase D | consumer request | `Measurements` carried as typed bytes today |
| 11 | HPKE code points final; drop `Draft…`/Experimental | 029 | draft-ietf-cose-hpke publishes with IANA values | 034 lifecycle |
| 12 | Serialization profile identifiers final | 024 | draft-ietf-cbor-serialization publishes | 034 lifecycle |
| 13 | Report draft-ietf-cose-hpke-27 key-encryption vectors using 16-byte AES-GCM IVs (RFC 9053 requires 96-bit) | 029 | — | Upstream erratum/issue |
| 14 | Add `scitt` to `apicheck` | 030 | after the first release that contains `scitt` | No v0.2.2 baseline exists |
| 15 | Inline EAT submodules keep original bytes; JSON submods | 032 | consumer request | Re-encoded deterministically today |
| 16 | `TestMarshalerVerbatimPermissive`-style splice for non-raw Marshalers in Permissive mode | 022 | consumer request | Raw types only today |
| 17 | Benchmark coverage: every decode/encode path the default options exercise (forgiving maps were uncovered until 2026-11-22) | release check | — | `BenchmarkDecodeItemMapForgiving` added; audit for other gaps |
| 18 | String interning (`WithStringIntern`) has no tests or benchmark | 018 | next perf pass | Add correctness tests and `BenchmarkDecodeRepeatedKeysIntern` (target: steady-state 0 allocs for repeated keys) |
| 19 | Arena-only nested-map decode: 10 allocs vs target ≤2 | 018 | perf work | 0 allocs with zero-copy + arena; the remaining allocs are text strings |
| 20 | `Cursor.FindMapKey` on a 50-key map: 2 allocs vs target ≤1 | 018 | perf work | `BenchmarkCursorFindMapKey` |

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-22 | Filed from the deferred items of 020–035 | corecbor maintainers |
| 2026-11-22 | Add items 18–20 from 018's closure | corecbor maintainers |
| 2026-11-22 | Status: In-Progress (streams for items 1–3, 7, 9, 17–20 started) | corecbor maintainers |
| 2026-11-22 | Item 3 done for cwt and eat (behavior-identical accessor adoption) | corecbor maintainers |
