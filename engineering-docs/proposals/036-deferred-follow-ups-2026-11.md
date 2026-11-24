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
| 1 | Strict decode of maps with >16 entries is ~15% slower (`DecodeStrictLargeMap100/1000`), `DecodeNestedMapStrict` ~5% — **partly recovered 2026-11-22**: strict 100/1000-entry maps −7%/−10% and half the allocations; ~5% of the original gap remains | 024 (accepted trade-off) | perf work | See *Results*. Duplicate tracking now chains entries per hash instead of a slice per hash. `DecodeOpts` is 96 bytes vs v0.2.2's 88: its exported fields can't be reordered or moved behind a pointer under 034, so the size target is dropped |
| 2 | `RawMessage` struct decode +3–4% vs pre-025 main — **measured, deferred 2026-11-22** | 022, 025 | perf work | The span walk (`Cursor.RawBytes`) is ~2.6% of the profile. Decoder-recorded offsets need a module-internal channel into `rfc8949`'s unexported span recorder and trade the walk for per-entry recording, so the expected gain is below run-to-run noise (±5–10%). One alloc removed in passing (23 → 22) |
| 3 | ~~Sibling modules adopt `Value.Int64`/`Uint64`/`Get*`~~ **Done (cwt, eat) 2026-11-22** | 025 Phase C | — | Every integer narrowing site in cwt/eat was already range-checked by 031/032 (no wrapping left), so adoption is behavior-identical: `claimKeyOf`, `fromValue`, `parseNumericDate`, ACE `exi`, eat `intKey`/`parseUintClaim`, `psa.intOf` now use `Int64`/`Uint64`; boundary tests added; no golden changes. Map loops dispatch every entry, so `Get*` doesn't apply. cose/edhoc sites not in scope here |
| 4 | RFC 8746 typed arrays | 026 Phase D | consumer request | — |
| 5 | Concise Diagnostic Notation alignment | 026 Phase E | draft-ietf-cbor-edn-literals publishes | `DiagCDN()` reserved |
| 6 | Ed448 / X448 sign, verify and ECDH | 028, 029, 033 | standard library support | Parse/marshal only today; EDHOC suite 25 and HPKE-5/6 blocked on it |
| 7 | `BenchmarkParseKeyEC2` 20 allocs vs target 10 | 028 | perf work | **Done (partial, floor documented).** 20 → 15 allocs/op (2064 → 2056 B/op, time unchanged within noise): the on-curve check uses `crypto/ecdh` `NewPublicKey` on a stack buffer instead of `ecdsa.ParseUncompressedPublicKey`, and parse config no longer escapes without options. Floor ~15 with the current design: decode 3, `Key` + params map 2, boxing into `map[int64]any` 2–3, point buffer escaping through the interface call 1, `crypto/ecdh` internals ~4. Reaching 10 needs typed key fields instead of `map[int64]any` and a non-allocating on-curve check, which the standard library doesn't expose |
| 8 | mDL issuer-auth interop vector | 028 | vector with a confirmed license | Non-gating |
| 9 | `cose.NewKeyFromPublic` accepting `*ecdh.PublicKey` (X25519) | 033 follow-ups | — | **Done.** `NewKeyFromPublic` already took `*ecdh.PublicKey` (029); added `NewKeyFromECDH`, `(*Key).ECDHPublicKey` and `(*Key).ECDHPrivateKey` (X25519; EC2 P-256/384/521), additive per 034. edhoc's local builder is removed in favor of `cose.NewKeyFromPublic`; RFC 9529 traces 1 and 2 pass byte-for-byte and the legacy v0.2.2 vectors still reproduce |
| 10 | RFC 10013 measured component helpers | 032 Phase D | consumer request | `Measurements` carried as typed bytes today |
| 11 | HPKE code points final; drop `Draft…`/Experimental | 029 | draft-ietf-cose-hpke publishes with IANA values | 034 lifecycle |
| 12 | Serialization profile identifiers final | 024 | draft-ietf-cbor-serialization publishes | 034 lifecycle |
| 13 | Report draft-ietf-cose-hpke-27 key-encryption vectors using 16-byte AES-GCM IVs (RFC 9053 requires 96-bit) | 029 | — | Upstream erratum/issue |
| 14 | Add `scitt` to `apicheck` | 030 | after the first release that contains `scitt` | No v0.2.2 baseline exists |
| 15 | Inline EAT submodules keep original bytes; JSON submods | 032 | consumer request | Re-encoded deterministically today |
| 16 | `TestMarshalerVerbatimPermissive`-style splice for non-raw Marshalers in Permissive mode | 022 | consumer request | Raw types only today |
| 17 | Benchmark coverage: every decode/encode path the default options exercise (forgiving maps were uncovered until 2026-11-22) — **done 2026-11-22** | release check | — | `bench_036_test.go` adds forgiving large maps, nested maps, long text/bytes, tags, mixed arrays, deterministic/permissive encode, `EncodeTo`, `Marshal`/`Unmarshal` of maps/any/slices, `DecodeFrom` and stream decode. Gaps it showed → items 21–24 |
| 18 | String interning (`WithStringIntern`) has no tests or benchmark — **done 2026-11-22** | 018 | — | `intern_036_test.go`: equal and shared strings, no aliasing of the source (plain, zero-copy, arena), `Prefill`, capacity bound, steady-state 0 allocs; `BenchmarkDecodeRepeatedKeysIntern` is 0 allocs/op. The steady-state test caught a per-key allocation in duplicate tracking for maps over 16 entries, fixed with item 1 |
| 19 | Arena-only nested-map decode: 10 allocs vs target ≤2 — **criterion amended 2026-11-22** | 018 | — | All 10 are text and byte strings. `WithArena` documents that only container backing is arena-owned and that strings stay valid after `Reset`, so arena-only can't reach ≤2 without changing that contract (034). `TestArenaNestedMapAllocs` pins arena 10, arena + intern 1, arena + zero-copy 0 |
| 20 | `Cursor.FindMapKey` on a 50-key map: 2 allocs vs target ≤1 — **done 2026-11-22** | 018 | — | Frames are stored inline: 2 → 1 alloc (the decoded value). Fixed a defect found on the way: `EnterArray`/`EnterMap` didn't count the nested container as an item of its parent, so leaving the parent afterwards failed with `ErrTruncated` or skipped the next sibling (`TestCursorSiblingAfterNested`) |
| 21 | `Unmarshal` of a 1000-item `[]uint64`: ~23 µs vs ~1.9 µs to `Decode` the same array — **done 2026-11-22**: 23.6 → 6.0 µs (−75%) at `-cpu 1`, 2.85 µs at default GOMAXPROCS | 036 item 17 | perf work | Elements of predeclared scalar types can't have methods, so slices and arrays of them call the same setters as `valueToGo` without per-element dispatch, and `[]uint64`/`[]string`/`[]float64`/`[]bool` of matching kinds are filled directly. Errors and results are unchanged; `unmarshal_slice_036_test.go` compares every outcome with named element types, which keep the generic path. The remaining gap to `Decode` (~3× at `-cpu 1`, ~1.6× at default) is mostly GC for the 8 KB result slice |
| 22 | `DecodeTags`: ~500 allocs for 300 tags — **done 2026-11-22**: 500 → 200 allocs, 35.2 → 1.6 KB/op, −28% time | 036 item 17 | perf work | With an arena (including the `Decoder`'s internal one), tag content comes from the arena like array backing, capped at one item so an append can't overwrite the next slot. `Value` and `Clone` unchanged. The remaining 200 are the tags' byte strings, which `WithArena` keeps heap-owned. Without an arena each tag still allocates its one-item slice; batching it would tie every tag's lifetime to a shared slab. Lifetime note: a tag from `Decoder.Decode` around a scalar used to survive the next `Decode` (one around an array never did); it now follows the documented rule that Values are valid until the next `Decode`. `FuzzTagPreservation` relied on the old behavior and now re-decodes on a second `Decoder` |
| 23 | `DecodeFrom`: 28 allocs vs 10 for `Decode` of the same item — **done 2026-11-22** | 036 item 17 | — | 28 → 20 allocs, 4928 → 4352 B, 1.83 → 1.71 µs (−7%). The item reader's buffer and frame stack are pooled; the buffer is reused only after a successful non-`ZeroCopy` decode, when no Value can alias it. The 20 that remain are the decoded value (10 strings, 9 heap container slices) plus the benchmark's `bytes.Reader`, so the reader adds none. `Decode`'s 10 come from the root decoder's internal arena, which `DecodeFrom` doesn't use: its Values outlive the call (034) |
| 24 | Stream decode: ~7.8 µs per item vs ~0.7 µs for `Decode` — **done 2026-11-22** | 036 item 17 | — | 1.83 → 1.31 µs per item (−28%), 27 → 19 allocs per item. On this machine the gap was 1.8 vs 0.7 µs, not 7.8. `Stream.Next` decodes an item in place from the `BufferedReader` buffer when the whole item is there. It falls back to the item reader, with identical errors, limits and consumption, when the item straddles a refill, the decode fails, or `ZeroCopy`, `Budget` or `Arena` is set. Per item it now matches `rfc8949.Decode` with heap containers (1.23 µs, 19 allocs); the rest of the gap to `Decode` is the arena, as in item 23. `FuzzDecodeFromMatchesDecode` now covers `BufferedReader` and `ZeroCopy`. Adding `ZeroCopy` coverage exposed a panic in `Decode`: a zero-copy empty text string at the end of the input. It is fixed |
| 25 | `Cursor` limit checks — **done 2026-11-22** | `FuzzRawSpanRoundTrip` | — | `Skip` reported `ErrMaxNestingDepth` where `Decode` reported `ErrMaxArrayLength` for a container over both limits; now length first, as `Decode` and the stream reader do. Auditing the rest of `Cursor` found: `EnterArray`/`EnterMap` checked none of `Decode`'s head rules or limits, and a count ≥ 2⁶³ wrapped to -1 (read as indefinite); `Cursor.Decode` restarted nesting depth at the cursor; `FindMapKey` panicked on a text key whose length doesn't fit an `int`. All fixed (safety defects, 034); `cursor_limits_test.go`. Found on the way, in `cwt`/`eat`: a bignum claim key with an integer value re-encoded as a registered claim (bignum 1 as `iss`), now rejected with `cwt.ErrAmbiguousClaimKey` naming the key as received; and in `cose`, a COSE_Key parameter holding NaN/±Inf parsed but couldn't be marshalled, now rejected with `ErrNonFiniteKeyParam` / `*KeyParamError`. `cwt`/`eat` also silently rewrote NaN payloads to `f97e00` when re-encoding claims; now rejected with `cwt.ErrNonCanonicalNaN` (decode and `Encode`). Opt-ins keep unmodeled claims byte for byte instead: `cwt.DecodeOptions.KeepAsReceived` → `ClaimsSet.ReceivedClaims`, `eat.WithKeepAsReceived()` (submodules included); `Encode` writes them verbatim. `cose.KeepParamsAsReceived()` does the same for key parameters (`ReceivedParams`, `DeleteReceivedParam`; labels -12..5 always checked). Shared checks: `internal/asreceived` |

## Results (2026-11-22)

Apple M4 Pro, default GOMAXPROCS. Base is `fea25db` plus the item 17
benchmarks; base and head binaries ran interleaved, benchstat n=6–8.
Times on this machine vary ±5–10% between runs, so only significant
changes are listed; every other benchmark was unchanged within noise.

| Benchmark | Before | After | Item |
|---|---|---|---|
| `DecodeStrictLargeMap100` | 7.28 µs, 200 allocs | 6.76 µs (−7%), 100 allocs | 1 |
| `DecodeStrictLargeMap1000` | 75.5–77.3 µs, 2000 allocs | 67.9–71.5 µs (−7 to −10%), 1000 allocs | 1 |
| `DecodeForgivingLargeMap100` | 7.27–7.45 µs, 200 allocs | 6.66–6.76 µs (−8 to −9%), 100 allocs | 1 |
| `DecodeForgivingLargeMap1000` | 74.6–76.2 µs, 2000 allocs | 66.1–67.8 µs (−11%), 1000 allocs | 1 |
| `MapInsertHash` (rfc8949) | 10.1 µs, 201 allocs | 8.73 µs (−14%), 101 allocs | 1 |
| `DecodeNestedMapStrict` | 769 ns | 781 ns (~, p=0.07) | 1 |
| `UnmarshalMap` | 255 allocs, 4.19 KiB | 205 allocs, 3.80 KiB | 1 |
| `UnmarshalStructRawMessage` | 1.26 µs, 23 allocs | 1.27 µs (~), 22 allocs | 2 |
| `DecodeRepeatedKeysIntern` | — | 1.32 µs, 0 allocs | 18 |
| `CursorFindMapKey` / `…Last` | 2 allocs, 128 B | 1 alloc, 112 B | 20 |

`EncodeMapPreordered` (16 ns) read +6.7% in one full run and +7%
(not significant, p=0.06) on a 10-round re-run; the encoder is
unchanged on this branch, so this is code layout, not a regression.

### Items 21–22

Base `01b8bb0`, `-cpu 1`, min of 10 interleaved rounds. Every other
benchmark in the root and `rfc8949` packages was within 2% of base on
a focused re-run of anything a full run flagged.

| Benchmark | Before | After | Item |
|---|---|---|---|
| `UnmarshalSlice` | 23.6 µs, 3 allocs | 5.98 µs (−75%), 3 allocs | 21 |
| `DecodeTags` | 21.5 µs, 500 allocs, 35.2 KB | 15.5 µs (−28%), 200 allocs, 1.6 KB | 22 |

### Items 23–24

Base `01b8bb0`. Base and head binaries ran interleaved at `-cpu 1`,
alternating which went first each round. Figures are the min of 10
rounds at load ~2.5. Every other benchmark was within 2% of base on a
focused re-run of anything a full run flagged; the full runs drifted
±5% both ways, including on encoder benchmarks with identical code.

| Benchmark | Before | After | Item |
|---|---|---|---|
| `DecodeFrom` | 1.83 µs, 4928 B, 28 allocs | 1.71 µs (−7%), 4352 B, 20 allocs | 23 |
| `StreamDecodeSequence` (100 items) | 183 µs, 492 KB, 2703 allocs | 131 µs (−28%), 437 KB, 1918 allocs | 24 |

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-22 | Filed from the deferred items of 020–035 | corecbor maintainers |
| 2026-11-22 | Add items 18–20 from 018's closure | corecbor maintainers |
| 2026-11-22 | Status: In-Progress (streams for items 1–3, 7, 9, 17–20 started) | corecbor maintainers |
| 2026-11-22 | Item 3 done for cwt and eat (behavior-identical accessor adoption) | corecbor maintainers |
| 2026-11-22 | Items 17, 18, 20 done; 19 criterion amended; 1 partly recovered; 2 measured and deferred; items 21–24 filed from 17 | corecbor maintainers |
| 2026-11-22 | Items 23, 24 done; zero-copy empty-text panic fixed on the way | corecbor maintainers |
| 2026-11-22 | Items 21, 22 done | corecbor maintainers |
| 2026-11-22 | Item 25 filed and done (`Cursor` limits; `cwt`/`eat` bignum claim keys) | corecbor maintainers |
| 2026-11-23 | Done items ship in v0.3.0; the open items are deferred out of v0.3 (each waits on its trigger) | corecbor maintainers |
