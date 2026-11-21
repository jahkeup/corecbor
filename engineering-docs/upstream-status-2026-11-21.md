# Upstream status — 2026-11-21 (IANA CBOR tags registry re-check)

Scope: the IANA CBOR tags registry only. The rest of the survey in
`upstream-status-2026-11.md` was not re-run.

Method: `go run ./cmd/cbor-registry-gen -fetch` into a scratch cache
(registry last updated by IANA 2026-11-13), diffed against the
committed `registry/registry.json`.

## Result

- **+10 tags, none removed or reassigned:** 33000 (TLA+ function),
  44252 (metrological value), 46010 (CRC-32/ISO-HDLC digest), 46011
  (MD5 digest), 55003–55005 (USOF references), 133133 (ZeWIF),
  827539798 (Universal Saves Format bundle), 1735551332 (PromiseGrid
  message envelope).
- **228 entries changed formatting only:** reference strings now read
  `[RFC 8949]` instead of `[RFC8949]` and separate multiple references
  with `; `. No semantic change; no existing generated constant name
  changes (proposal 026 freezes generated names).
- No tag modeled by corecbor (spec §4.3, `TagsWellKnown`) changed.

## Correction to `upstream-status-2026-11.md`

That snapshot listed "10/11/13 IXDTF" among new tags. They are not CBOR
tags: they are keys in RFC 9581's time-key sub-registry, picked up by
an over-broad parse of the registry XML. They matter to the RFC 9581
tag helpers (proposal 026) as map keys, not as tag numbers.

## Action

Regenerate `registry/` with the generator's `-fetch` mode as part of
proposal 026; the expected diff is the one above.
