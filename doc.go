// Package corecbor provides a strict RFC 8949 CBOR encoder and a
// forgiving CBOR decoder with knobs to control strictness.
//
// The encoder offers selectable modes — Permissive (default,
// round-trip-safe but not byte-deterministic) and CoreDeterministic
// (RFC 8949 §4.2.1, byte-identical output for byte-identical input).
// Phase 2 adds Canonical (RFC 7049) and CTAP2 (FIDO/WebAuthn) modes.
//
// The decoder defaults forgiving — it accepts every well-formed CBOR
// byte sequence the spec defines plus the well-known "common quirks"
// (indefinite-length, non-shortest argument encoding, duplicate map
// keys, etc.). Callers who need strict input validation pass per-knob
// rejection options or use the StrictDecoder preset, which is suitable
// for inputs feeding into AAD-bound cryptographic primitives.
//
// This package is the primitive layer. It exposes a Value-tree API
// (Uint, NegInt, Bytes, Text, Array, Map, Tag, ...) — not a
// reflection-based marshal/unmarshal surface. Higher layers
// (schema-aware codecs, COSE, CWT) build on top of this layer.
//
// See engineering-docs/encoder-decoder-spec.md for the full contract.
package corecbor
