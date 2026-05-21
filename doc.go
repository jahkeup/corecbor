// Package corecbor provides a strict RFC 8949 CBOR encoder and a
// forgiving CBOR decoder with knobs to control strictness.
//
// # Encoder
//
// The encoder offers selectable modes via [New]:
//   - [ModePermissive] (default): round-trip-safe preferred serialization
//     (shortest argument encoding, input-width floats). Not byte-deterministic.
//   - [ModeCoreDeterministic]: RFC 8949 §4.2.1 Core Deterministic Encoding —
//     shortest float encoding, map keys sorted by encoded bytes (bytewise-lex).
//   - [ModeCanonical]: RFC 7049 §3.9 / RFC 8949 §4.2.3 — shortest float
//     encoding, map keys sorted length-first then bytewise-lex.
//   - [ModeCTAP2]: FIDO/WebAuthn CTAP2 canonical — map keys sorted
//     length-first, all floats forced to float64.
//
// Options [AllowNonFiniteFloats] and [AllowInvalidUTF8] relax the default
// strict validation on the encoder side.
//
// # Streaming
//
// [Encoder.EncodeTo] writes a value directly to an [io.Writer].
// [Encoder.Stream] returns a [StreamEncoder] for imperative construction
// of arrays and maps without building a full value tree in memory.
//
// [Decoder.DecodeFrom] reads one value from an [io.Reader].
// [Decoder.Stream] returns a [Stream] iterator for reading sequences of
// concatenated CBOR values.
//
// # Decoder
//
// The decoder defaults to forgiving — it accepts every well-formed CBOR
// byte sequence the spec defines plus the well-known "common quirks"
// (indefinite-length, non-shortest argument encoding, duplicate map
// keys, etc.). Callers who need strict input validation pass per-knob
// rejection options or use the [StrictDecoder] preset, which is suitable
// for inputs feeding into AAD-bound cryptographic primitives.
//
// [Decoder.Decode] rejects trailing bytes: if src contains bytes after
// the first complete CBOR data item, it returns [ErrTrailingBytes].
//
// # Value model
//
// This package is the primitive layer. It exposes a Value-tree API
// ([Uint], [NegInt], [Bytes], [Text], [Array], [Map], [Tag], ...) — not a
// reflection-based marshal/unmarshal surface. Higher layers
// (schema-aware codecs, COSE, CWT) build on top of this layer.
//
// See engineering-docs/encoder-decoder-spec.md for the full contract.
package corecbor
