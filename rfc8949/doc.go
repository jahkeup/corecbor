// Package rfc8949 implements CBOR encoding per RFC 8949.
//
// It supports two modes:
//   - Permissive (default): preferred serialization (shortest argument encoding)
//     with input-width-preserving float encoding.
//   - CoreDeterministic: RFC 8949 §4.2.1 Core Deterministic Encoding Requirements
//     including shortest float encoding, map key sorting by encoded form, and
//     no indefinite-length items.
//
// The encoder operates on the value model defined in [github.com/jahkeup/corecbor/cbor]
// and uses the low-level wire primitives from [github.com/jahkeup/corecbor/wire].
package rfc8949
