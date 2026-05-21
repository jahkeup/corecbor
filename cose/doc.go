// Package cose implements COSE_Sign1 signing and verification per RFC 9052.
//
// It supports Ed25519 and ECDSA (P-256, P-384, P-521) algorithms, with
// COSE_Key conversion to/from Go stdlib crypto keys.
//
// CBOR encoding uses corecbor's CoreDeterministic mode for internal
// structures (Sig_structure, protected headers) and the forgiving
// decoder for parsing incoming messages.
package cose
