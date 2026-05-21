// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package cwt implements CBOR Web Tokens (CWT) as defined in RFC 8392.
//
// A CWT is a compact means of representing claims to be transferred between
// two parties. The claims are encoded in CBOR and protected using COSE
// (CBOR Object Signing and Encryption).
//
// This package supports creating and verifying signed CWTs (COSE_Sign1-wrapped)
// and validating standard claims such as expiration, not-before, and audience.
package cwt
