// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package eat implements Entity Attestation Tokens (EAT) as defined in RFC 9711.
//
// EAT extends CBOR Web Tokens (CWT) with attestation-specific claims such as
// device identity (UEID), security level, secure boot status, and debug state.
// Tokens are signed using COSE_Sign1 and can be appraised against policy via
// the Appraiser type.
package eat
