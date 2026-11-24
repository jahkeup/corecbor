// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

// Sign1 represents a COSE_Sign1 message (single-signer signing).
// CBOR structure: Tag(18, [protectedBstr, unprotectedMap, payload/nil, signature])
type Sign1 struct {
	Protected   Headers
	Unprotected Headers
	Payload     []byte
	Signature   []byte
}

// Encrypt0 represents a COSE_Encrypt0 message (single-recipient encryption).
// CBOR structure: Tag(16, [protectedBstr, unprotectedMap, ciphertext])
type Encrypt0 struct {
	Protected   Headers
	Unprotected Headers
	Ciphertext  []byte
}

// Mac0 represents a COSE_Mac0 message (single-recipient MAC).
// CBOR structure: Tag(17, [protectedBstr, unprotectedMap, payload, tag])
type Mac0 struct {
	Protected   Headers
	Unprotected Headers
	Payload     []byte
	Tag         []byte
}

// Sign represents a COSE_Sign message (multi-signer signing).
// CBOR structure: Tag(98, [protectedBstr, unprotectedMap, payload/nil, [+signature]])
type Sign struct {
	Protected   Headers
	Unprotected Headers
	Payload     []byte
	Signatures  []Signature
}

// Signature represents one entry in COSE_Sign's signatures array.
type Signature struct {
	Protected   Headers
	Unprotected Headers
	Signature   []byte
}

// Mac represents a COSE_Mac message (multi-recipient MAC).
// CBOR structure: Tag(97, [protectedBstr, unprotectedMap, payload, tag, [+recipient]])
type Mac struct {
	Protected   Headers
	Unprotected Headers
	Payload     []byte
	Tag         []byte
	Recipients  []Recipient
}

// Encrypt represents a COSE_Encrypt message (multi-recipient encryption).
// CBOR structure: Tag(96, [protectedBstr, unprotectedMap, ciphertext, [+recipient]])
type Encrypt struct {
	Protected   Headers
	Unprotected Headers
	Ciphertext  []byte
	Recipients  []Recipient
}

// Recipient is a COSE_recipient (RFC 9052 §5.1).
// CBOR structure: [protectedBstr, unprotectedMap, ciphertext/nil, ? [+recipient]]
type Recipient struct {
	Protected   Headers
	Unprotected Headers
	Ciphertext  []byte
	// Recipients holds nested recipients, for a layer whose key is
	// itself distributed by further recipients (RFC 9052 §5.1,
	// Appendix B). They are parsed and written back; DecryptMulti and
	// VerifyMACMulti open the top-level recipient they are given and
	// don't descend into them.
	Recipients []Recipient
}
