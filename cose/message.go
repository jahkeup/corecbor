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
