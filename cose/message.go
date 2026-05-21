package cose

// Sign1 represents a COSE_Sign1 message (single-signer signing).
// CBOR structure: Tag(18, [protectedBstr, unprotectedMap, payload/nil, signature])
type Sign1 struct {
	// Protected contains the integrity-protected header parameters.
	Protected Headers

	// Unprotected contains the non-integrity-protected header parameters.
	Unprotected Headers

	// Payload is the serialized content. nil indicates detached payload.
	Payload []byte

	// Signature is the computed signature value.
	Signature []byte
}
