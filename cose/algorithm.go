package cose

// Algorithm identifies a COSE algorithm from the IANA registry.
type Algorithm int64

const (
	// AlgEdDSA is the EdDSA algorithm (Ed25519).
	AlgEdDSA Algorithm = -8

	// AlgES256 is ECDSA w/ SHA-256 using P-256.
	AlgES256 Algorithm = -7

	// AlgES384 is ECDSA w/ SHA-384 using P-384.
	AlgES384 Algorithm = -35

	// AlgES512 is ECDSA w/ SHA-512 using P-521.
	AlgES512 Algorithm = -36
)

// String returns the algorithm name.
func (a Algorithm) String() string {
	switch a {
	case AlgEdDSA:
		return "EdDSA"
	case AlgES256:
		return "ES256"
	case AlgES384:
		return "ES384"
	case AlgES512:
		return "ES512"
	default:
		return "unknown"
	}
}
