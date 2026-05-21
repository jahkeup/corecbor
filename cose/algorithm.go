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

	// Content encryption algorithms (RFC 9053 §4.1)
	AlgA128GCM Algorithm = 1
	AlgA192GCM Algorithm = 2
	AlgA256GCM Algorithm = 3

	// MAC algorithms (RFC 9053 §3.1)
	AlgHMAC256_64 Algorithm = 4
	AlgHMAC256    Algorithm = 5
	AlgHMAC384    Algorithm = 6
	AlgHMAC512    Algorithm = 7

	// Key distribution algorithms (RFC 9052 §8.5)
	AlgDirect Algorithm = -6

	// AES Key Wrap (RFC 9053 §6.2.1)
	AlgA128KW Algorithm = -3
	AlgA192KW Algorithm = -4
	AlgA256KW Algorithm = -5

	// ECDH-ES + HKDF (RFC 9053 §6.3.1)
	AlgECDH_ES_HKDF_256 Algorithm = -25

	// PBES2 (RFC 9053 §6.2.2)
	AlgPBES2_HS256_A128KW Algorithm = -11

	// HPKE base mode with DHKEM(P-256), HKDF-SHA256, AES-128-GCM (RFC 9180)
	AlgHPKEBaseP256SHA256AES128GCM Algorithm = 35
)

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
	case AlgA128GCM:
		return "A128GCM"
	case AlgA192GCM:
		return "A192GCM"
	case AlgA256GCM:
		return "A256GCM"
	case AlgHMAC256_64:
		return "HMAC256/64"
	case AlgHMAC256:
		return "HMAC256"
	case AlgHMAC384:
		return "HMAC384"
	case AlgHMAC512:
		return "HMAC512"
	case AlgDirect:
		return "direct"
	case AlgA128KW:
		return "A128KW"
	case AlgA192KW:
		return "A192KW"
	case AlgA256KW:
		return "A256KW"
	case AlgECDH_ES_HKDF_256:
		return "ECDH-ES+HKDF-256"
	case AlgPBES2_HS256_A128KW:
		return "PBES2-HS256+A128KW"
	default:
		return "unknown"
	}
}
