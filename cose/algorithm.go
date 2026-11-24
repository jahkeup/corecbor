// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import "crypto"

// Algorithm identifies a COSE algorithm from the IANA registry.
type Algorithm int64

// Values are checked against the IANA COSE Algorithms registry
// (testdata/iana-cose-algorithms.csv, TestAlgorithmRegistry).
const (
	// AlgEdDSA is the EdDSA algorithm (Ed25519).
	//
	// Deprecated: polymorphic identifier, deprecated by RFC 9864. Use
	// AlgEd25519 (and WithFullySpecifiedAlgorithms when signing). Still
	// emitted by NewSigner by default and still verified.
	AlgEdDSA Algorithm = -8

	// AlgES256 is ECDSA w/ SHA-256 using P-256.
	//
	// Deprecated: polymorphic identifier, deprecated by RFC 9864. Use
	// AlgESP256 (and WithFullySpecifiedAlgorithms when signing). Still
	// emitted by NewSigner by default and still verified.
	AlgES256 Algorithm = -7

	// AlgES384 is ECDSA w/ SHA-384 using P-384.
	//
	// Deprecated: polymorphic identifier, deprecated by RFC 9864. Use
	// AlgESP384.
	AlgES384 Algorithm = -35

	// AlgES512 is ECDSA w/ SHA-512 using P-521.
	//
	// Deprecated: polymorphic identifier, deprecated by RFC 9864. Use
	// AlgESP512.
	AlgES512 Algorithm = -36

	// Fully-specified signature algorithms (RFC 9864).
	AlgESP256  Algorithm = -9  // ECDSA using P-256 and SHA-256
	AlgESP384  Algorithm = -51 // ECDSA using P-384 and SHA-384
	AlgESP512  Algorithm = -52 // ECDSA using P-521 and SHA-512
	AlgEd25519 Algorithm = -19 // EdDSA using Ed25519

	// AlgEd448 is EdDSA using Ed448 (RFC 9864). Registered only: Go has no
	// Ed448 implementation, so signing and verifying return
	// ErrUnsupportedAlgorithm.
	AlgEd448 Algorithm = -53

	// ECDSA with Brainpool curves (RFC 9864). Registered only (not
	// Recommended by IANA, no Go implementation).
	AlgESB256 Algorithm = -265
	AlgESB320 Algorithm = -266
	AlgESB384 Algorithm = -267
	AlgESB512 Algorithm = -268

	// ML-DSA (RFC 9964), on AKP keys (kty 7). Requires a Go 1.27+
	// toolchain (crypto/mldsa); built with an older toolchain these return
	// ErrUnsupportedAlgorithm.
	AlgMLDSA44 Algorithm = -48
	AlgMLDSA65 Algorithm = -49
	AlgMLDSA87 Algorithm = -50

	// Content encryption algorithms (RFC 9053 §4.1)
	AlgA128GCM Algorithm = 1
	AlgA192GCM Algorithm = 2
	AlgA256GCM Algorithm = 3

	// AES-CCM content encryption (RFC 9053 §4.2): AES-CCM-L-M-K, with an
	// L-octet length field (16 → 13-byte nonce, 64 → 7-byte nonce), an
	// M-bit tag and a K-bit key.
	AlgAESCCM_16_64_128  Algorithm = 10
	AlgAESCCM_16_64_256  Algorithm = 11
	AlgAESCCM_64_64_128  Algorithm = 12
	AlgAESCCM_64_64_256  Algorithm = 13
	AlgAESCCM_16_128_128 Algorithm = 30
	AlgAESCCM_16_128_256 Algorithm = 31
	AlgAESCCM_64_128_128 Algorithm = 32
	AlgAESCCM_64_128_256 Algorithm = 33

	// AlgChaCha20Poly1305 (RFC 9053 §4.3). Registered only: there is no
	// ChaCha20-Poly1305 in the standard library, and the cose module takes
	// no golang.org/x/crypto dependency.
	AlgChaCha20Poly1305 Algorithm = 24

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

	// ECDH-ES key agreement (RFC 9053 §6.3). -25/-26 are direct key
	// agreement (the derived key is the CEK); -29/-30/-31 derive a KEK
	// that AES-KW-wraps the CEK.
	AlgECDH_ES_HKDF_256 Algorithm = -25
	AlgECDH_ES_HKDF_512 Algorithm = -26
	AlgECDH_ES_A128KW   Algorithm = -29
	AlgECDH_ES_A192KW   Algorithm = -30
	AlgECDH_ES_A256KW   Algorithm = -31

	// AlgPBES2_HS256_A128KW was corecbor's PBES2 identifier in v0.2.
	//
	// Deprecated: PBES2 is not a registered COSE algorithm, and -11 is
	// registered as direct+HKDF-SHA-512. Use AlgPrivatePBES2_HS256_A128KW;
	// -11 is emitted and accepted only under WithLegacyPBES2Labels.
	AlgPBES2_HS256_A128KW Algorithm = -11

	// AlgPrivatePBES2_HS256_A128KW is PBES2-HS256+A128KW (RFC 8018 key
	// derivation, AES-KW wrap) in the COSE private-use range (< -65536),
	// since PBES2 is not registered for COSE. Only corecbor peers
	// understand it.
	AlgPrivatePBES2_HS256_A128KW Algorithm = -65601

	// AlgHPKEBaseP256SHA256AES128GCM is corecbor's pre-draft HPKE
	// key-encryption format (see HPKEKey).
	//
	// Deprecated: non-interoperable, and unrelated to
	// draft-ietf-cose-hpke's HPKE-0; see HPKERecipient and WithDraftHPKE27.
	AlgHPKEBaseP256SHA256AES128GCM Algorithm = 35

	// RSASSA-PSS (RFC 8230 §2). The key must be at least 2048 bits. An
	// RSA Signer emits PS256 unless its protected headers or COSE_Key
	// select another RSA algorithm.
	AlgPS256 Algorithm = -37
	AlgPS384 Algorithm = -38
	AlgPS512 Algorithm = -39

	// RSASSA-PKCS1-v1_5 (RFC 8812 §2). Not Recommended by IANA: a Verifier
	// accepts these only when listed in WithAllowedAlgorithms, and a Signer
	// emits them only when selected explicitly.
	AlgRS256 Algorithm = -257
	AlgRS384 Algorithm = -258
	AlgRS512 Algorithm = -259

	// Hash algorithms (RFC 9054), used by COSE_CertHash (x5t, RFC 9360).
	// SHA-1 and SHA-256/64 are registered as "Filter Only".
	AlgSHA1       Algorithm = -14
	AlgSHA256_64  Algorithm = -15
	AlgSHA256     Algorithm = -16
	AlgSHA512_256 Algorithm = -17
	AlgSHA384     Algorithm = -43
	AlgSHA512     Algorithm = -44
)

var algNames = map[Algorithm]string{
	AlgEdDSA:   "EdDSA",
	AlgES256:   "ES256",
	AlgES384:   "ES384",
	AlgES512:   "ES512",
	AlgESP256:  "ESP256",
	AlgESP384:  "ESP384",
	AlgESP512:  "ESP512",
	AlgEd25519: "Ed25519",
	AlgEd448:   "Ed448",
	AlgESB256:  "ESB256",
	AlgESB320:  "ESB320",
	AlgESB384:  "ESB384",
	AlgESB512:  "ESB512",
	AlgMLDSA44: "ML-DSA-44",
	AlgMLDSA65: "ML-DSA-65",
	AlgMLDSA87: "ML-DSA-87",

	AlgA128GCM:           "A128GCM",
	AlgA192GCM:           "A192GCM",
	AlgA256GCM:           "A256GCM",
	AlgAESCCM_16_64_128:  "AES-CCM-16-64-128",
	AlgAESCCM_16_64_256:  "AES-CCM-16-64-256",
	AlgAESCCM_64_64_128:  "AES-CCM-64-64-128",
	AlgAESCCM_64_64_256:  "AES-CCM-64-64-256",
	AlgAESCCM_16_128_128: "AES-CCM-16-128-128",
	AlgAESCCM_16_128_256: "AES-CCM-16-128-256",
	AlgAESCCM_64_128_128: "AES-CCM-64-128-128",
	AlgAESCCM_64_128_256: "AES-CCM-64-128-256",
	AlgChaCha20Poly1305:  "ChaCha20/Poly1305",

	AlgHMAC256_64: "HMAC256/64",
	AlgHMAC256:    "HMAC256",
	AlgHMAC384:    "HMAC384",
	AlgHMAC512:    "HMAC512",

	AlgDirect:           "direct",
	AlgA128KW:           "A128KW",
	AlgA192KW:           "A192KW",
	AlgA256KW:           "A256KW",
	AlgECDH_ES_HKDF_256: "ECDH-ES+HKDF-256",
	AlgECDH_ES_HKDF_512: "ECDH-ES+HKDF-512",
	AlgECDH_ES_A128KW:   "ECDH-ES+A128KW",
	AlgECDH_ES_A192KW:   "ECDH-ES+A192KW",
	AlgECDH_ES_A256KW:   "ECDH-ES+A256KW",

	AlgPBES2_HS256_A128KW:          "PBES2-HS256+A128KW",
	AlgPrivatePBES2_HS256_A128KW:   "PBES2-HS256+A128KW (private use)",
	AlgHPKEBaseP256SHA256AES128GCM: "HPKE-Base-P256-SHA256-AES128GCM",

	AlgPS256: "PS256",
	AlgPS384: "PS384",
	AlgPS512: "PS512",
	AlgRS256: "RS256",
	AlgRS384: "RS384",
	AlgRS512: "RS512",

	AlgSHA1:       "SHA-1",
	AlgSHA256_64:  "SHA-256/64",
	AlgSHA256:     "SHA-256",
	AlgSHA512_256: "SHA-512/256",
	AlgSHA384:     "SHA-384",
	AlgSHA512:     "SHA-512",
}

func (a Algorithm) String() string {
	if n, ok := algNames[a]; ok {
		return n
	}
	return "unknown"
}

// Deprecated reports whether IANA marks the algorithm Deprecated: the
// polymorphic ECDSA and EdDSA identifiers (RFC 9864). The legacy PBES2
// identifier -11 is not a deprecated COSE algorithm (IANA registers it as
// direct+HKDF-SHA-512); it is deprecated only as corecbor's old PBES2
// identifier.
func (a Algorithm) Deprecated() bool {
	switch a {
	case AlgES256, AlgES384, AlgES512, AlgEdDSA:
		return true
	}
	return false
}

// FullySpecified returns the RFC 9864 fully-specified identifier for
// algorithm a used with pub: ES256 with a P-256 key → ESP256, ES384 with
// P-384 → ESP384, ES512 with P-521 → ESP512, EdDSA with an Ed25519 key →
// Ed25519. A fully-specified a that matches pub is returned unchanged.
// ok is false when a and pub don't match or there is no fully-specified
// form.
func FullySpecified(a Algorithm, pub crypto.PublicKey) (Algorithm, bool) {
	implied, err := algForPublicKey(pub)
	if err != nil || implied == algRSAFamily {
		return 0, false
	}
	fs := fullySpecifiedFor(implied)
	if fs != 0 && (a == implied || a == fs) {
		return fs, true
	}
	return 0, false
}

// fullySpecifiedFor maps a signature algorithm to its RFC 9864
// fully-specified form (0 if there is none). Fully-specified algorithms
// map to themselves.
func fullySpecifiedFor(a Algorithm) Algorithm {
	switch a {
	case AlgES256, AlgESP256:
		return AlgESP256
	case AlgES384, AlgESP384:
		return AlgESP384
	case AlgES512, AlgESP512:
		return AlgESP512
	case AlgEdDSA, AlgEd25519:
		return AlgEd25519
	case AlgMLDSA44, AlgMLDSA65, AlgMLDSA87:
		return a
	}
	return 0
}

// signerCanEmit reports whether a signer whose key implies implied may
// sign with a: a member of the same family, or any RSA algorithm for an
// RSA key (PS256 is only the default).
func signerCanEmit(a, implied Algorithm) bool {
	return sameSignatureFamily(a, implied) || (isRSAAlg(a) && isRSAAlg(implied))
}

// sameSignatureFamily reports whether a and b select the same signature
// operation: equal algorithms, or a polymorphic identifier and its
// fully-specified replacement (ES256 and ESP256, EdDSA and Ed25519, …).
func sameSignatureFamily(a, b Algorithm) bool {
	if a == b {
		return true
	}
	fa := fullySpecifiedFor(a)
	return fa != 0 && fa == fullySpecifiedFor(b)
}
