// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"slices"

	"github.com/jahkeup/corecbor"
)

type EncryptOption func(*encryptOpts)

type encryptOpts struct {
	externalAAD []byte
	policy      headerPolicy
	legacy      legacyEncoding

	nonce             []byte // WithNonce
	baseIV, partialIV []byte // WithPartialIV
	hpkeInfo          []byte // WithHPKEInfo
}

// WithLegacyPBES2Labels uses the v0.2 PBES2 identifiers, alg -11 and
// iteration-count label -21, for both sealing and opening. IANA
// registers -11 as direct+HKDF-SHA-512 and -21 as PartyU identity, so
// no other implementation reads these messages as PBES2.
//
// Deprecated: colliding code points (proposal 029); removed no earlier
// than v0.32.0.
func WithLegacyPBES2Labels() EncryptOption {
	return func(o *encryptOpts) { o.legacy.pbes2 = true }
}

// WithLegacyECDHES uses the v0.2 ECDH-ES encoding for ECDHESKey
// recipients with the default algorithm: -25 carrying AES-KW (-29)
// semantics, a v0.2 key-derivation context, and a raw-point ephemeral
// key. Messages produced this way only interoperate with corecbor v0.2.
//
// Deprecated: non-conformant to RFC 9053 §6.3 (proposal 029); removed
// no earlier than v0.32.0.
func WithLegacyECDHES() EncryptOption {
	return func(o *encryptOpts) { o.legacy.ecdh = true }
}

// CompatV02Encryption bundles WithLegacyPBES2Labels and
// WithLegacyECDHES, the interop-only selectors needed to read or write
// v0.2 encrypted messages. It weakens no verification.
//
// Deprecated: migrate to explicit selectors; removed no earlier than
// v0.32.0.
func CompatV02Encryption() EncryptOption {
	return func(o *encryptOpts) {
		o.legacy.pbes2 = true
		o.legacy.ecdh = true
	}
}

// WithNonce makes Encrypt0Seal use nonce as the IV instead of a random
// one. For test vectors and deterministic fixtures only: reusing a nonce
// with the same key breaks AES-GCM and AES-CCM.
func WithNonce(nonce []byte) EncryptOption {
	return func(o *encryptOpts) { o.nonce = nonce }
}

// WithPartialIV uses RFC 9052 §3.1 nonce construction: the IV is the
// Base IV XORed with the Partial IV left-padded to the IV length.
// Encrypt0Seal writes partialIV to the Partial IV header (6) instead of
// writing an IV (5); Encrypt0Open uses baseIV with the message's
// Partial IV. OSCORE (RFC 8613) builds its nonces this way.
func WithPartialIV(baseIV, partialIV []byte) EncryptOption {
	return func(o *encryptOpts) {
		o.baseIV = baseIV
		o.partialIV = partialIV
	}
}

func WithEncryptExternalAAD(aad []byte) EncryptOption {
	return func(o *encryptOpts) { o.externalAAD = aad }
}

// WithEncryptAlgorithms restricts which content-encryption algorithms
// are accepted. For DecryptEncrypt0 the caller's alg must be listed.
// For DecryptMulti it replaces the default set (AES-GCM 128/192/256).
func WithEncryptAlgorithms(algs ...Algorithm) EncryptOption {
	return func(o *encryptOpts) { o.policy.allowed = slices.Clone(algs) }
}

// WithEncryptKnownCriticalHeaders declares header labels the caller
// processes itself; see WithKnownCriticalHeaders.
func WithEncryptKnownCriticalHeaders(labels ...any) EncryptOption {
	return func(o *encryptOpts) { o.policy.knownCrit = append(o.policy.knownCrit, normalizeLabels(labels)...) }
}

// WithLegacyEncryptHeaders restores v0.2.2 header handling for
// decryption: the alg header isn't bound to the caller's algorithm
// (DecryptEncrypt0) or checked against the unprotected bucket
// (DecryptMulti), and crit isn't processed.
//
// Deprecated: proposal 027 H2/H3 (RFC 9052 §3.1). Retained for
// migration only; removed no earlier than v0.32.0.
func WithLegacyEncryptHeaders() EncryptOption {
	return func(o *encryptOpts) {
		o.policy.legacyAlg = true
		o.policy.legacyCrit = true
	}
}

// EncryptEncrypt0 encrypts plaintext into a COSE_Encrypt0 with AES-GCM
// key and the caller's nonce. The nonce is not written to the message,
// so the recipient must learn it out of band.
//
// Deprecated: use Encrypt0Seal, which generates the IV and carries it in
// the IV header (label 5). EncryptEncrypt0 keeps working for the life of
// the v0.x line.
func EncryptEncrypt0(plaintext, key, nonce []byte, alg Algorithm, opts ...EncryptOption) (*Encrypt0, error) {
	var o encryptOpts
	for _, opt := range opts {
		opt(&o)
	}

	if err := validateAESGCMKey(alg, key); err != nil {
		return nil, err
	}

	msg := &Encrypt0{}
	msg.Protected.SetAlgorithm(alg)

	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}

	aad, err := buildEncStructure(protectedBytes, o.externalAAD)
	if err != nil {
		return nil, err
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%w: nonce must be %d bytes", ErrInvalidKey, gcm.NonceSize())
	}

	msg.Ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return msg, nil
}

// DecryptEncrypt0 decrypts a COSE_Encrypt0 with AES-GCM key, the
// caller's nonce and alg; the message's alg must match alg.
//
// Deprecated: use Encrypt0Open, which reads the IV from the message.
// DecryptEncrypt0 keeps working for the life of the v0.x line.
func DecryptEncrypt0(msg *Encrypt0, key, nonce []byte, alg Algorithm, opts ...EncryptOption) ([]byte, error) {
	var o encryptOpts
	for _, opt := range opts {
		opt(&o)
	}

	if err := validateAESGCMKey(alg, key); err != nil {
		return nil, err
	}
	if err := checkCrit(&msg.Protected, &msg.Unprotected, &o.policy); err != nil {
		return nil, err
	}
	if err := bindAlg(&msg.Protected, &msg.Unprotected, alg, &o.policy); err != nil {
		return nil, err
	}

	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}

	aad, err := buildEncStructure(protectedBytes, o.externalAAD)
	if err != nil {
		return nil, err
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%w: nonce must be %d bytes", ErrDecryption, gcm.NonceSize())
	}

	plaintext, err := gcm.Open(nil, nonce, msg.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecryption
	}
	return plaintext, nil
}

// Enc_structure = ["Encrypt0", protectedBstr, externalAAD]  (RFC 9052 §5.3)
func buildEncStructure(protectedBytes, externalAAD []byte) ([]byte, error) {
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}
	if externalAAD == nil {
		externalAAD = []byte{}
	}
	arr := corecbor.MakeArray(
		corecbor.Text("Encrypt0"),
		corecbor.Bytes(protectedBytes),
		corecbor.Bytes(externalAAD),
	)
	enc := sharedEncoder
	return enc.Encode(nil, arr)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return gcm, nil
}

func validateAESGCMKey(alg Algorithm, key []byte) error {
	var expected int
	switch alg {
	case AlgA128GCM:
		expected = 16
	case AlgA192GCM:
		expected = 24
	case AlgA256GCM:
		expected = 32
	default:
		return fmt.Errorf("%w: %s is not an AES-GCM algorithm", ErrUnsupportedAlgorithm, alg)
	}
	if len(key) != expected {
		return fmt.Errorf("%w: key must be %d bytes for %s", ErrInvalidKey, expected, alg)
	}
	return nil
}
