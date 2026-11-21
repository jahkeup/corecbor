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
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
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
