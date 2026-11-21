// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"slices"
)

// Encrypt0Seal encrypts plaintext into a COSE_Encrypt0 with key and alg
// (AES-GCM or AES-CCM). The IV is generated randomly at the AEAD's nonce
// size and carried in the unprotected IV header (5), so the recipient
// needs nothing but the key; WithPartialIV writes a Partial IV (6)
// instead, and WithNonce fixes the IV for test vectors.
// WithEncryptExternalAAD binds external data.
//
// Encrypt0Seal is the recommended replacement for EncryptEncrypt0, which
// takes a caller-managed nonce and never transmits it.
func Encrypt0Seal(plaintext, key []byte, alg Algorithm, opts ...EncryptOption) (*Encrypt0, error) {
	var o encryptOpts
	for _, opt := range opts {
		opt(&o)
	}
	aead, err := contentAEAD(alg, key)
	if err != nil {
		return nil, err
	}
	msg := &Encrypt0{}
	msg.Protected.SetAlgorithm(alg)
	nonce, err := sealNonce(aead, &msg.Unprotected, &o)
	if err != nil {
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
	msg.Ciphertext = aead.Seal(nil, nonce, plaintext, aad)
	return msg, nil
}

// Encrypt0Open decrypts a COSE_Encrypt0 with key. The content algorithm
// is the message's protected alg and must be AES-GCM 128/192/256 unless
// WithEncryptAlgorithms allows others (such as AES-CCM). The IV comes
// from the message: its IV header (5), or its Partial IV (6) combined
// with the Base IV given by WithPartialIV. A message carrying both is
// ErrMalformed (RFC 9052 §3.1).
func Encrypt0Open(msg *Encrypt0, key []byte, opts ...EncryptOption) ([]byte, error) {
	var o encryptOpts
	for _, opt := range opts {
		opt(&o)
	}
	if err := checkCrit(&msg.Protected, &msg.Unprotected, &o.policy); err != nil {
		return nil, err
	}
	alg, err := multiAlg(&msg.Protected, &msg.Unprotected, &o.policy, defaultEncryptMultiAlgs)
	if err != nil {
		return nil, err
	}
	aead, err := contentAEAD(alg, key)
	if err != nil {
		return nil, err
	}
	nonce, err := openNonce(aead, &msg.Protected, &msg.Unprotected, &o)
	if err != nil {
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
	plaintext, err := aead.Open(nil, nonce, msg.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecryption
	}
	return plaintext, nil
}

// sealNonce picks the IV for a new message and records it in unprot:
// WithPartialIV → Partial IV header and Base IV XOR Partial IV;
// WithNonce → that nonce in the IV header; otherwise a random IV.
func sealNonce(aead cipher.AEAD, unprot *Headers, o *encryptOpts) ([]byte, error) {
	size := aead.NonceSize()
	switch {
	case o.partialIV != nil:
		nonce, err := partialIVNonce(o.baseIV, o.partialIV, size)
		if err != nil {
			return nil, err
		}
		setParam(unprot, headerLabelPartialIV, slices.Clone(o.partialIV))
		return nonce, nil
	case o.nonce != nil:
		if len(o.nonce) != size {
			return nil, fmt.Errorf("%w: nonce must be %d bytes", ErrInvalidKey, size)
		}
		setParam(unprot, headerLabelIV, slices.Clone(o.nonce))
		return o.nonce, nil
	default:
		nonce := make([]byte, size)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generating IV: %w", err)
		}
		setParam(unprot, headerLabelIV, nonce)
		return nonce, nil
	}
}

// openNonce recovers a message's IV from its IV or Partial IV header
// (either bucket).
func openNonce(aead cipher.AEAD, prot, unprot *Headers, o *encryptOpts) ([]byte, error) {
	iv, hasIV := headerBytes(prot, unprot, headerLabelIV)
	piv, hasPIV := headerBytes(prot, unprot, headerLabelPartialIV)
	size := aead.NonceSize()
	switch {
	case hasIV && hasPIV:
		return nil, fmt.Errorf("%w: both IV and Partial IV present (RFC 9052 §3.1)", ErrMalformed)
	case hasIV:
		if len(iv) != size {
			return nil, fmt.Errorf("%w: IV must be %d bytes", ErrDecryption, size)
		}
		return iv, nil
	case hasPIV:
		if o.baseIV == nil {
			return nil, fmt.Errorf("%w: Partial IV present but no Base IV (WithPartialIV)", ErrDecryption)
		}
		return partialIVNonce(o.baseIV, piv, size)
	default:
		return nil, fmt.Errorf("%w: missing IV in message", ErrDecryption)
	}
}

// partialIVNonce builds the RFC 9052 §3.1 nonce: Partial IV left-padded
// with zeros to the nonce length, XORed with the Base IV.
func partialIVNonce(baseIV, partialIV []byte, size int) ([]byte, error) {
	if len(baseIV) != size {
		return nil, fmt.Errorf("%w: Base IV must be %d bytes", ErrInvalidKey, size)
	}
	if len(partialIV) == 0 || len(partialIV) > size {
		return nil, fmt.Errorf("%w: Partial IV must be 1 to %d bytes", ErrInvalidKey, size)
	}
	nonce := slices.Clone(baseIV)
	off := size - len(partialIV)
	for i, b := range partialIV {
		nonce[off+i] ^= b
	}
	return nonce, nil
}

// headerBytes returns a byte-string parameter from either bucket.
func headerBytes(prot, unprot *Headers, label int64) ([]byte, bool) {
	if v, ok := prot.params[label].([]byte); ok {
		return v, true
	}
	if v, ok := unprot.params[label].([]byte); ok {
		return v, true
	}
	return nil, false
}

// setParam sets one header parameter, allocating the map if needed.
func setParam(h *Headers, label int64, v any) {
	if h.params == nil {
		h.params = make(map[any]any, 1)
	}
	h.params[label] = v
	h.raw = nil
}
