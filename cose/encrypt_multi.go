// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/rand"
	"fmt"

	"github.com/jahkeup/corecbor"
)

// EncryptMulti encrypts plaintext into a COSE_Encrypt for recipients.
// contentAlg is AES-GCM or AES-CCM. A random content key is wrapped for
// each recipient, except with a single direct recipient: a DirectKey
// (alg direct, RFC 9052 §8.5.1), whose key is the content key, or direct
// key agreement (ECDH-ES + HKDF, -25/-26), whose agreed key is
// (§8.5.4). A direct recipient alongside others is ErrInvalidKey. The IV is random and carried in header 5.
func EncryptMulti(plaintext []byte, contentAlg Algorithm, recipients []KeyDeriver, opts ...EncryptOption) (*Encrypt, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("%w: at least one recipient required", ErrInvalidKey)
	}

	var o encryptOpts
	for _, opt := range opts {
		opt(&o)
	}

	cekLen := cekLenForAlg(contentAlg)
	if cekLen == 0 {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, contentAlg)
	}

	dcek, dr, directEnc, err := directEncryption(recipients, contentAlg, cekLen)
	if err != nil {
		return nil, err
	}
	ka, direct, err := directAgreement(recipients, o.legacy)
	if err != nil {
		return nil, err
	}
	msg := &Encrypt{}
	var cek []byte
	switch {
	case directEnc:
		cek = dcek
		msg.Recipients = []Recipient{dr}
		direct = true
	case direct:
		var r Recipient
		cek, r, err = agreeRecipient(ka, contentAlg, cekLen)
		if err != nil {
			return nil, err
		}
		msg.Recipients = []Recipient{r}
	default:
		cek = make([]byte, cekLen)
		if _, err := rand.Read(cek); err != nil {
			return nil, fmt.Errorf("generating CEK: %w", err)
		}
	}

	msg.Protected.SetAlgorithm(contentAlg)
	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	aad, err := buildEncStructureMulti(protectedBytes, o.externalAAD)
	if err != nil {
		return nil, err
	}

	aead, err := contentAEAD(contentAlg, cek)
	if err != nil {
		return nil, err
	}
	nonce, err := sealNonce(aead, &msg.Unprotected, &encryptOpts{nonce: o.nonce, baseIV: o.baseIV, partialIV: o.partialIV})
	if err != nil {
		return nil, err
	}
	msg.Ciphertext = aead.Seal(nil, nonce, plaintext, aad)

	if !direct {
		msg.Recipients, err = sealRecipients(cek, contentAlg, recipients, o.legacy)
		if err != nil {
			return nil, err
		}
	}
	return msg, nil
}

// DecryptMulti decrypts a COSE_Encrypt message with the key recovered by
// recipient. The content algorithm comes from the protected header and
// must be in the allowed set (AES-GCM 128/192/256 unless
// WithEncryptAlgorithms says otherwise, for example to allow AES-CCM).
// The recipient's alg must match recipient's algorithm.
// WithEncryptExternalAAD supplies the external AAD the sender used.
func DecryptMulti(msg *Encrypt, recipient KeyDeriver, recipientIndex int, opts ...EncryptOption) ([]byte, error) {
	if recipientIndex < 0 || recipientIndex >= len(msg.Recipients) {
		return nil, fmt.Errorf("%w: recipient index out of range", ErrDecryption)
	}
	return decryptMultiPath(msg, recipient, []int{recipientIndex}, opts)
}

// DecryptMultiNested is DecryptMulti for a recipient nested under others
// (RFC 9052 §5.1, Appendix B). path[0] indexes msg.Recipients, path[1]
// that recipient's Recipients, and so on; recipient opens the last one.
// The key it recovers is the key of the layer above, which is opened
// with it, up to the content key. A layer above the last must be AES
// key wrap (A128KW, A192KW, A256KW) or direct; others are
// ErrUnsupportedAlgorithm. Each layer's headers are checked as
// DecryptMulti checks a recipient's. A path that doesn't name a
// recipient is ErrDecryption.
func DecryptMultiNested(msg *Encrypt, recipient KeyDeriver, path []int, opts ...EncryptOption) ([]byte, error) {
	return decryptMultiPath(msg, recipient, path, opts)
}

func decryptMultiPath(msg *Encrypt, recipient KeyDeriver, path []int, opts []EncryptOption) ([]byte, error) {
	layers, err := recipientPath(msg.Recipients, path)
	if err != nil {
		return nil, err
	}
	var o encryptOpts
	for _, opt := range opts {
		opt(&o)
	}

	if err := checkCrit(&msg.Protected, &msg.Unprotected, &o.policy); err != nil {
		return nil, err
	}
	contentAlg, err := multiAlg(&msg.Protected, &msg.Unprotected, &o.policy, defaultEncryptMultiAlgs)
	if err != nil {
		return nil, err
	}
	cekLen := cekLenForAlg(contentAlg)
	if cekLen == 0 {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, contentAlg)
	}

	cek, err := openRecipientPath(layers, recipient, contentAlg, cekLen, &o)
	if err != nil {
		return nil, err
	}

	aead, err := contentAEAD(contentAlg, cek)
	if err != nil {
		return nil, ErrDecryption
	}
	nonce, err := openNonce(aead, &msg.Protected, &msg.Unprotected, &o)
	if err != nil {
		return nil, err
	}

	protectedBytes, err := msg.Protected.authProtected(&o.policy)
	if err != nil {
		return nil, err
	}
	aad, err := buildEncStructureMulti(protectedBytes, o.externalAAD)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, msg.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecryption
	}
	return plaintext, nil
}

func buildEncStructureMulti(protectedBytes, externalAAD []byte) ([]byte, error) {
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}
	if externalAAD == nil {
		externalAAD = []byte{}
	}
	arr := corecbor.MakeArray(
		corecbor.Text("Encrypt"),
		corecbor.Bytes(protectedBytes),
		corecbor.Bytes(externalAAD),
	)
	enc := sharedEncoder
	return enc.Encode(nil, arr)
}
