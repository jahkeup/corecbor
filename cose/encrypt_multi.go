// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/rand"
	"fmt"

	"github.com/jahkeup/corecbor"
)

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

	cek := make([]byte, cekLen)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("generating CEK: %v", err)
	}

	msg := &Encrypt{}
	msg.Protected.SetAlgorithm(contentAlg)

	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}

	aad, err := buildEncStructureMulti(protectedBytes, o.externalAAD)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %v", err)
	}
	msg.Unprotected.Set(int64(5), nonce)

	gcm, err := newGCM(cek)
	if err != nil {
		return nil, err
	}
	msg.Ciphertext = gcm.Seal(nil, nonce, plaintext, aad)

	wrapOpts := KeyWrapOpts{CEKAlgorithm: contentAlg, CEKLength: cekLen}
	msg.Recipients = make([]Recipient, len(recipients))

	for i, r := range recipients {
		var recipCek []byte
		if _, ok := r.(*ECDHESKey); ok {
			ek := r.(*ECDHESKey)
			derived, headers, err := ek.DeriveKey(wrapOpts)
			if err != nil {
				return nil, fmt.Errorf("recipient %d: %w", i, err)
			}
			_ = derived
			wrappedCek, wrapErr := aeskwWrapWithDerived(derived, cek)
			if wrapErr != nil {
				return nil, fmt.Errorf("recipient %d: %w", i, wrapErr)
			}
			msg.Recipients[i] = Recipient{
				Unprotected: headers,
				Ciphertext:  wrappedCek,
			}
			msg.Recipients[i].Protected.SetAlgorithm(r.Algorithm())
		} else {
			recipCek = cek
			ciphertext, headers, err := r.WrapKey(recipCek, wrapOpts)
			if err != nil {
				return nil, fmt.Errorf("recipient %d: %w", i, err)
			}
			msg.Recipients[i] = Recipient{
				Unprotected: headers,
				Ciphertext:  ciphertext,
			}
			msg.Recipients[i].Protected.SetAlgorithm(r.Algorithm())
		}
	}

	return msg, nil
}

func DecryptMulti(msg *Encrypt, recipient KeyDeriver, recipientIndex int) ([]byte, error) {
	if recipientIndex < 0 || recipientIndex >= len(msg.Recipients) {
		return nil, fmt.Errorf("%w: recipient index out of range", ErrDecryption)
	}

	r := msg.Recipients[recipientIndex]
	contentAlg := msg.Protected.Algorithm()
	cekLen := cekLenForAlg(contentAlg)
	if cekLen == 0 {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, contentAlg)
	}

	unwrapOpts := KeyUnwrapOpts{CEKAlgorithm: contentAlg, CEKLength: cekLen}

	var cek []byte
	var err error

	if ek, ok := recipient.(*ECDHESKey); ok {
		derived, derr := ek.UnderiveKey(r.Unprotected, unwrapOpts)
		if derr != nil {
			return nil, derr
		}
		cek, err = aeskwUnwrapWithDerived(derived, r.Ciphertext)
		if err != nil {
			return nil, ErrDecryption
		}
	} else {
		cek, err = recipient.UnwrapKey(r.Ciphertext, r.Unprotected, unwrapOpts)
		if err != nil {
			return nil, err
		}
	}

	nonce, ok := msg.Unprotected.Get(int64(5)).([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: missing IV in message", ErrDecryption)
	}

	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}

	aad, err := buildEncStructureMulti(protectedBytes, nil)
	if err != nil {
		return nil, err
	}

	gcm, err := newGCM(cek)
	if err != nil {
		return nil, ErrDecryption
	}

	plaintext, err := gcm.Open(nil, nonce, msg.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecryption
	}
	return plaintext, nil
}

func aeskwWrapWithDerived(derived, cek []byte) ([]byte, error) {
	kw := &AESKWKey{Key: derived}
	wrapped, _, err := kw.WrapKey(cek, KeyWrapOpts{})
	return wrapped, err
}

func aeskwUnwrapWithDerived(derived, ciphertext []byte) ([]byte, error) {
	kw := &AESKWKey{Key: derived}
	return kw.UnwrapKey(ciphertext, Headers{}, KeyUnwrapOpts{})
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
