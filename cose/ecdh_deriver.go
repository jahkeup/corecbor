// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/jahkeup/corecbor"
)

const (
	headerLabelEphemeralKey int64 = -1
	headerLabelSalt         int64 = -20
)

type ECDHESKey struct {
	PrivateKey *ecdh.PrivateKey
	PeerPublic *ecdh.PublicKey
}

func (e *ECDHESKey) Algorithm() Algorithm { return AlgECDH_ES_HKDF_256 }

func (e *ECDHESKey) WrapKey(cek []byte, opts KeyWrapOpts) ([]byte, Headers, error) {
	curve := e.PeerPublic.Curve()
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: generating ephemeral key: %v", ErrInvalidKey, err)
	}

	shared, err := ephemeral.ECDH(e.PeerPublic)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: ECDH failed: %v", ErrInvalidKey, err)
	}

	keyLen := opts.CEKLength
	if keyLen == 0 {
		keyLen = cekLenForAlg(opts.CEKAlgorithm)
	}
	if keyLen == 0 {
		return nil, Headers{}, fmt.Errorf("%w: cannot determine CEK length", ErrInvalidKey)
	}

	info, err := buildHKDFInfo(opts.CEKAlgorithm, keyLen)
	if err != nil {
		return nil, Headers{}, err
	}

	derived, err := hkdfDerive(shared, nil, info, keyLen)
	if err != nil {
		return nil, Headers{}, err
	}

	var h Headers
	h.Set(headerLabelEphemeralKey, ephemeral.PublicKey().Bytes())

	_ = cek
	_ = derived
	return nil, h, nil
}

func (e *ECDHESKey) UnwrapKey(_ []byte, h Headers, opts KeyUnwrapOpts) ([]byte, error) {
	ephBytes, ok := h.Get(headerLabelEphemeralKey).([]byte)
	if !ok || len(ephBytes) == 0 {
		return nil, fmt.Errorf("%w: missing ephemeral key in headers", ErrDecryption)
	}

	curve := e.PrivateKey.PublicKey().Curve()
	ephPub, err := curve.NewPublicKey(ephBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ephemeral key: %v", ErrDecryption, err)
	}

	shared, err := e.PrivateKey.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH failed: %v", ErrDecryption, err)
	}

	keyLen := opts.CEKLength
	if keyLen == 0 {
		keyLen = cekLenForAlg(opts.CEKAlgorithm)
	}
	if keyLen == 0 {
		return nil, fmt.Errorf("%w: cannot determine CEK length", ErrDecryption)
	}

	info, err := buildHKDFInfo(opts.CEKAlgorithm, keyLen)
	if err != nil {
		return nil, err
	}

	return hkdfDerive(shared, nil, info, keyLen)
}

// DeriveKey performs ECDH + HKDF to derive a key (for use in EncryptMulti).
func (e *ECDHESKey) DeriveKey(opts KeyWrapOpts) (cek []byte, headers Headers, err error) {
	curve := e.PeerPublic.Curve()
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: generating ephemeral key: %v", ErrInvalidKey, err)
	}

	shared, err := ephemeral.ECDH(e.PeerPublic)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: ECDH failed: %v", ErrInvalidKey, err)
	}

	keyLen := opts.CEKLength
	if keyLen == 0 {
		keyLen = cekLenForAlg(opts.CEKAlgorithm)
	}
	if keyLen == 0 {
		return nil, Headers{}, fmt.Errorf("%w: cannot determine CEK length", ErrInvalidKey)
	}

	info, err := buildHKDFInfo(opts.CEKAlgorithm, keyLen)
	if err != nil {
		return nil, Headers{}, err
	}

	derived, err := hkdfDerive(shared, nil, info, keyLen)
	if err != nil {
		return nil, Headers{}, err
	}

	var h Headers
	h.Set(headerLabelEphemeralKey, ephemeral.PublicKey().Bytes())
	return derived, h, nil
}

// UnderiveKey performs ECDH + HKDF to re-derive the CEK from the ephemeral key in headers.
func (e *ECDHESKey) UnderiveKey(h Headers, opts KeyUnwrapOpts) ([]byte, error) {
	return e.UnwrapKey(nil, h, opts)
}

func cekLenForAlg(alg Algorithm) int {
	switch alg {
	case AlgA128GCM:
		return 16
	case AlgA192GCM:
		return 24
	case AlgA256GCM:
		return 32
	default:
		return 0
	}
}

// HKDF info per RFC 9053 §5.1 (simplified):
// CBOR array: [AlgID, partyU (bstr), partyV (bstr), suppPub ([keyLength*8])]
func buildHKDFInfo(alg Algorithm, keyLen int) ([]byte, error) {
	arr := corecbor.Array{
		goToCBOR(int64(alg)),
		corecbor.Bytes(nil),
		corecbor.Bytes(nil),
		corecbor.Array{goToCBOR(int64(keyLen * 8))},
	}
	enc := sharedEncoder
	return enc.Encode(nil, arr)
}

func hkdfDerive(secret, salt, info []byte, keyLen int) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, salt, string(info), keyLen)
}
