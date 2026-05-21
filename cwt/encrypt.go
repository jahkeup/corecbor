// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"fmt"

	"github.com/jahkeup/corecbor/cose"
)

// Encrypt creates an encrypted CWT (COSE_Encrypt0-wrapped claims).
// The caller must supply a key appropriate for alg (e.g. 32 bytes for A256GCM)
// and a 12-byte nonce for AES-GCM algorithms.
func Encrypt(claims *ClaimsSet, key []byte, nonce []byte, alg cose.Algorithm) ([]byte, error) {
	payload, err := claims.Encode()
	if err != nil {
		return nil, err
	}

	msg, err := cose.EncryptEncrypt0(payload, key, nonce, alg)
	if err != nil {
		return nil, err
	}

	return cose.MarshalEncrypt0(msg)
}

// Decrypt decodes and decrypts an encrypted CWT, returning the embedded claims.
func Decrypt(data []byte, key []byte, nonce []byte, alg cose.Algorithm) (*ClaimsSet, error) {
	msg, err := cose.UnmarshalEncrypt0(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	plaintext, err := cose.DecryptEncrypt0(msg, key, nonce, alg)
	if err != nil {
		return nil, err
	}

	return DecodeClaimsSet(plaintext)
}

// MAC creates a MAC'd CWT (COSE_Mac0-wrapped claims).
// The caller must supply a key and an HMAC algorithm (e.g. AlgHMAC256).
func MAC(claims *ClaimsSet, key []byte, alg cose.Algorithm) ([]byte, error) {
	payload, err := claims.Encode()
	if err != nil {
		return nil, err
	}

	msg, err := cose.ComputeMAC0(payload, key, alg)
	if err != nil {
		return nil, err
	}

	return cose.MarshalMac0(msg)
}

// VerifyMAC verifies and decodes a MAC'd CWT, returning the embedded claims.
func VerifyMAC(data []byte, key []byte, alg cose.Algorithm) (*ClaimsSet, error) {
	msg, err := cose.UnmarshalMac0(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	if err := cose.VerifyMAC0(msg, key, alg); err != nil {
		return nil, err
	}

	return DecodeClaimsSet(msg.Payload)
}
