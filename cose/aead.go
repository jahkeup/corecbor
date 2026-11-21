// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/cipher"
	"fmt"

	"github.com/jahkeup/corecbor/cose/internal/aesccm"
)

// contentAEAD returns the AEAD for a COSE content-encryption algorithm:
// AES-GCM (RFC 9053 §4.1) or AES-CCM (§4.2). The key length must match
// the algorithm.
func contentAEAD(alg Algorithm, key []byte) (cipher.AEAD, error) {
	want := cekLenForAlg(alg)
	if want == 0 {
		return nil, fmt.Errorf("%w: %s is not a supported content-encryption algorithm", ErrUnsupportedAlgorithm, alg)
	}
	if len(key) != want {
		return nil, fmt.Errorf("%w: key must be %d bytes for %s", ErrInvalidKey, want, alg)
	}
	tag, nonce, ok := ccmParams(alg)
	if !ok {
		return newGCM(key)
	}
	a, err := aesccm.New(key, tag, nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return a, nil
}

// ccmParams returns the tag and nonce sizes of an AES-CCM algorithm
// (AES-CCM-L-M-K: L=16 → 13-byte nonce, L=64 → 7-byte nonce; M = tag
// bits).
func ccmParams(alg Algorithm) (tag, nonce int, ok bool) {
	switch alg {
	case AlgAESCCM_16_64_128, AlgAESCCM_16_64_256:
		return 8, 13, true
	case AlgAESCCM_64_64_128, AlgAESCCM_64_64_256:
		return 8, 7, true
	case AlgAESCCM_16_128_128, AlgAESCCM_16_128_256:
		return 16, 13, true
	case AlgAESCCM_64_128_128, AlgAESCCM_64_128_256:
		return 16, 7, true
	}
	return 0, 0, false
}
