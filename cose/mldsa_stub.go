// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

//go:build !go1.27

package cose

import (
	"crypto"
	"fmt"
)

// crypto/mldsa first ships in Go 1.27. Built with an older toolchain,
// ML-DSA algorithms and AKP keys return ErrUnsupportedAlgorithm.

const mldsaSupported = false

func mldsaAlgForPublic(crypto.PublicKey) (Algorithm, bool) { return 0, false }

func mldsaSign(_ crypto.Signer, alg Algorithm, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w: %s needs a Go 1.27+ toolchain", ErrUnsupportedAlgorithm, alg)
}

func mldsaVerify(_ crypto.PublicKey, alg Algorithm, _, _ []byte) error {
	return fmt.Errorf("%w: %s needs a Go 1.27+ toolchain", ErrUnsupportedAlgorithm, alg)
}

func mldsaPublicFromAKP(alg Algorithm, _ []byte) (crypto.PublicKey, error) {
	return nil, fmt.Errorf("%w: %s needs a Go 1.27+ toolchain", ErrUnsupportedAlgorithm, alg)
}

func mldsaSignerFromAKP(alg Algorithm, _, _ []byte) (crypto.Signer, error) {
	return nil, fmt.Errorf("%w: %s needs a Go 1.27+ toolchain", ErrUnsupportedAlgorithm, alg)
}

func mldsaAKPParams(any) (Algorithm, []byte, []byte, bool) { return 0, nil, nil, false }
