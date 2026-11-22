// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

//go:build go1.27

package cose

import (
	"crypto"
	"crypto/mldsa"
	"fmt"
)

// ML-DSA (RFC 9964) via crypto/mldsa, which first ships in Go 1.27. The
// signature is over the COSE ToBeSigned bytes directly, with an empty
// context (RFC 9964 §4); private keys are 32-byte seeds.

func mldsaParams(alg Algorithm) (mldsa.Parameters, bool) {
	switch alg {
	case AlgMLDSA44:
		return mldsa.MLDSA44(), true
	case AlgMLDSA65:
		return mldsa.MLDSA65(), true
	case AlgMLDSA87:
		return mldsa.MLDSA87(), true
	}
	return mldsa.Parameters{}, false
}

func mldsaAlgForParams(p mldsa.Parameters) (Algorithm, bool) {
	for _, a := range []Algorithm{AlgMLDSA44, AlgMLDSA65, AlgMLDSA87} {
		if q, _ := mldsaParams(a); q == p {
			return a, true
		}
	}
	return 0, false
}

func mldsaAlgForPublic(pub crypto.PublicKey) (Algorithm, bool) {
	p, ok := pub.(*mldsa.PublicKey)
	if !ok || p == nil {
		return 0, false
	}
	return mldsaAlgForParams(p.Parameters())
}

func mldsaSign(key crypto.Signer, alg Algorithm, data []byte) ([]byte, error) {
	if a, ok := mldsaAlgForPublic(key.Public()); !ok || a != alg {
		return nil, fmt.Errorf("%w: %s needs a matching ML-DSA key", ErrInvalidKey, alg)
	}
	// Empty context and no pre-hash (RFC 9964 §4); the rand argument is
	// ignored by ML-DSA's hedged signing.
	sig, err := key.Sign(nil, data, &mldsa.Options{})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return sig, nil
}

func mldsaVerify(key crypto.PublicKey, alg Algorithm, data, sig []byte) error {
	pub, ok := key.(*mldsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: %s needs an ML-DSA key", ErrAlgorithmMismatch, alg)
	}
	if a, _ := mldsaAlgForParams(pub.Parameters()); a != alg {
		return fmt.Errorf("%w: header alg %s, key is %s", ErrAlgorithmMismatch, alg, a)
	}
	if err := mldsa.Verify(pub, data, sig, &mldsa.Options{}); err != nil {
		return ErrVerification
	}
	return nil
}

// mldsaPublicFromAKP builds the public key of an AKP key with alg.
func mldsaPublicFromAKP(alg Algorithm, pub []byte) (crypto.PublicKey, error) {
	p, ok := mldsaParams(alg)
	if !ok {
		return nil, fmt.Errorf("%w: AKP alg %s", ErrUnsupportedAlgorithm, alg)
	}
	k, err := mldsa.NewPublicKey(p, pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return k, nil
}

// mldsaSignerFromAKP builds the private key of an AKP key from its seed.
// When pub is present it must be the seed's public key (RFC 9964 §3).
func mldsaSignerFromAKP(alg Algorithm, seed, pub []byte) (crypto.Signer, error) {
	p, ok := mldsaParams(alg)
	if !ok {
		return nil, fmt.Errorf("%w: AKP alg %s", ErrUnsupportedAlgorithm, alg)
	}
	if len(seed) != mldsa.PrivateKeySize {
		return nil, fmt.Errorf("%w: ML-DSA priv must be a %d-byte seed", ErrInvalidKey, mldsa.PrivateKeySize)
	}
	k, err := mldsa.NewPrivateKey(p, seed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	if pub != nil {
		want, err := mldsa.NewPublicKey(p, pub)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		if !k.PublicKey().Equal(want) {
			return nil, fmt.Errorf("%w: AKP pub does not match priv", ErrInvalidKey)
		}
	}
	return k, nil
}

// mldsaAKPParams returns the alg and pub (and seed, for a private key)
// of an ML-DSA Go key, for building a COSE_Key.
func mldsaAKPParams(key any) (alg Algorithm, pub, seed []byte, ok bool) {
	switch k := key.(type) {
	case *mldsa.PublicKey:
		a, ok := mldsaAlgForParams(k.Parameters())
		return a, k.Bytes(), nil, ok
	case *mldsa.PrivateKey:
		a, ok := mldsaAlgForParams(k.PublicKey().Parameters())
		return a, k.PublicKey().Bytes(), k.Bytes(), ok
	}
	return 0, nil, nil, false
}
