// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdh"
	"crypto/hpke"
	"fmt"
)

// AlgHPKE_Base_P256_SHA256_AES128GCM is HPKE in base mode with
// DHKEM(P-256), HKDF-SHA256, AES-128-GCM.
const AlgHPKE_Base_P256_SHA256_AES128GCM Algorithm = 35

// HPKEKey implements KeyDeriver using HPKE (RFC 9180) for key encapsulation.
// WrapKey uses the recipient's public key to encapsulate the CEK.
// UnwrapKey uses our private key to decapsulate.
type HPKEKey struct {
	// PublicKey is the recipient's public key (used in WrapKey).
	PublicKey *ecdh.PublicKey
	// PrivateKey is our private key (used in UnwrapKey).
	PrivateKey *ecdh.PrivateKey
}

func (h *HPKEKey) Algorithm() Algorithm {
	return AlgHPKE_Base_P256_SHA256_AES128GCM
}

// WrapKey encapsulates cek using HPKE Seal. The entire sealed blob
// (enc || ciphertext) is returned as the recipient ciphertext.
func (h *HPKEKey) WrapKey(cek []byte, opts KeyWrapOpts) ([]byte, Headers, error) {
	if h.PublicKey == nil {
		return nil, Headers{}, fmt.Errorf("%w: HPKEKey.PublicKey is nil", ErrInvalidKey)
	}
	pub, err := hpke.NewDHKEMPublicKey(h.PublicKey)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	info := []byte(fmt.Sprintf("COSE-HPKE-CEK-%d", opts.CEKAlgorithm))
	sealed, err := hpke.Seal(pub, hpke.HKDFSHA256(), hpke.AES128GCM(), info, cek)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("cose: HPKE seal failed: %w", err)
	}
	return sealed, Headers{}, nil
}

// UnwrapKey decapsulates the CEK from the sealed blob using HPKE Open.
func (h *HPKEKey) UnwrapKey(ciphertext []byte, hdrs Headers, opts KeyUnwrapOpts) ([]byte, error) {
	if h.PrivateKey == nil {
		return nil, fmt.Errorf("%w: HPKEKey.PrivateKey is nil", ErrInvalidKey)
	}
	priv, err := hpke.NewDHKEMPrivateKey(h.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	info := []byte(fmt.Sprintf("COSE-HPKE-CEK-%d", opts.CEKAlgorithm))
	cek, err := hpke.Open(priv, hpke.HKDFSHA256(), hpke.AES128GCM(), info, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: HPKE open failed", ErrDecryption)
	}
	return cek, nil
}
