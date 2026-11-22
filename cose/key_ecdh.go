// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"fmt"
)

// NewKeyFromECDH returns a COSE_Key holding priv and its public part:
// OKP X25519 (crv 4) for ecdh.X25519, and EC2 for the NIST curves
// (P-256, P-384, P-521), with coordinates and d at the curve's exact
// size. crypto/ecdh keys are always valid points, so no further checks
// apply. Public-only keys go through NewKeyFromPublic, which accepts
// *ecdh.PublicKey.
func NewKeyFromECDH(priv *ecdh.PrivateKey) (*Key, error) {
	if priv == nil {
		return nil, fmt.Errorf("%w: nil ECDH private key", ErrInvalidKey)
	}
	k, err := NewKeyFromPublic(priv.PublicKey())
	if err != nil {
		return nil, err
	}
	// ecdh.PrivateKey.Bytes is the fixed-size NIST scalar or the 32-byte
	// X25519 private key, which is exactly COSE's d.
	k.set(keyLabelD, priv.Bytes())
	return k, nil
}

// ECDHPublicKey returns the key's public part as a crypto/ecdh key, for
// key agreement: OKP X25519, or EC2 on P-256, P-384 or P-521. Other key
// types and curves are ErrInvalidKey. For EC2 keys this is the same
// point PublicKey returns as an *ecdsa.PublicKey.
func (k *Key) ECDHPublicKey() (*ecdh.PublicKey, error) {
	if err := k.hasECDHForm(); err != nil {
		return nil, err
	}
	pk, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	switch pub := pk.(type) {
	case *ecdh.PublicKey:
		return pub, nil
	case *ecdsa.PublicKey:
		e, err := pub.ECDH()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		return e, nil
	default:
		return nil, fmt.Errorf("%w: %T has no ECDH form", ErrInvalidKey, pk)
	}
}

// ECDHPrivateKey returns the key's private part as a crypto/ecdh key:
// OKP X25519, or EC2 on P-256, P-384 or P-521. If the key also carries
// its public part, the two must match (ErrInvalidKey otherwise). It does
// not check key_ops; callers with a usage policy check Permits.
func (k *Key) ECDHPrivateKey() (*ecdh.PrivateKey, error) {
	if err := k.hasECDHForm(); err != nil {
		return nil, err
	}
	curve, err := coseCurveToECDH(k.Curve())
	if err != nil {
		return nil, err
	}
	d, ok := k.bytesParam(keyLabelD)
	if !ok {
		return nil, fmt.Errorf("%w: no private key material", ErrInvalidKey)
	}
	priv, err := curve.NewPrivateKey(d)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	if _, hasX := k.bytesParam(keyLabelX); hasX {
		pub, err := k.ECDHPublicKey()
		if err != nil {
			return nil, err
		}
		if !pub.Equal(priv.PublicKey()) {
			return nil, fmt.Errorf("%w: private key doesn't match its public key", ErrInvalidKey)
		}
	}
	return priv, nil
}

// hasECDHForm reports whether k's kty and curve have a crypto/ecdh form.
func (k *Key) hasECDHForm() error {
	switch k.KeyType() {
	case KeyTypeOKP:
		if k.Curve() != CurveX25519 {
			return fmt.Errorf("%w: OKP curve %d has no ECDH form", ErrInvalidKey, k.Curve())
		}
		return nil
	case KeyTypeEC2:
		_, err := coseCurveToECDH(k.Curve())
		return err
	default:
		return fmt.Errorf("%w: key type %d has no ECDH form", ErrInvalidKey, k.KeyType())
	}
}
