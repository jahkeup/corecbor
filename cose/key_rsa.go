// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
)

// RSA private-key members (RFC 8230 §4) beyond d.
const (
	keyLabelRSAP    int64 = -4
	keyLabelRSAQ    int64 = -5
	keyLabelRSADP   int64 = -6
	keyLabelRSADQ   int64 = -7
	keyLabelRSAQInv int64 = -8
)

// rsaSigner builds a two-prime RSA private key from RFC 8230 §4
// parameters (n, e, d, p, q; dP/dQ/qInv are recomputed) and validates it.
func (k *Key) rsaSigner() (crypto.Signer, error) {
	pubAny, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	pub := pubAny.(*rsa.PublicKey)
	d, okD := k.get(keyLabelRSAD).([]byte)
	p, okP := k.get(keyLabelRSAP).([]byte)
	q, okQ := k.get(keyLabelRSAQ).([]byte)
	if !okD {
		return nil, fmt.Errorf("%w: no private key material", ErrInvalidKey)
	}
	if !okP || !okQ {
		return nil, fmt.Errorf("%w: RSA private key needs p and q", ErrInvalidKey)
	}
	priv := &rsa.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(d),
		Primes:    []*big.Int{new(big.Int).SetBytes(p), new(big.Int).SetBytes(q)},
	}
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	priv.Precompute()
	return priv, nil
}

// ecdhToElliptic maps a NIST crypto/ecdh curve to its crypto/elliptic
// counterpart (nil for X25519).
func ecdhToElliptic(c ecdh.Curve) elliptic.Curve {
	switch c {
	case ecdh.P256():
		return elliptic.P256()
	case ecdh.P384():
		return elliptic.P384()
	case ecdh.P521():
		return elliptic.P521()
	}
	return nil
}

// setRSAPrivate stores a two-prime RSA private key's RFC 8230 members.
func (k *Key) setRSAPrivate(p *rsa.PrivateKey) error {
	if len(p.Primes) != 2 {
		return fmt.Errorf("%w: multi-prime RSA keys are not supported", ErrInvalidKey)
	}
	p.Precompute()
	k.set(keyLabelRSAD, p.D.Bytes())
	k.set(keyLabelRSAP, p.Primes[0].Bytes())
	k.set(keyLabelRSAQ, p.Primes[1].Bytes())
	k.set(keyLabelRSADP, p.Precomputed.Dp.Bytes())
	k.set(keyLabelRSADQ, p.Precomputed.Dq.Bytes())
	k.set(keyLabelRSAQInv, p.Precomputed.Qinv.Bytes())
	return nil
}
