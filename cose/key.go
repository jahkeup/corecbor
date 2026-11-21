// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"math"
	"math/big"
)

func NewKeyFromPublic(pub crypto.PublicKey) (*Key, error) {
	k := &Key{params: make(map[int64]any)}
	switch p := pub.(type) {
	case ed25519.PublicKey:
		k.set(keyLabelKty, int64(KeyTypeOKP))
		k.set(keyLabelCrv, int64(CurveEd25519))
		k.set(keyLabelX, []byte(p))
	case *ecdsa.PublicKey:
		k.set(keyLabelKty, int64(KeyTypeEC2))
		crv, err := goCurveToOse(p.Curve)
		if err != nil {
			return nil, err
		}
		k.set(keyLabelCrv, int64(crv))
		size := curveKeySize(p.Curve)
		raw, err := p.Bytes()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		// raw is uncompressed: 0x04 || X || Y
		x := padLeft(raw[1:1+size], size)
		y := padLeft(raw[1+size:], size)
		k.set(keyLabelX, x)
		k.set(keyLabelY, y)
	default:
		return nil, fmt.Errorf("%w: unsupported public key type %T", ErrInvalidKey, pub)
	}
	return k, nil
}

func NewKeyFromSigner(s crypto.Signer) (*Key, error) {
	k, err := NewKeyFromPublic(s.Public())
	if err != nil {
		return nil, err
	}
	switch p := s.(type) {
	case ed25519.PrivateKey:
		k.set(keyLabelD, []byte(p.Seed()))
	case *ecdsa.PrivateKey:
		size := curveKeySize(p.Curve)
		d, err := p.Bytes()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		k.set(keyLabelD, padLeft(d, size))
	default:
		return nil, fmt.Errorf("%w: unsupported signer type %T", ErrInvalidKey, s)
	}
	return k, nil
}

// PublicKey returns the key's public part as a Go key:
// ed25519.PublicKey (OKP Ed25519), *ecdh.PublicKey (OKP X25519),
// *ecdsa.PublicKey (EC2) or *rsa.PublicKey (RSA). EC2 coordinates
// shorter than the curve size are left-padded, as in v0.2.2; longer ones
// are ErrInvalidKey (v0.2.2 silently truncated them into a different
// point).
func (k *Key) PublicKey() (crypto.PublicKey, error) {
	kty := k.KeyType()
	switch kty {
	case KeyTypeOKP:
		crv := k.Curve()
		x, ok := k.get(keyLabelX).([]byte)
		switch crv {
		case CurveEd25519:
			if !ok || len(x) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("%w: invalid Ed25519 public key", ErrInvalidKey)
			}
			return ed25519.PublicKey(x), nil
		case CurveX25519:
			if !ok {
				return nil, fmt.Errorf("%w: missing X25519 x", ErrInvalidKey)
			}
			pub, err := ecdh.X25519().NewPublicKey(x)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
			}
			return pub, nil
		default:
			return nil, fmt.Errorf("%w: unsupported OKP curve %d", ErrInvalidKey, crv)
		}

	case KeyTypeRSA:
		n, okN := k.get(keyLabelRSAN).([]byte)
		e, okE := k.get(keyLabelRSAE).([]byte)
		if !okN || !okE {
			return nil, fmt.Errorf("%w: RSA key needs n and e", ErrInvalidKey)
		}
		ei := new(big.Int).SetBytes(e)
		if !ei.IsInt64() || ei.Int64() < 3 || ei.Int64() > math.MaxInt32 {
			return nil, fmt.Errorf("%w: invalid RSA public exponent", ErrInvalidKey)
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(ei.Int64())}
		if pub.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("%w: RSA modulus is %d bits, want at least %d", ErrInvalidKey, pub.N.BitLen(), minRSABits)
		}
		return pub, nil

	case KeyTypeEC2:
		crv := k.Curve()
		goCrv, err := coseCurveToGo(crv)
		if err != nil {
			return nil, err
		}
		x, ok := k.get(keyLabelX).([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: missing EC2 x coordinate", ErrInvalidKey)
		}
		y, ok := k.get(keyLabelY).([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: missing EC2 y coordinate", ErrInvalidKey)
		}
		size := curveKeySize(goCrv)
		if len(x) > size || len(y) > size {
			return nil, fmt.Errorf("%w: EC2 coordinate longer than %d bytes", ErrInvalidKey, size)
		}
		point := make([]byte, 1+2*size)
		point[0] = 0x04
		copy(point[1:1+size], padLeft(x, size))
		copy(point[1+size:], padLeft(y, size))
		pub, err := ecdsa.ParseUncompressedPublicKey(goCrv, point)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		return pub, nil

	default:
		return nil, fmt.Errorf("%w: unsupported key type %d", ErrInvalidKey, kty)
	}
}

// ed25519PublicFromSeed returns the Ed25519 public key for a 32-byte seed.
func ed25519PublicFromSeed(seed []byte) []byte {
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

func (k *Key) Signer() (crypto.Signer, error) {
	d, ok := k.get(keyLabelD).([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: no private key material", ErrInvalidKey)
	}

	kty := k.KeyType()
	switch kty {
	case KeyTypeOKP:
		crv := k.Curve()
		if crv != CurveEd25519 {
			return nil, fmt.Errorf("%w: unsupported OKP curve %d", ErrInvalidKey, crv)
		}
		if len(d) != ed25519.SeedSize {
			return nil, fmt.Errorf("%w: invalid Ed25519 seed length", ErrInvalidKey)
		}
		return ed25519.NewKeyFromSeed(d), nil

	case KeyTypeEC2:
		crv := k.Curve()
		goCrv, err := coseCurveToGo(crv)
		if err != nil {
			return nil, err
		}
		priv, err := ecdsa.ParseRawPrivateKey(goCrv, d)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		return priv, nil

	default:
		return nil, fmt.Errorf("%w: unsupported key type %d", ErrInvalidKey, kty)
	}
}
