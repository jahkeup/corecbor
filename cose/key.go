// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
)

// COSE Key parameter labels (RFC 9052 / RFC 9053).
const (
	keyLabelKty int64 = 1
	keyLabelKid int64 = 2
	keyLabelAlg int64 = 3
	keyLabelCrv int64 = -1
	keyLabelX   int64 = -2
	keyLabelY   int64 = -3
	keyLabelD   int64 = -4
)

type KeyType int64

const (
	KeyTypeOKP       KeyType = 1
	KeyTypeEC2       KeyType = 2
	KeyTypeSymmetric KeyType = 4
)

type Curve int64

const (
	CurveP256    Curve = 1
	CurveP384    Curve = 2
	CurveP521    Curve = 3
	CurveX25519  Curve = 4
	CurveEd25519 Curve = 6
)

// Key is a COSE_Key represented as a map of integer labels to values.
type Key struct {
	params map[int64]any
}

func (k *Key) get(label int64) any {
	if k.params == nil {
		return nil
	}
	return k.params[label]
}

func (k *Key) set(label int64, v any) {
	if k.params == nil {
		k.params = make(map[int64]any)
	}
	k.params[label] = v
}

func (k *Key) KeyType() KeyType {
	v, _ := k.get(keyLabelKty).(int64)
	return KeyType(v)
}

func (k *Key) Curve() Curve {
	v, _ := k.get(keyLabelCrv).(int64)
	return Curve(v)
}

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
		x := padLeft(p.X.Bytes(), size)
		y := padLeft(p.Y.Bytes(), size)
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
		k.set(keyLabelD, padLeft(p.D.Bytes(), size))
	default:
		return nil, fmt.Errorf("%w: unsupported signer type %T", ErrInvalidKey, s)
	}
	return k, nil
}

func (k *Key) PublicKey() (crypto.PublicKey, error) {
	kty := k.KeyType()
	switch kty {
	case KeyTypeOKP:
		crv := k.Curve()
		if crv != CurveEd25519 {
			return nil, fmt.Errorf("%w: unsupported OKP curve %d", ErrInvalidKey, crv)
		}
		x, ok := k.get(keyLabelX).([]byte)
		if !ok || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: invalid Ed25519 public key", ErrInvalidKey)
		}
		return ed25519.PublicKey(x), nil

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
		// Build uncompressed point: 0x04 || X || Y
		size := curveKeySize(goCrv)
		point := make([]byte, 1+2*size)
		point[0] = 0x04
		copy(point[1:1+size], padLeft(x, size))
		copy(point[1+size:], padLeft(y, size))
		pub, err := ecdsa.ParseUncompressedPublicKey(goCrv, point)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		return pub, nil

	default:
		return nil, fmt.Errorf("%w: unsupported key type %d", ErrInvalidKey, kty)
	}
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
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		return priv, nil

	default:
		return nil, fmt.Errorf("%w: unsupported key type %d", ErrInvalidKey, kty)
	}
}

func goCurveToOse(c elliptic.Curve) (Curve, error) {
	switch c {
	case elliptic.P256():
		return CurveP256, nil
	case elliptic.P384():
		return CurveP384, nil
	case elliptic.P521():
		return CurveP521, nil
	default:
		return 0, fmt.Errorf("%w: unsupported elliptic curve", ErrInvalidKey)
	}
}

func coseCurveToGo(c Curve) (elliptic.Curve, error) {
	switch c {
	case CurveP256:
		return elliptic.P256(), nil
	case CurveP384:
		return elliptic.P384(), nil
	case CurveP521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: unsupported COSE curve %d", ErrInvalidKey, c)
	}
}

func curveKeySize(c elliptic.Curve) int {
	return (c.Params().BitSize + 7) / 8
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
