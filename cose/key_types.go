// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
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
