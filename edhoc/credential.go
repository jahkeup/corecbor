// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
)

type CredentialType int

const (
	CredentialRPK CredentialType = iota
	CredentialCWT
)

type Credential struct {
	Type     CredentialType
	CWTBytes []byte
}

const claimCnf = 8

func encodeIDCredCWT(cwtBytes []byte) ([]byte, error) {
	return cborEncodeValue(nil, cbor.Bytes(cwtBytes))
}

func extractPublicKeyFromCWT(cwtBytes []byte, issuerPub crypto.PublicKey) (crypto.PublicKey, error) {
	verifier, err := cose.NewVerifier(issuerPub)
	if err != nil {
		return nil, fmt.Errorf("%w: creating CWT verifier: %v", ErrAuthentication, err)
	}

	claims, err := cwt.Verify(cwtBytes, verifier)
	if err != nil {
		return nil, fmt.Errorf("%w: CWT verification failed: %v", ErrAuthentication, err)
	}

	if claims.Confirmation != nil && claims.Confirmation.Key != nil {
		return claims.Confirmation.Key.PublicKey()
	}

	cnfVal, ok := claims.Private[int64(claimCnf)]
	if !ok {
		return nil, fmt.Errorf("%w: CWT missing cnf claim", ErrMessageFormat)
	}

	cnfMap, err := valueToMap(cnfVal)
	if err != nil {
		return nil, fmt.Errorf("%w: cnf claim: %v", ErrMessageFormat, err)
	}

	coseKeyVal, ok := cnfMap[int64(1)]
	if !ok {
		return nil, fmt.Errorf("%w: cnf missing COSE_Key (key 1)", ErrMessageFormat)
	}

	coseKeyMap, err := valueToMap(coseKeyVal)
	if err != nil {
		return nil, fmt.Errorf("%w: COSE_Key: %v", ErrMessageFormat, err)
	}

	return coseKeyMapToPublicKey(coseKeyMap)
}

func valueToMap(v any) (map[int64]any, error) {
	switch m := v.(type) {
	case cbor.Value:
		if m.Kind() != cbor.KindMap {
			return nil, fmt.Errorf("expected map, got kind %d", m.Kind())
		}
		result := make(map[int64]any, len(m.Map()))
		for _, entry := range m.Map() {
			key := cborToInt64(entry.Key)
			result[key] = cborToNative(entry.Value)
		}
		return result, nil
	case map[int64]any:
		return m, nil
	case map[any]any:
		result := make(map[int64]any, len(m))
		for k, val := range m {
			switch ki := k.(type) {
			case int64:
				result[ki] = val
			case int:
				result[int64(ki)] = val
			}
		}
		return result, nil
	default:
		return nil, fmt.Errorf("expected map, got %T", v)
	}
}

func cborToInt64(v cbor.Value) int64 {
	switch v.Kind() {
	case cbor.KindUint:
		return int64(v.UintVal())
	case cbor.KindNegInt:
		return -1 - int64(v.NegIntVal())
	default:
		return 0
	}
}

func cborToNative(v cbor.Value) any {
	switch v.Kind() {
	case cbor.KindUint:
		return int64(v.UintVal())
	case cbor.KindNegInt:
		return -1 - int64(v.NegIntVal())
	case cbor.KindBytes:
		return v.BytesVal()
	case cbor.KindText:
		return v.TextVal()
	case cbor.KindMap:
		result := make(map[int64]any, len(v.Map()))
		for _, entry := range v.Map() {
			key := cborToInt64(entry.Key)
			result[key] = cborToNative(entry.Value)
		}
		return result
	default:
		return v
	}
}

func coseKeyMapToPublicKey(m map[int64]any) (crypto.PublicKey, error) {
	ktyRaw, ok := m[1]
	if !ok {
		return nil, fmt.Errorf("%w: COSE_Key missing kty", ErrMessageFormat)
	}
	kty, ok := ktyRaw.(int64)
	if !ok {
		return nil, fmt.Errorf("%w: COSE_Key kty must be int", ErrMessageFormat)
	}

	switch cose.KeyType(kty) {
	case cose.KeyTypeOKP:
		return extractOKPPublicKey(m)
	case cose.KeyTypeEC2:
		return extractEC2PublicKey(m)
	default:
		return nil, fmt.Errorf("%w: unsupported COSE_Key type %d", ErrUnsupportedSuite, kty)
	}
}

func extractOKPPublicKey(m map[int64]any) (crypto.PublicKey, error) {
	xRaw, ok := m[-2]
	if !ok {
		return nil, fmt.Errorf("%w: OKP key missing x coordinate", ErrMessageFormat)
	}
	x, ok := xRaw.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: OKP x must be bytes", ErrMessageFormat)
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid Ed25519 key size", ErrMessageFormat)
	}
	return ed25519.PublicKey(x), nil
}

func extractEC2PublicKey(m map[int64]any) (crypto.PublicKey, error) {
	crvRaw, ok := m[-1]
	if !ok {
		return nil, fmt.Errorf("%w: EC2 key missing crv", ErrMessageFormat)
	}
	crv, ok := crvRaw.(int64)
	if !ok {
		return nil, fmt.Errorf("%w: EC2 crv must be int", ErrMessageFormat)
	}

	var curve elliptic.Curve
	switch cose.Curve(crv) {
	case cose.CurveP256:
		curve = elliptic.P256()
	case cose.CurveP384:
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("%w: unsupported EC2 curve %d", ErrUnsupportedSuite, crv)
	}

	xRaw, ok := m[-2]
	if !ok {
		return nil, fmt.Errorf("%w: EC2 key missing x", ErrMessageFormat)
	}
	x, ok := xRaw.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: EC2 x must be bytes", ErrMessageFormat)
	}

	yRaw, ok := m[-3]
	if !ok {
		return nil, fmt.Errorf("%w: EC2 key missing y", ErrMessageFormat)
	}
	y, ok := yRaw.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: EC2 y must be bytes", ErrMessageFormat)
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	return pub, nil
}
