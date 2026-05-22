// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
	"math"
	"time"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cose"
)

const (
	claimIss = 1
	claimSub = 2
	claimAud = 3
	claimExp = 4
	claimNbf = 5
	claimIat = 6
	claimCti = 7
	claimCnf = 8
)

// cnf map keys per RFC 8747.
const (
	cnfKeyByCOSEKey = 1
	cnfKeyEncrypted = 2
	cnfKeyByKid     = 3
)

// Confirmation represents the cnf (confirmation) claim (key 8)
// per RFC 8747. Binds the token to a specific cryptographic key.
type Confirmation struct {
	Key       *cose.Key // cnf map key 1: COSE_Key by value
	KeyID     []byte    // cnf map key 3: key ID reference
	Encrypted []byte    // cnf map key 2: encrypted COSE_Key
}

// ClaimsSet represents the set of claims in a CWT.
type ClaimsSet struct {
	Issuer       string
	Subject      string
	Audience     string
	Expiration   time.Time
	NotBefore    time.Time
	IssuedAt     time.Time
	CWTID        []byte
	Confirmation *Confirmation
	Private      map[any]any
}

// Encode serializes the ClaimsSet as a CBOR map using CoreDeterministic mode.
func (c *ClaimsSet) Encode() ([]byte, error) {
	m := corecbor.Map{}

	if c.Issuer != "" {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimIss), Value: corecbor.Text(c.Issuer)})
	}
	if c.Subject != "" {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimSub), Value: corecbor.Text(c.Subject)})
	}
	if c.Audience != "" {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimAud), Value: corecbor.Text(c.Audience)})
	}
	if !c.Expiration.IsZero() {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimExp), Value: numericDate(c.Expiration)})
	}
	if !c.NotBefore.IsZero() {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimNbf), Value: numericDate(c.NotBefore)})
	}
	if !c.IssuedAt.IsZero() {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimIat), Value: numericDate(c.IssuedAt)})
	}
	if len(c.CWTID) > 0 {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimCti), Value: corecbor.Bytes(c.CWTID)})
	}
	if c.Confirmation != nil {
		cnfMap, err := encodeCnf(c.Confirmation)
		if err != nil {
			return nil, fmt.Errorf("%w: cnf: %v", ErrMalformedClaims, err)
		}
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimCnf), Value: cnfMap})
	}

	for k, v := range c.Private {
		key, err := toValue(k)
		if err != nil {
			return nil, fmt.Errorf("%w: private claim key: %v", ErrMalformedClaims, err)
		}
		val, err := toValue(v)
		if err != nil {
			return nil, fmt.Errorf("%w: private claim value: %v", ErrMalformedClaims, err)
		}
		m = append(m, corecbor.MapEntry{Key: key, Value: val})
	}

	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	return enc.Encode(nil, m)
}

// DecodeClaimsSet deserializes a CBOR-encoded claims map into a ClaimsSet.
func DecodeClaimsSet(data []byte) (*ClaimsSet, error) {
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	m, ok := v.(corecbor.Map)
	if !ok {
		return nil, fmt.Errorf("%w: expected map, got %T", ErrMalformedClaims, v)
	}

	cs := &ClaimsSet{}
	for _, entry := range m {
		keyInt, isInt := entryKeyInt(entry.Key)
		if !isInt {
			if cs.Private == nil {
				cs.Private = make(map[any]any)
			}
			cs.Private[fromValue(entry.Key)] = fromValue(entry.Value)
			continue
		}

		switch keyInt {
		case claimIss:
			t, ok := entry.Value.(corecbor.Text)
			if !ok {
				return nil, fmt.Errorf("%w: iss must be text", ErrMalformedClaims)
			}
			cs.Issuer = string(t)
		case claimSub:
			t, ok := entry.Value.(corecbor.Text)
			if !ok {
				return nil, fmt.Errorf("%w: sub must be text", ErrMalformedClaims)
			}
			cs.Subject = string(t)
		case claimAud:
			t, ok := entry.Value.(corecbor.Text)
			if !ok {
				return nil, fmt.Errorf("%w: aud must be text", ErrMalformedClaims)
			}
			cs.Audience = string(t)
		case claimExp:
			ts, err := parseNumericDate(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: exp: %v", ErrMalformedClaims, err)
			}
			cs.Expiration = ts
		case claimNbf:
			ts, err := parseNumericDate(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: nbf: %v", ErrMalformedClaims, err)
			}
			cs.NotBefore = ts
		case claimIat:
			ts, err := parseNumericDate(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: iat: %v", ErrMalformedClaims, err)
			}
			cs.IssuedAt = ts
		case claimCti:
			b, ok := entry.Value.(corecbor.Bytes)
			if !ok {
				return nil, fmt.Errorf("%w: cti must be bytes", ErrMalformedClaims)
			}
			cs.CWTID = []byte(b)
		case claimCnf:
			cnf, err := decodeCnf(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: cnf: %v", ErrMalformedClaims, err)
			}
			cs.Confirmation = cnf
		default:
			if cs.Private == nil {
				cs.Private = make(map[any]any)
			}
			cs.Private[fromValue(entry.Key)] = fromValue(entry.Value)
		}
	}

	return cs, nil
}

func numericDate(t time.Time) corecbor.Value {
	sec := t.Unix()
	nsec := t.Nanosecond()
	if nsec == 0 {
		if sec >= 0 {
			return corecbor.Uint(sec)
		}
		return corecbor.NegInt(sec)
	}
	return corecbor.Float64(float64(sec) + float64(nsec)/1e9)
}

func parseNumericDate(v corecbor.Value) (time.Time, error) {
	switch x := v.(type) {
	case corecbor.Uint:
		return time.Unix(int64(x), 0), nil
	case corecbor.NegInt:
		return time.Unix(int64(x), 0), nil
	case corecbor.Float64:
		sec, frac := math.Modf(float64(x))
		return time.Unix(int64(sec), int64(frac*1e9)), nil
	case corecbor.Float32:
		f := float64(x)
		sec, frac := math.Modf(f)
		return time.Unix(int64(sec), int64(frac*1e9)), nil
	default:
		return time.Time{}, fmt.Errorf("expected numeric, got %T", v)
	}
}

func entryKeyInt(key corecbor.Value) (int64, bool) {
	switch k := key.(type) {
	case corecbor.Uint:
		return int64(k), true
	case corecbor.NegInt:
		return int64(k), true
	default:
		return 0, false
	}
}

func toValue(v any) (corecbor.Value, error) {
	switch x := v.(type) {
	case corecbor.Value:
		return x, nil
	case string:
		return corecbor.Text(x), nil
	case int:
		if x >= 0 {
			return corecbor.Uint(x), nil
		}
		return corecbor.NegInt(int64(x)), nil
	case int64:
		if x >= 0 {
			return corecbor.Uint(x), nil
		}
		return corecbor.NegInt(x), nil
	case uint64:
		return corecbor.Uint(x), nil
	case float64:
		return corecbor.Float64(x), nil
	case []byte:
		return corecbor.Bytes(x), nil
	case bool:
		return corecbor.Bool(x), nil
	default:
		return nil, fmt.Errorf("unsupported type %T", v)
	}
}

func fromValue(v corecbor.Value) any {
	switch x := v.(type) {
	case corecbor.Uint:
		return int64(x)
	case corecbor.NegInt:
		return int64(x)
	case corecbor.Text:
		return string(x)
	case corecbor.Bytes:
		return []byte(x)
	case corecbor.Float64:
		return float64(x)
	case corecbor.Float32:
		return float64(x)
	case corecbor.Bool:
		return bool(x)
	default:
		return v
	}
}

func encodeCnf(cnf *Confirmation) (corecbor.Map, error) {
	var m corecbor.Map
	if cnf.Key != nil {
		keyMap, err := marshalCOSEKey(cnf.Key)
		if err != nil {
			return nil, err
		}
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(cnfKeyByCOSEKey), Value: keyMap})
	}
	if len(cnf.Encrypted) > 0 {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(cnfKeyEncrypted), Value: corecbor.Bytes(cnf.Encrypted)})
	}
	if len(cnf.KeyID) > 0 {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(cnfKeyByKid), Value: corecbor.Bytes(cnf.KeyID)})
	}
	return m, nil
}

func decodeCnf(v corecbor.Value) (*Confirmation, error) {
	m, ok := v.(corecbor.Map)
	if !ok {
		return nil, fmt.Errorf("expected map, got %T", v)
	}
	cnf := &Confirmation{}
	for _, entry := range m {
		k, isInt := entryKeyInt(entry.Key)
		if !isInt {
			continue
		}
		switch k {
		case cnfKeyByCOSEKey:
			keyMap, ok := entry.Value.(corecbor.Map)
			if !ok {
				return nil, fmt.Errorf("COSE_Key must be map")
			}
			key, err := unmarshalCOSEKey(keyMap)
			if err != nil {
				return nil, err
			}
			cnf.Key = key
		case cnfKeyEncrypted:
			b, ok := entry.Value.(corecbor.Bytes)
			if !ok {
				return nil, fmt.Errorf("encrypted key must be bytes")
			}
			cnf.Encrypted = []byte(b)
		case cnfKeyByKid:
			b, ok := entry.Value.(corecbor.Bytes)
			if !ok {
				return nil, fmt.Errorf("kid must be bytes")
			}
			cnf.KeyID = []byte(b)
		}
	}
	return cnf, nil
}

func marshalCOSEKey(k *cose.Key) (corecbor.Map, error) {
	pub, err := k.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("marshalCOSEKey: %w", err)
	}
	return cosePublicKeyToMap(pub, k)
}

func cosePublicKeyToMap(pub interface{}, k *cose.Key) (corecbor.Map, error) {
	switch p := pub.(type) {
	case ed25519.PublicKey:
		return corecbor.Map{
			{Key: corecbor.Uint(1), Value: corecbor.Uint(int64(cose.KeyTypeOKP))},
			{Key: corecbor.NegInt(0), Value: corecbor.Uint(int64(cose.CurveEd25519))},
			{Key: corecbor.NegInt(1), Value: corecbor.Bytes([]byte(p))},
		}, nil
	case *ecdsa.PublicKey:
		crv := k.Curve()
		size := (p.Curve.Params().BitSize + 7) / 8
		raw, err := p.Bytes()
		if err != nil {
			return nil, fmt.Errorf("ecdsa public key bytes: %w", err)
		}
		// raw is uncompressed: 0x04 || X || Y
		x := padLeftBytes(raw[1:1+size], size)
		y := padLeftBytes(raw[1+size:], size)
		return corecbor.Map{
			{Key: corecbor.Uint(1), Value: corecbor.Uint(int64(cose.KeyTypeEC2))},
			{Key: corecbor.NegInt(0), Value: corecbor.Uint(int64(crv))},
			{Key: corecbor.NegInt(1), Value: corecbor.Bytes(x)},
			{Key: corecbor.NegInt(2), Value: corecbor.Bytes(y)},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}

func padLeftBytes(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func unmarshalCOSEKey(m corecbor.Map) (*cose.Key, error) {
	pos := make(map[int64]any)
	neg := make(map[int64]any)
	for _, entry := range m {
		switch kv := entry.Key.(type) {
		case corecbor.Uint:
			switch val := entry.Value.(type) {
			case corecbor.Uint:
				pos[int64(kv)] = int64(val)
			case corecbor.NegInt:
				pos[int64(kv)] = int64(val)
			case corecbor.Bytes:
				pos[int64(kv)] = []byte(val)
			}
		case corecbor.NegInt:
			switch val := entry.Value.(type) {
			case corecbor.Uint:
				neg[int64(kv)] = int64(val)
			case corecbor.NegInt:
				neg[int64(kv)] = int64(val)
			case corecbor.Bytes:
				neg[int64(kv)] = []byte(val)
			}
		}
	}
	return coseKeyFromMaps(pos, neg)
}

func coseKeyFromMaps(pos, neg map[int64]any) (*cose.Key, error) {
	ktyRaw, ok := pos[1]
	if !ok {
		return nil, fmt.Errorf("missing kty")
	}
	kty, ok := ktyRaw.(int64)
	if !ok {
		return nil, fmt.Errorf("kty must be int")
	}

	switch cose.KeyType(kty) {
	case cose.KeyTypeOKP:
		xRaw, ok := neg[1]
		if !ok {
			return nil, fmt.Errorf("OKP key missing x (NegInt 1 = label -2)")
		}
		x, ok := xRaw.([]byte)
		if !ok {
			return nil, fmt.Errorf("OKP x must be bytes")
		}
		return cose.NewKeyFromPublic(ed25519.PublicKey(x))
	case cose.KeyTypeEC2:
		crvRaw, ok := neg[0]
		if !ok {
			return nil, fmt.Errorf("EC2 key missing crv (NegInt 0 = label -1)")
		}
		crv, ok := crvRaw.(int64)
		if !ok {
			return nil, fmt.Errorf("EC2 crv must be int")
		}
		xRaw, ok := neg[1]
		if !ok {
			return nil, fmt.Errorf("EC2 key missing x (NegInt 1 = label -2)")
		}
		x, ok := xRaw.([]byte)
		if !ok {
			return nil, fmt.Errorf("EC2 x must be bytes")
		}
		yRaw, ok := neg[2]
		if !ok {
			return nil, fmt.Errorf("EC2 key missing y (NegInt 2 = label -3)")
		}
		y, ok := yRaw.([]byte)
		if !ok {
			return nil, fmt.Errorf("EC2 y must be bytes")
		}
		goCrv, err := coseCurveToElliptic(cose.Curve(crv))
		if err != nil {
			return nil, err
		}
		size := (goCrv.Params().BitSize + 7) / 8
		point := make([]byte, 1+2*size)
		point[0] = 0x04
		copy(point[1:1+size], padLeftBytes(x, size))
		copy(point[1+size:], padLeftBytes(y, size))
		pub, err := ecdsa.ParseUncompressedPublicKey(goCrv, point)
		if err != nil {
			return nil, fmt.Errorf("EC2 parse public key: %w", err)
		}
		return cose.NewKeyFromPublic(pub)
	default:
		return nil, fmt.Errorf("unsupported key type %d", kty)
	}
}

func coseCurveToElliptic(c cose.Curve) (elliptic.Curve, error) {
	switch c {
	case cose.CurveP256:
		return elliptic.P256(), nil
	case cose.CurveP384:
		return elliptic.P384(), nil
	case cose.CurveP521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported COSE curve %d", c)
	}
}
