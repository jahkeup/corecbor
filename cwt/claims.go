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
	var m []corecbor.MapEntry

	if c.Issuer != "" {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(uint64(claimIss)), Value: corecbor.Text(c.Issuer)})
	}
	if c.Subject != "" {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(uint64(claimSub)), Value: corecbor.Text(c.Subject)})
	}
	if c.Audience != "" {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(uint64(claimAud)), Value: corecbor.Text(c.Audience)})
	}
	if !c.Expiration.IsZero() {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(uint64(claimExp)), Value: numericDate(c.Expiration)})
	}
	if !c.NotBefore.IsZero() {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(uint64(claimNbf)), Value: numericDate(c.NotBefore)})
	}
	if !c.IssuedAt.IsZero() {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(uint64(claimIat)), Value: numericDate(c.IssuedAt)})
	}
	if len(c.CWTID) > 0 {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(uint64(claimCti)), Value: corecbor.Bytes(c.CWTID)})
	}
	if c.Confirmation != nil {
		cnfMap, err := encodeCnf(c.Confirmation)
		if err != nil {
			return nil, fmt.Errorf("%w: cnf: %v", ErrMalformedClaims, err)
		}
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(uint64(claimCnf)), Value: corecbor.MakeMapFromSlice(cnfMap)})
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
	return enc.Encode(nil, corecbor.MakeMapFromSlice(m))
}

// DecodeClaimsSet deserializes a CBOR-encoded claims map into a ClaimsSet.
func DecodeClaimsSet(data []byte) (*ClaimsSet, error) {
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	if v.Kind() != corecbor.KindMap {
		return nil, fmt.Errorf("%w: expected map, got kind %d", ErrMalformedClaims, v.Kind())
	}
	m := v.Map()

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
			ok := entry.Value.Kind() == corecbor.KindText
			t := entry.Value.TextVal()
			if !ok {
				return nil, fmt.Errorf("%w: iss must be text", ErrMalformedClaims)
			}
			cs.Issuer = t
		case claimSub:
			ok := entry.Value.Kind() == corecbor.KindText
			t := entry.Value.TextVal()
			if !ok {
				return nil, fmt.Errorf("%w: sub must be text", ErrMalformedClaims)
			}
			cs.Subject = t
		case claimAud:
			ok := entry.Value.Kind() == corecbor.KindText
			t := entry.Value.TextVal()
			if !ok {
				return nil, fmt.Errorf("%w: aud must be text", ErrMalformedClaims)
			}
			cs.Audience = t
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
			ok := entry.Value.Kind() == corecbor.KindBytes
			b := entry.Value.BytesVal()
			if !ok {
				return nil, fmt.Errorf("%w: cti must be bytes", ErrMalformedClaims)
			}
			cs.CWTID = b
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
			return corecbor.Uint(uint64(sec))
		}
		return corecbor.NegInt(uint64(-1 - sec))
	}
	return corecbor.Float64(float64(sec) + float64(nsec)/1e9)
}

func parseNumericDate(v corecbor.Value) (time.Time, error) {
	switch v.Kind() {
	case corecbor.KindUint:
		return time.Unix(int64(v.UintVal()), 0), nil
	case corecbor.KindNegInt:
		return time.Unix(-1-int64(v.NegIntVal()), 0), nil
	case corecbor.KindFloat64:
		sec, frac := math.Modf(v.Float64Val())
		return time.Unix(int64(sec), int64(frac*1e9)), nil
	case corecbor.KindFloat32:
		f := float64(v.Float32Val())
		sec, frac := math.Modf(f)
		return time.Unix(int64(sec), int64(frac*1e9)), nil
	default:
		return time.Time{}, fmt.Errorf("expected numeric, got kind %d", v.Kind())
	}
}

func entryKeyInt(key corecbor.Value) (int64, bool) {
	switch key.Kind() {
	case corecbor.KindUint:
		return int64(key.UintVal()), true
	case corecbor.KindNegInt:
		return -1 - int64(key.NegIntVal()), true
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
			return corecbor.Uint(uint64(x)), nil
		}
		return corecbor.NegInt(uint64(-1 - int64(x))), nil
	case int64:
		if x >= 0 {
			return corecbor.Uint(uint64(x)), nil
		}
		return corecbor.NegInt(uint64(-1 - x)), nil
	case uint64:
		return corecbor.Uint(x), nil
	case float64:
		return corecbor.Float64(x), nil
	case []byte:
		return corecbor.Bytes(x), nil
	case bool:
		return corecbor.Bool(x), nil
	default:
		return corecbor.Value{}, fmt.Errorf("unsupported type %T", v)
	}
}

func fromValue(v corecbor.Value) any {
	switch v.Kind() {
	case corecbor.KindUint:
		return int64(v.UintVal())
	case corecbor.KindNegInt:
		return -1 - int64(v.NegIntVal())
	case corecbor.KindText:
		return v.TextVal()
	case corecbor.KindBytes:
		return v.BytesVal()
	case corecbor.KindFloat64:
		return v.Float64Val()
	case corecbor.KindFloat32:
		return float64(v.Float32Val())
	case corecbor.KindBool:
		return v.BoolVal()
	default:
		return v
	}
}

func encodeCnf(cnf *Confirmation) ([]corecbor.MapEntry, error) {
	var m []corecbor.MapEntry
	if cnf.Key != nil {
		keyMap, err := marshalCOSEKey(cnf.Key)
		if err != nil {
			return nil, err
		}
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(uint64(cnfKeyByCOSEKey)), Value: corecbor.MakeMapFromSlice(keyMap)})
	}
	if len(cnf.Encrypted) > 0 {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(uint64(cnfKeyEncrypted)), Value: corecbor.Bytes(cnf.Encrypted)})
	}
	if len(cnf.KeyID) > 0 {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(uint64(cnfKeyByKid)), Value: corecbor.Bytes(cnf.KeyID)})
	}
	return m, nil
}

func decodeCnf(v corecbor.Value) (*Confirmation, error) {
	if v.Kind() != corecbor.KindMap {
		return nil, fmt.Errorf("expected map, got kind %d", v.Kind())
	}
	m := v.Map()
	cnf := &Confirmation{}
	for _, entry := range m {
		k, isInt := entryKeyInt(entry.Key)
		if !isInt {
			continue
		}
		switch k {
		case cnfKeyByCOSEKey:
			if entry.Value.Kind() != corecbor.KindMap {
				return nil, fmt.Errorf("COSE_Key must be map")
			}
			keyMap := entry.Value.Map()
			key, err := unmarshalCOSEKey(keyMap)
			if err != nil {
				return nil, err
			}
			cnf.Key = key
		case cnfKeyEncrypted:
			ok := entry.Value.Kind() == corecbor.KindBytes
			b := entry.Value.BytesVal()
			if !ok {
				return nil, fmt.Errorf("encrypted key must be bytes")
			}
			cnf.Encrypted = b
		case cnfKeyByKid:
			ok := entry.Value.Kind() == corecbor.KindBytes
			b := entry.Value.BytesVal()
			if !ok {
				return nil, fmt.Errorf("kid must be bytes")
			}
			cnf.KeyID = b
		}
	}
	return cnf, nil
}

func marshalCOSEKey(k *cose.Key) ([]corecbor.MapEntry, error) {
	pub, err := k.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("marshalCOSEKey: %w", err)
	}
	return cosePublicKeyToMap(pub, k)
}

func cosePublicKeyToMap(pub interface{}, k *cose.Key) ([]corecbor.MapEntry, error) {
	switch p := pub.(type) {
	case ed25519.PublicKey:
		return []corecbor.MapEntry{
			{Key: corecbor.Uint(1), Value: corecbor.Uint(uint64(cose.KeyTypeOKP))},
			{Key: corecbor.NegInt(0), Value: corecbor.Uint(uint64(cose.CurveEd25519))},
			{Key: corecbor.NegInt(1), Value: corecbor.Bytes([]byte(p))},
		}, nil
	case *ecdsa.PublicKey:
		crv := k.Curve()
		size := (p.Curve.Params().BitSize + 7) / 8
		raw, err := p.Bytes()
		if err != nil {
			return nil, fmt.Errorf("ecdsa public key bytes: %w", err)
		}
		x := padLeftBytes(raw[1:1+size], size)
		y := padLeftBytes(raw[1+size:], size)
		return []corecbor.MapEntry{
			{Key: corecbor.Uint(1), Value: corecbor.Uint(uint64(cose.KeyTypeEC2))},
			{Key: corecbor.NegInt(0), Value: corecbor.Uint(uint64(crv))},
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

func unmarshalCOSEKey(m []corecbor.MapEntry) (*cose.Key, error) {
	pos := make(map[int64]any)
	neg := make(map[int64]any)
	for _, entry := range m {
		switch entry.Key.Kind() {
		case corecbor.KindUint:
			kv := int64(entry.Key.UintVal())
			switch entry.Value.Kind() {
			case corecbor.KindUint:
				pos[kv] = int64(entry.Value.UintVal())
			case corecbor.KindNegInt:
				pos[kv] = -1 - int64(entry.Value.NegIntVal())
			case corecbor.KindBytes:
				pos[kv] = entry.Value.BytesVal()
			}
		case corecbor.KindNegInt:
			kv := int64(entry.Key.NegIntVal())
			switch entry.Value.Kind() {
			case corecbor.KindUint:
				neg[kv] = int64(entry.Value.UintVal())
			case corecbor.KindNegInt:
				neg[kv] = -1 - int64(entry.Value.NegIntVal())
			case corecbor.KindBytes:
				neg[kv] = entry.Value.BytesVal()
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
