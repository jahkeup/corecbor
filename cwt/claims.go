package cwt

import (
	"fmt"
	"math"
	"time"

	"github.com/jahkeup/corecbor"
)

const (
	claimIss = 1
	claimSub = 2
	claimAud = 3
	claimExp = 4
	claimNbf = 5
	claimIat = 6
	claimCti = 7
)

// ClaimsSet represents the set of claims in a CWT.
type ClaimsSet struct {
	Issuer     string
	Subject    string
	Audience   string
	Expiration time.Time
	NotBefore  time.Time
	IssuedAt   time.Time
	CWTID      []byte
	Private    map[any]any
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
