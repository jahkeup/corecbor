// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

import (
	"fmt"
	"time"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cwt"
)

const (
	claimNonce         = 10
	claimUEID          = 256
	claimOEMId         = 258
	claimSecurityLevel = 261
	claimSecureBoot    = 262
	claimDebug         = 263
	claimUptime        = 266
	claimProfile       = 265
	claimSWComponents  = 267
	claimSubmods       = 268

	swCompType      = 1
	swCompMeasValue = 2
	swCompVersion   = 4
	swCompSignerID  = 5
	swCompMeasDesc  = 6
)

// SecurityLevel represents the EAT security level claim (RFC 9711 §4.3.1).
type SecurityLevel int64

const (
	SecLevelUnrestricted     SecurityLevel = 1
	SecLevelRestrictedOS     SecurityLevel = 2
	SecLevelSecureRestricted SecurityLevel = 3
	SecLevelHardware         SecurityLevel = 4
)

// DebugStatus represents the EAT debug status claim (RFC 9711 §4.3.3).
type DebugStatus int64

const (
	DebugEnabled          DebugStatus = 0
	DebugDisabled         DebugStatus = 1
	DebugDisabledSince    DebugStatus = 2
	DebugPermanentDisable DebugStatus = 3
)

// SWComponent represents a single software component measurement (EAT §4.4.1).
type SWComponent struct {
	Type                   string
	MeasurementValue       []byte
	Version                string
	SignerID               []byte
	MeasurementDescription string
}

// Submod holds submodule attestation evidence. Values are either a nested EAT
// token (signed CBOR bytes) or inline Claims. Token and Claims are mutually exclusive.
type Submod struct {
	// Token is a nested EAT (signed CBOR bytes). Mutually exclusive with Claims.
	Token []byte
	// Claims is an inline submodule claims set. Mutually exclusive with Token.
	Claims *Claims
}

// Claims represents an EAT claims set, extending CWT with attestation claims.
type Claims struct {
	cwt.ClaimsSet

	Nonce         [][]byte
	UEID          []byte
	OEMId         []byte
	SecurityLevel SecurityLevel
	SecureBoot    *bool
	Debug         DebugStatus
	Uptime        *uint64
	Profile       string
	SWComponents  []SWComponent
	// Submods holds submodule attestation evidence. Keys are submodule names.
	Submods map[string]Submod
}

// Encode serializes the Claims as a CBOR map with integer keys.
func (c *Claims) Encode() ([]byte, error) {
	m := corecbor.Map{}

	if c.Issuer != "" {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(1), Value: corecbor.Text(c.Issuer)})
	}
	if c.Subject != "" {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(2), Value: corecbor.Text(c.Subject)})
	}
	if c.Audience != "" {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(3), Value: corecbor.Text(c.Audience)})
	}
	if !c.Expiration.IsZero() {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(4), Value: corecbor.Uint(c.Expiration.Unix())})
	}
	if !c.NotBefore.IsZero() {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(5), Value: corecbor.Uint(c.NotBefore.Unix())})
	}
	if !c.IssuedAt.IsZero() {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(6), Value: corecbor.Uint(c.IssuedAt.Unix())})
	}
	if len(c.CWTID) > 0 {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(7), Value: corecbor.Bytes(c.CWTID)})
	}

	if len(c.Nonce) > 0 {
		if len(c.Nonce) == 1 {
			m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimNonce), Value: corecbor.Bytes(c.Nonce[0])})
		} else {
			arr := make(corecbor.Array, len(c.Nonce))
			for i, n := range c.Nonce {
				arr[i] = corecbor.Bytes(n)
			}
			m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimNonce), Value: arr})
		}
	}
	if len(c.UEID) > 0 {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimUEID), Value: corecbor.Bytes(c.UEID)})
	}
	if len(c.OEMId) > 0 {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimOEMId), Value: corecbor.Bytes(c.OEMId)})
	}
	if c.SecurityLevel != 0 {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimSecurityLevel), Value: corecbor.Uint(int64(c.SecurityLevel))})
	}
	if c.SecureBoot != nil {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimSecureBoot), Value: corecbor.Bool(*c.SecureBoot)})
	}
	if c.Debug != 0 {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimDebug), Value: corecbor.Uint(int64(c.Debug))})
	}
	if c.Uptime != nil {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimUptime), Value: corecbor.Uint(*c.Uptime)})
	}
	if c.Profile != "" {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimProfile), Value: corecbor.Text(c.Profile)})
	}
	if len(c.SWComponents) > 0 {
		arr := make(corecbor.Array, len(c.SWComponents))
		for i, sw := range c.SWComponents {
			cm := corecbor.Map{}
			if sw.Type != "" {
				cm = append(cm, corecbor.MapEntry{Key: corecbor.Uint(swCompType), Value: corecbor.Text(sw.Type)})
			}
			if len(sw.MeasurementValue) > 0 {
				cm = append(cm, corecbor.MapEntry{Key: corecbor.Uint(swCompMeasValue), Value: corecbor.Bytes(sw.MeasurementValue)})
			}
			if sw.Version != "" {
				cm = append(cm, corecbor.MapEntry{Key: corecbor.Uint(swCompVersion), Value: corecbor.Text(sw.Version)})
			}
			if len(sw.SignerID) > 0 {
				cm = append(cm, corecbor.MapEntry{Key: corecbor.Uint(swCompSignerID), Value: corecbor.Bytes(sw.SignerID)})
			}
			if sw.MeasurementDescription != "" {
				cm = append(cm, corecbor.MapEntry{Key: corecbor.Uint(swCompMeasDesc), Value: corecbor.Text(sw.MeasurementDescription)})
			}
			arr[i] = cm
		}
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimSWComponents), Value: arr})
	}

	if len(c.Submods) > 0 {
		sm := corecbor.Map{}
		for name, sub := range c.Submods {
			var val corecbor.Value
			if sub.Token != nil {
				val = corecbor.Bytes(sub.Token)
			} else if sub.Claims != nil {
				encoded, err := sub.Claims.Encode()
				if err != nil {
					return nil, fmt.Errorf("submods[%q]: %w", name, err)
				}
				dec := corecbor.NewDecoder()
				decoded, err := dec.Decode(encoded)
				if err != nil {
					return nil, fmt.Errorf("submods[%q] re-decode: %w", name, err)
				}
				val = decoded
			} else {
				continue
			}
			sm = append(sm, corecbor.MapEntry{Key: corecbor.Text(name), Value: val})
		}
		if len(sm) > 0 {
			m = append(m, corecbor.MapEntry{Key: corecbor.Uint(claimSubmods), Value: sm})
		}
	}

	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	return enc.Encode(nil, m)
}

// DecodeClaims deserializes a CBOR-encoded map into EAT Claims.
func DecodeClaims(data []byte) (*Claims, error) {
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedEAT, err)
	}

	m, ok := v.(corecbor.Map)
	if !ok {
		return nil, fmt.Errorf("%w: expected map, got %T", ErrMalformedEAT, v)
	}

	c := &Claims{}
	for _, entry := range m {
		keyInt, isInt := entryKeyInt(entry.Key)
		if !isInt {
			continue
		}

		switch keyInt {
		case 1:
			t, ok := entry.Value.(corecbor.Text)
			if !ok {
				return nil, fmt.Errorf("%w: iss must be text", ErrMalformedEAT)
			}
			c.Issuer = string(t)
		case 2:
			t, ok := entry.Value.(corecbor.Text)
			if !ok {
				return nil, fmt.Errorf("%w: sub must be text", ErrMalformedEAT)
			}
			c.Subject = string(t)
		case 3:
			t, ok := entry.Value.(corecbor.Text)
			if !ok {
				return nil, fmt.Errorf("%w: aud must be text", ErrMalformedEAT)
			}
			c.Audience = string(t)
		case 4:
			ts, err := parseNumericDate(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: exp: %v", ErrMalformedEAT, err)
			}
			c.Expiration = ts
		case 5:
			ts, err := parseNumericDate(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: nbf: %v", ErrMalformedEAT, err)
			}
			c.NotBefore = ts
		case 6:
			ts, err := parseNumericDate(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: iat: %v", ErrMalformedEAT, err)
			}
			c.IssuedAt = ts
		case 7:
			b, ok := entry.Value.(corecbor.Bytes)
			if !ok {
				return nil, fmt.Errorf("%w: cti must be bytes", ErrMalformedEAT)
			}
			c.CWTID = []byte(b)
		case claimNonce:
			nonces, err := parseNonce(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedEAT, err)
			}
			c.Nonce = nonces
		case claimUEID:
			b, ok := entry.Value.(corecbor.Bytes)
			if !ok {
				return nil, fmt.Errorf("%w: UEID must be bytes", ErrMalformedEAT)
			}
			c.UEID = []byte(b)
		case claimOEMId:
			b, ok := entry.Value.(corecbor.Bytes)
			if !ok {
				return nil, fmt.Errorf("%w: OEMId must be bytes", ErrMalformedEAT)
			}
			c.OEMId = []byte(b)
		case claimSecurityLevel:
			n, err := parseIntClaim(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: security-level: %v", ErrMalformedEAT, err)
			}
			c.SecurityLevel = SecurityLevel(n)
		case claimSecureBoot:
			b, ok := entry.Value.(corecbor.Bool)
			if !ok {
				return nil, fmt.Errorf("%w: secure-boot must be bool", ErrMalformedEAT)
			}
			bv := bool(b)
			c.SecureBoot = &bv
		case claimDebug:
			n, err := parseIntClaim(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: debug: %v", ErrMalformedEAT, err)
			}
			c.Debug = DebugStatus(n)
		case claimUptime:
			n, err := parseUintClaim(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: uptime: %v", ErrMalformedEAT, err)
			}
			c.Uptime = &n
		case claimProfile:
			t, ok := entry.Value.(corecbor.Text)
			if !ok {
				return nil, fmt.Errorf("%w: profile must be text", ErrMalformedEAT)
			}
			c.Profile = string(t)
		case claimSWComponents:
			arr, ok := entry.Value.(corecbor.Array)
			if !ok {
				return nil, fmt.Errorf("%w: sw-components must be array", ErrMalformedEAT)
			}
			swcs := make([]SWComponent, len(arr))
			for i, elem := range arr {
				cm, ok := elem.(corecbor.Map)
				if !ok {
					return nil, fmt.Errorf("%w: sw-component[%d] must be map", ErrMalformedEAT, i)
				}
				var sw SWComponent
				for _, e := range cm {
					k, isInt := entryKeyInt(e.Key)
					if !isInt {
						continue
					}
					switch k {
					case swCompType:
						if t, ok := e.Value.(corecbor.Text); ok {
							sw.Type = string(t)
						}
					case swCompMeasValue:
						if b, ok := e.Value.(corecbor.Bytes); ok {
							sw.MeasurementValue = []byte(b)
						}
					case swCompVersion:
						if t, ok := e.Value.(corecbor.Text); ok {
							sw.Version = string(t)
						}
					case swCompSignerID:
						if b, ok := e.Value.(corecbor.Bytes); ok {
							sw.SignerID = []byte(b)
						}
					case swCompMeasDesc:
						if t, ok := e.Value.(corecbor.Text); ok {
							sw.MeasurementDescription = string(t)
						}
					}
				}
				swcs[i] = sw
			}
			c.SWComponents = swcs
		case claimSubmods:
			sm, ok := entry.Value.(corecbor.Map)
			if !ok {
				return nil, fmt.Errorf("%w: submods must be map", ErrMalformedEAT)
			}
			c.Submods = make(map[string]Submod, len(sm))
			for _, e := range sm {
				name, ok := e.Key.(corecbor.Text)
				if !ok {
					return nil, fmt.Errorf("%w: submod key must be text", ErrMalformedEAT)
				}
				switch val := e.Value.(type) {
				case corecbor.Bytes:
					c.Submods[string(name)] = Submod{Token: []byte(val)}
				case corecbor.Map:
					enc := corecbor.New(corecbor.ModeCoreDeterministic)
					encoded, err := enc.Encode(nil, val)
					if err != nil {
						return nil, fmt.Errorf("%w: submods[%q] re-encode: %v", ErrMalformedEAT, string(name), err)
					}
					inlineClaims, err := DecodeClaims(encoded)
					if err != nil {
						return nil, fmt.Errorf("%w: submods[%q]: %v", ErrMalformedEAT, string(name), err)
					}
					c.Submods[string(name)] = Submod{Claims: inlineClaims}
				default:
					return nil, fmt.Errorf("%w: submod[%q] value must be bytes or map", ErrMalformedEAT, string(name))
				}
			}
		}
	}

	return c, nil
}

func parseNonce(v corecbor.Value) ([][]byte, error) {
	switch x := v.(type) {
	case corecbor.Bytes:
		return [][]byte{[]byte(x)}, nil
	case corecbor.Array:
		nonces := make([][]byte, len(x))
		for i, elem := range x {
			b, ok := elem.(corecbor.Bytes)
			if !ok {
				return nil, fmt.Errorf("nonce array element %d must be bytes", i)
			}
			nonces[i] = []byte(b)
		}
		return nonces, nil
	default:
		return nil, fmt.Errorf("nonce must be bytes or array, got %T", v)
	}
}

func parseIntClaim(v corecbor.Value) (int64, error) {
	switch x := v.(type) {
	case corecbor.Uint:
		return int64(x), nil
	case corecbor.NegInt:
		return int64(x), nil
	default:
		return 0, fmt.Errorf("expected integer, got %T", v)
	}
}

func parseUintClaim(v corecbor.Value) (uint64, error) {
	switch x := v.(type) {
	case corecbor.Uint:
		return uint64(x), nil
	default:
		return 0, fmt.Errorf("expected unsigned integer, got %T", v)
	}
}

func parseNumericDate(v corecbor.Value) (time.Time, error) {
	switch x := v.(type) {
	case corecbor.Uint:
		return time.Unix(int64(x), 0), nil
	case corecbor.NegInt:
		return time.Unix(int64(x), 0), nil
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
