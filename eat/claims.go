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
	var entries []corecbor.MapEntry

	if c.Issuer != "" {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(1), Value: corecbor.Text(c.Issuer)})
	}
	if c.Subject != "" {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(2), Value: corecbor.Text(c.Subject)})
	}
	if c.Audience != "" {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(3), Value: corecbor.Text(c.Audience)})
	}
	if !c.Expiration.IsZero() {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(4), Value: corecbor.Uint(uint64(c.Expiration.Unix()))})
	}
	if !c.NotBefore.IsZero() {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(5), Value: corecbor.Uint(uint64(c.NotBefore.Unix()))})
	}
	if !c.IssuedAt.IsZero() {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(6), Value: corecbor.Uint(uint64(c.IssuedAt.Unix()))})
	}
	if len(c.CWTID) > 0 {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(7), Value: corecbor.Bytes(c.CWTID)})
	}

	if len(c.Nonce) > 0 {
		if len(c.Nonce) == 1 {
			entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(claimNonce), Value: corecbor.Bytes(c.Nonce[0])})
		} else {
			items := make([]corecbor.Value, len(c.Nonce))
			for i, n := range c.Nonce {
				items[i] = corecbor.Bytes(n)
			}
			entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(claimNonce), Value: corecbor.MakeArray(items...)})
		}
	}
	if len(c.UEID) > 0 {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(claimUEID), Value: corecbor.Bytes(c.UEID)})
	}
	if len(c.OEMId) > 0 {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(claimOEMId), Value: corecbor.Bytes(c.OEMId)})
	}
	if c.SecurityLevel != 0 {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(claimSecurityLevel), Value: corecbor.Uint(uint64(c.SecurityLevel))})
	}
	if c.SecureBoot != nil {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(claimSecureBoot), Value: corecbor.Bool(*c.SecureBoot)})
	}
	if c.Debug != 0 {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(claimDebug), Value: corecbor.Uint(uint64(c.Debug))})
	}
	if c.Uptime != nil {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(claimUptime), Value: corecbor.Uint(*c.Uptime)})
	}
	if c.Profile != "" {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(claimProfile), Value: corecbor.Text(c.Profile)})
	}
	if len(c.SWComponents) > 0 {
		items := make([]corecbor.Value, len(c.SWComponents))
		for i, sw := range c.SWComponents {
			var cmEntries []corecbor.MapEntry
			if sw.Type != "" {
				cmEntries = append(cmEntries, corecbor.MapEntry{Key: corecbor.Uint(swCompType), Value: corecbor.Text(sw.Type)})
			}
			if len(sw.MeasurementValue) > 0 {
				cmEntries = append(cmEntries, corecbor.MapEntry{Key: corecbor.Uint(swCompMeasValue), Value: corecbor.Bytes(sw.MeasurementValue)})
			}
			if sw.Version != "" {
				cmEntries = append(cmEntries, corecbor.MapEntry{Key: corecbor.Uint(swCompVersion), Value: corecbor.Text(sw.Version)})
			}
			if len(sw.SignerID) > 0 {
				cmEntries = append(cmEntries, corecbor.MapEntry{Key: corecbor.Uint(swCompSignerID), Value: corecbor.Bytes(sw.SignerID)})
			}
			if sw.MeasurementDescription != "" {
				cmEntries = append(cmEntries, corecbor.MapEntry{Key: corecbor.Uint(swCompMeasDesc), Value: corecbor.Text(sw.MeasurementDescription)})
			}
			items[i] = corecbor.MakeMap(cmEntries...)
		}
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(claimSWComponents), Value: corecbor.MakeArray(items...)})
	}

	if len(c.Submods) > 0 {
		var smEntries []corecbor.MapEntry
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
			smEntries = append(smEntries, corecbor.MapEntry{Key: corecbor.Text(name), Value: val})
		}
		if len(smEntries) > 0 {
			entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(claimSubmods), Value: corecbor.MakeMap(smEntries...)})
		}
	}

	m := corecbor.MakeMap(entries...)
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

	if v.Kind() != corecbor.KindMap {
		return nil, fmt.Errorf("%w: expected map, got %v", ErrMalformedEAT, v.Kind())
	}

	m := v.Map()
	c := &Claims{}
	for _, entry := range m {
		keyInt, isInt := entryKeyInt(entry.Key)
		if !isInt {
			continue
		}

		switch keyInt {
		case 1:
			if entry.Value.Kind() != corecbor.KindText {
				return nil, fmt.Errorf("%w: iss must be text", ErrMalformedEAT)
			}
			c.Issuer = entry.Value.Text()
		case 2:
			if entry.Value.Kind() != corecbor.KindText {
				return nil, fmt.Errorf("%w: sub must be text", ErrMalformedEAT)
			}
			c.Subject = entry.Value.Text()
		case 3:
			if entry.Value.Kind() != corecbor.KindText {
				return nil, fmt.Errorf("%w: aud must be text", ErrMalformedEAT)
			}
			c.Audience = entry.Value.Text()
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
			if entry.Value.Kind() != corecbor.KindBytes {
				return nil, fmt.Errorf("%w: cti must be bytes", ErrMalformedEAT)
			}
			c.CWTID = entry.Value.Bytes()
		case claimNonce:
			nonces, err := parseNonce(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedEAT, err)
			}
			c.Nonce = nonces
		case claimUEID:
			if entry.Value.Kind() != corecbor.KindBytes {
				return nil, fmt.Errorf("%w: UEID must be bytes", ErrMalformedEAT)
			}
			c.UEID = entry.Value.Bytes()
		case claimOEMId:
			if entry.Value.Kind() != corecbor.KindBytes {
				return nil, fmt.Errorf("%w: OEMId must be bytes", ErrMalformedEAT)
			}
			c.OEMId = entry.Value.Bytes()
		case claimSecurityLevel:
			n, err := parseIntClaim(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: security-level: %v", ErrMalformedEAT, err)
			}
			c.SecurityLevel = SecurityLevel(n)
		case claimSecureBoot:
			if entry.Value.Kind() != corecbor.KindBool {
				return nil, fmt.Errorf("%w: secure-boot must be bool", ErrMalformedEAT)
			}
			bv := entry.Value.Bool()
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
			if entry.Value.Kind() != corecbor.KindText {
				return nil, fmt.Errorf("%w: profile must be text", ErrMalformedEAT)
			}
			c.Profile = entry.Value.Text()
		case claimSWComponents:
			if entry.Value.Kind() != corecbor.KindArray {
				return nil, fmt.Errorf("%w: sw-components must be array", ErrMalformedEAT)
			}
			arr := entry.Value.Array()
			swcs := make([]SWComponent, len(arr))
			for i, elem := range arr {
				if elem.Kind() != corecbor.KindMap {
					return nil, fmt.Errorf("%w: sw-component[%d] must be map", ErrMalformedEAT, i)
				}
				cm := elem.Map()
				var sw SWComponent
				for _, e := range cm {
					k, isInt := entryKeyInt(e.Key)
					if !isInt {
						continue
					}
					switch k {
					case swCompType:
						if e.Value.Kind() == corecbor.KindText {
							sw.Type = e.Value.Text()
						}
					case swCompMeasValue:
						if e.Value.Kind() == corecbor.KindBytes {
							sw.MeasurementValue = e.Value.Bytes()
						}
					case swCompVersion:
						if e.Value.Kind() == corecbor.KindText {
							sw.Version = e.Value.Text()
						}
					case swCompSignerID:
						if e.Value.Kind() == corecbor.KindBytes {
							sw.SignerID = e.Value.Bytes()
						}
					case swCompMeasDesc:
						if e.Value.Kind() == corecbor.KindText {
							sw.MeasurementDescription = e.Value.Text()
						}
					}
				}
				swcs[i] = sw
			}
			c.SWComponents = swcs
		case claimSubmods:
			if entry.Value.Kind() != corecbor.KindMap {
				return nil, fmt.Errorf("%w: submods must be map", ErrMalformedEAT)
			}
			sm := entry.Value.Map()
			c.Submods = make(map[string]Submod, len(sm))
			for _, e := range sm {
				if e.Key.Kind() != corecbor.KindText {
					return nil, fmt.Errorf("%w: submod key must be text", ErrMalformedEAT)
				}
				name := e.Key.Text()
				switch e.Value.Kind() {
				case corecbor.KindBytes:
					c.Submods[name] = Submod{Token: e.Value.Bytes()}
				case corecbor.KindMap:
					enc := corecbor.New(corecbor.ModeCoreDeterministic)
					encoded, err := enc.Encode(nil, e.Value)
					if err != nil {
						return nil, fmt.Errorf("%w: submods[%q] re-encode: %v", ErrMalformedEAT, name, err)
					}
					inlineClaims, err := DecodeClaims(encoded)
					if err != nil {
						return nil, fmt.Errorf("%w: submods[%q]: %v", ErrMalformedEAT, name, err)
					}
					c.Submods[name] = Submod{Claims: inlineClaims}
				default:
					return nil, fmt.Errorf("%w: submod[%q] value must be bytes or map", ErrMalformedEAT, name)
				}
			}
		}
	}

	return c, nil
}

func parseNonce(v corecbor.Value) ([][]byte, error) {
	switch v.Kind() {
	case corecbor.KindBytes:
		return [][]byte{v.Bytes()}, nil
	case corecbor.KindArray:
		arr := v.Array()
		nonces := make([][]byte, len(arr))
		for i, elem := range arr {
			if elem.Kind() != corecbor.KindBytes {
				return nil, fmt.Errorf("nonce array element %d must be bytes", i)
			}
			nonces[i] = elem.Bytes()
		}
		return nonces, nil
	default:
		return nil, fmt.Errorf("nonce must be bytes or array, got %v", v.Kind())
	}
}

func parseIntClaim(v corecbor.Value) (int64, error) {
	switch v.Kind() {
	case corecbor.KindUint:
		return int64(v.Uint()), nil
	case corecbor.KindNegInt:
		return -1 - int64(v.NegInt()), nil
	default:
		return 0, fmt.Errorf("expected integer, got %v", v.Kind())
	}
}

func parseUintClaim(v corecbor.Value) (uint64, error) {
	switch v.Kind() {
	case corecbor.KindUint:
		return v.Uint(), nil
	default:
		return 0, fmt.Errorf("expected unsigned integer, got %v", v.Kind())
	}
}

func parseNumericDate(v corecbor.Value) (time.Time, error) {
	switch v.Kind() {
	case corecbor.KindUint:
		return time.Unix(int64(v.Uint()), 0), nil
	case corecbor.KindNegInt:
		return time.Unix(-1-int64(v.NegInt()), 0), nil
	default:
		return time.Time{}, fmt.Errorf("expected numeric, got %v", v.Kind())
	}
}

func entryKeyInt(key corecbor.Value) (int64, bool) {
	switch key.Kind() {
	case corecbor.KindUint:
		return int64(key.Uint()), true
	case corecbor.KindNegInt:
		return -1 - int64(key.NegInt()), true
	default:
		return 0, false
	}
}
