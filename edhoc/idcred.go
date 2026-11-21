// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"fmt"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/cose"
)

// COSE header labels used in ID_CRED_x (RFC 9528 §3.5.3).
const (
	labelKID     = 4
	labelKCWT    = 13
	labelKCCS    = 14
	labelX5Chain = 33
	labelX5T     = 34
)

// X5T is a COSE x5t value (RFC 9360): a hash of an X.509 certificate.
// It is cose.CertHash, so Matches checks a candidate certificate.
type X5T = cose.CertHash

// IDCred is a parsed ID_CRED_x (RFC 9528 §3.5.3). Exactly one field is
// set. A KID is sent in the compact form when it is the only parameter.
type IDCred struct {
	KID     []byte
	X5T     *X5T
	X5Chain [][]byte // DER certificates, leaf first
	KCCS    []byte   // encoded CWT Claims Set, by value
	KCWT    []byte   // encoded CWT, by value
}

func (id IDCred) set() int {
	n := 0
	if id.KID != nil {
		n++
	}
	if id.X5T != nil {
		n++
	}
	if id.X5Chain != nil {
		n++
	}
	if id.KCCS != nil {
		n++
	}
	if id.KCWT != nil {
		n++
	}
	return n
}

// full returns ID_CRED_x as a single-entry COSE header map. KCCS and
// KCWT are embedded byte-for-byte, so they enter the transcript exactly
// as given.
func (id IDCred) full() ([]byte, error) {
	if id.set() != 1 {
		return nil, fmt.Errorf("%w: ID_CRED must have exactly one parameter", ErrMessageFormat)
	}
	switch {
	case id.KID != nil:
		return encSeq([]byte{0xa1}, intItem(labelKID), bstrItem(id.KID)), nil
	case id.X5T != nil:
		return encSeq([]byte{0xa1}, intItem(labelX5T), []byte{0x82}, intItem(int64(id.X5T.Alg)), bstrItem(id.X5T.Hash)), nil
	case id.X5Chain != nil:
		if len(id.X5Chain) == 1 {
			return encSeq([]byte{0xa1}, intItem(labelX5Chain), bstrItem(id.X5Chain[0])), nil
		}
		items := []cbor.Value{}
		for _, c := range id.X5Chain {
			items = append(items, cbor.Bytes(c))
		}
		return encSeq([]byte{0xa1}, intItem(labelX5Chain), item(cbor.MakeArrayFromSlice(items))), nil
	case id.KCCS != nil:
		return encSeq([]byte{0xa1}, intItem(labelKCCS), id.KCCS), nil
	default:
		return encSeq([]byte{0xa1}, intItem(labelKCWT), id.KCWT), nil
	}
}

// compact returns ID_CRED_x as it appears in PLAINTEXT_2/3: a KID-only
// ID_CRED is replaced by the KID itself (RFC 9528 §3.5.3.2), encoded
// like a connection identifier.
func (id IDCred) compact() ([]byte, error) {
	if id.KID != nil && id.set() == 1 {
		return encodeCID(id.KID), nil
	}
	return id.full()
}

// ParseIDCred parses an ID_CRED_x header map, or the compact KID form
// (an integer or byte string).
func ParseIDCred(v cbor.Value) (IDCred, error) {
	return parseIDCred(v, nil)
}

// parseIDCred parses v; raw, when given, is v's encoding, used to keep
// KCCS/KCWT values byte-for-byte.
func parseIDCred(v cbor.Value, raw []byte) (IDCred, error) {
	switch v.Kind {
	case cbor.KindUint, cbor.KindNegInt, cbor.KindBytes:
		kid, err := decodeCIDValue(v, raw)
		if err != nil {
			return IDCred{}, err
		}
		return IDCred{KID: kid}, nil
	case cbor.KindMap:
	default:
		return IDCred{}, fmt.Errorf("%w: ID_CRED must be a map, integer or byte string", ErrMessageFormat)
	}
	if len(v.Pairs) != 1 {
		return IDCred{}, fmt.Errorf("%w: ID_CRED with %d parameters is not supported", ErrMessageFormat, len(v.Pairs))
	}
	label, err := valueInt(v.Pairs[0].Key, "ID_CRED label")
	if err != nil {
		return IDCred{}, err
	}
	val := v.Pairs[0].Value
	switch label {
	case labelKID:
		if val.Kind != cbor.KindBytes {
			return IDCred{}, fmt.Errorf("%w: kid must be a byte string", ErrMessageFormat)
		}
		return IDCred{KID: append([]byte{}, val.Bstr...)}, nil
	case labelX5T:
		if val.Kind != cbor.KindArray || len(val.Items) != 2 || val.Items[1].Kind != cbor.KindBytes {
			return IDCred{}, fmt.Errorf("%w: x5t must be [alg, hash]", ErrMessageFormat)
		}
		alg, err := valueInt(val.Items[0], "x5t alg")
		if err != nil {
			return IDCred{}, err
		}
		return IDCred{X5T: &X5T{Alg: cose.Algorithm(alg), Hash: append([]byte{}, val.Items[1].Bstr...)}}, nil
	case labelX5Chain:
		switch val.Kind {
		case cbor.KindBytes:
			return IDCred{X5Chain: [][]byte{append([]byte{}, val.Bstr...)}}, nil
		case cbor.KindArray:
			chain := make([][]byte, 0, len(val.Items))
			for _, c := range val.Items {
				if c.Kind != cbor.KindBytes {
					return IDCred{}, fmt.Errorf("%w: x5chain entries must be byte strings", ErrMessageFormat)
				}
				chain = append(chain, append([]byte{}, c.Bstr...))
			}
			if len(chain) == 0 {
				return IDCred{}, fmt.Errorf("%w: empty x5chain", ErrMessageFormat)
			}
			return IDCred{X5Chain: chain}, nil
		}
		return IDCred{}, fmt.Errorf("%w: x5chain must be a byte string or array", ErrMessageFormat)
	case labelKCCS, labelKCWT:
		enc := valueBytes(val, raw, label)
		if label == labelKCCS {
			if val.Kind != cbor.KindMap {
				return IDCred{}, fmt.Errorf("%w: kccs must be a map", ErrMessageFormat)
			}
			return IDCred{KCCS: enc}, nil
		}
		return IDCred{KCWT: enc}, nil
	}
	return IDCred{}, fmt.Errorf("%w: unsupported ID_CRED label %d", ErrMessageFormat, label)
}

// valueBytes returns the encoding of a single-entry map's value: taken
// from raw when available (a1, one-byte label, value), else re-encoded.
func valueBytes(val cbor.Value, raw []byte, label int64) []byte {
	if len(raw) > 2 && raw[0] == 0xa1 && label < 24 && raw[1] == byte(label) {
		return append([]byte{}, raw[2:]...)
	}
	return item(val)
}

// encodeCID encodes a connection identifier (RFC 9528 §3.3.2): a byte
// string that is the one-byte encoding of an integer in -24..23 is sent
// as that integer; anything else as a byte string.
func encodeCID(raw []byte) []byte {
	if len(raw) == 1 && isOneByteInt(raw[0]) {
		return []byte{raw[0]}
	}
	return bstrItem(raw)
}

func isOneByteInt(b byte) bool { return b <= 0x17 || (b >= 0x20 && b <= 0x37) }

// decodeCIDValue reverses encodeCID. raw, when given, is v's encoding.
func decodeCIDValue(v cbor.Value, raw []byte) ([]byte, error) {
	switch v.Kind {
	case cbor.KindBytes:
		return append([]byte{}, v.Bstr...), nil
	case cbor.KindUint:
		if v.Num <= 23 {
			return []byte{byte(v.Num)}, nil
		}
	case cbor.KindNegInt:
		if v.Num <= 23 {
			return []byte{0x20 | byte(v.Num)}, nil
		}
	}
	return nil, fmt.Errorf("%w: identifier must be a byte string or an integer in -24..23", ErrMessageFormat)
}

// ConnectionID is a connection identifier C_I / C_R as a byte string.
// Config fields stay []byte; this type documents the encoding rules.
type ConnectionID []byte

// ConnectionIDFromInt returns the identifier that is sent as the CBOR
// integer n, which must be in -24..23 (RFC 9528 §3.3.2).
func ConnectionIDFromInt(n int8) (ConnectionID, error) {
	switch {
	case n >= 0 && n <= 23:
		return ConnectionID{byte(n)}, nil
	case n < 0 && n >= -24:
		return ConnectionID{0x20 | byte(-1-n)}, nil
	}
	return nil, fmt.Errorf("%w: %d is not a one-byte CBOR integer", ErrMessageFormat, n)
}

// EADItem is an External Authorization Data item (RFC 9528 §3.8). On
// the wire a critical item's label is negated.
type EADItem struct {
	Label    uint64
	Critical bool
	Value    []byte // nil when absent
}

func encodeEAD(items []EADItem) ([]byte, error) {
	var out []byte
	for _, e := range items {
		switch {
		case e.Critical && e.Label == 0:
			return nil, fmt.Errorf("%w: EAD label 0 (padding) cannot be critical", ErrMessageFormat)
		case e.Label > 1<<62:
			return nil, fmt.Errorf("%w: EAD label out of range", ErrMessageFormat)
		case e.Critical:
			out = append(out, item(cbor.NegInt(e.Label-1))...)
		default:
			out = append(out, item(cbor.Uint(e.Label))...)
		}
		if e.Value != nil {
			out = append(out, bstrItem(e.Value)...)
		}
	}
	return out, nil
}

// decodeEAD reads the EAD items remaining in r. accept decides whether
// a critical item is understood; without it, any critical item fails.
func decodeEAD(r *seqReader, accept func(EADItem) bool) ([]EADItem, error) {
	var items []EADItem
	for r.more() {
		v, _, err := r.next()
		if err != nil {
			return nil, err
		}
		var e EADItem
		switch v.Kind {
		case cbor.KindUint:
			e.Label = v.Num
		case cbor.KindNegInt:
			e.Label, e.Critical = v.Num+1, true
		default:
			return nil, fmt.Errorf("%w: EAD label must be an integer", ErrMessageFormat)
		}
		if r.more() {
			save := r.rest
			nv, _, err := r.next()
			if err != nil {
				return nil, err
			}
			if nv.Kind == cbor.KindBytes {
				e.Value = append([]byte{}, nv.Bstr...)
			} else {
				r.rest = save
			}
		}
		if e.Critical && (accept == nil || !accept(e)) {
			return nil, fmt.Errorf("%w: unsupported critical EAD item %d", ErrAuthentication, e.Label)
		}
		items = append(items, e)
	}
	return items, nil
}
