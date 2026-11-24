// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/wire"
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

// IDCred is a parsed ID_CRED_x (RFC 9528 §3.5.3): a COSE header map
// that identifies or carries the sender's credential. The fields below
// are the parameters this package interprets; a received map may hold
// several, plus others in Other. A KID is sent in the compact form when
// it is the only parameter.
type IDCred struct {
	KID     []byte
	X5T     *X5T
	X5Chain [][]byte // DER certificates, leaf first
	KCCS    []byte   // encoded CWT Claims Set, by value
	KCWT    []byte   // encoded CWT, by value

	// Other holds the header parameters this package does not
	// interpret (for example kid context, label 10), in the order
	// received. A CredentialResolver sees them; when sending, they are
	// added to the map.
	Other []IDCredParam
	// Raw is ID_CRED_x exactly as received: the encoded header map, or
	// nil when ID_CRED_x arrived in the compact KID form. When set, it
	// is used byte-for-byte in MAC_2/MAC_3 and the Sig_structure
	// (RFC 9528 §3.5.3: labels need not be sorted), and sent as is.
	Raw []byte
}

// IDCredParam is a COSE header parameter in ID_CRED_x that this package
// does not interpret.
type IDCredParam struct {
	Label cbor.Value // an integer or a text string
	Value cbor.Value
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

// isReference reports whether id only references a credential (kid or
// x5t) rather than carrying one by value.
func (id IDCred) isReference() bool {
	return (id.KID != nil || id.X5T != nil) && id.X5Chain == nil && id.KCCS == nil && id.KCWT == nil
}

// identifies reports whether a received ID_CRED names the credential
// that pinned (a configured credential's IDCred) identifies: an equal
// kid, x5t or x5chain leaf, or byte-identical maps.
func (pinned IDCred) identifies(got IDCred) bool {
	switch {
	case pinned.KID != nil && got.KID != nil:
		return bytes.Equal(pinned.KID, got.KID)
	case pinned.X5T != nil && got.X5T != nil:
		return pinned.X5T.Alg == got.X5T.Alg && bytes.Equal(pinned.X5T.Hash, got.X5T.Hash)
	case len(pinned.X5Chain) > 0 && len(got.X5Chain) > 0:
		return bytes.Equal(pinned.X5Chain[0], got.X5Chain[0])
	}
	if pinned.set() == 0 && len(pinned.Other) == 0 {
		return false
	}
	a, errA := pinned.full()
	b, errB := got.full()
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

// full returns ID_CRED_x as a COSE header map: Raw when set, otherwise
// one entry per parameter, sorted by encoded label (deterministic).
// KCCS and KCWT are embedded byte-for-byte, so they enter the
// transcript exactly as given.
func (id IDCred) full() ([]byte, error) {
	if id.Raw != nil {
		return id.Raw, nil
	}
	type entry struct{ k, v []byte }
	var es []entry
	if id.KID != nil {
		es = append(es, entry{intItem(labelKID), bstrItem(id.KID)})
	}
	if id.X5T != nil {
		es = append(es, entry{intItem(labelX5T), encSeq([]byte{0x82}, intItem(int64(id.X5T.Alg)), bstrItem(id.X5T.Hash))})
	}
	if id.X5Chain != nil {
		v := []byte(nil)
		if len(id.X5Chain) == 1 {
			v = bstrItem(id.X5Chain[0])
		} else {
			items := []cbor.Value{}
			for _, c := range id.X5Chain {
				items = append(items, cbor.Bytes(c))
			}
			v = item(cbor.MakeArrayFromSlice(items))
		}
		es = append(es, entry{intItem(labelX5Chain), v})
	}
	if id.KCCS != nil {
		es = append(es, entry{intItem(labelKCCS), id.KCCS})
	}
	if id.KCWT != nil {
		es = append(es, entry{intItem(labelKCWT), id.KCWT})
	}
	for _, p := range id.Other {
		if p.Label.Kind != cbor.KindUint && p.Label.Kind != cbor.KindNegInt && p.Label.Kind != cbor.KindText {
			return nil, fmt.Errorf("%w: ID_CRED label must be an integer or text string", ErrMessageFormat)
		}
		es = append(es, entry{item(p.Label), item(p.Value)})
	}
	if len(es) == 0 {
		return nil, fmt.Errorf("%w: ID_CRED has no parameters", ErrMessageFormat)
	}
	if len(es) > 23 {
		return nil, fmt.Errorf("%w: ID_CRED has too many parameters", ErrMessageFormat)
	}
	slices.SortFunc(es, func(a, b entry) int { return bytes.Compare(a.k, b.k) })
	for i := 1; i < len(es); i++ {
		if bytes.Equal(es[i-1].k, es[i].k) {
			return nil, fmt.Errorf("%w: duplicate ID_CRED label", ErrMessageFormat)
		}
	}
	out := []byte{0xa0 | byte(len(es))}
	for _, e := range es {
		out = append(append(out, e.k...), e.v...)
	}
	return out, nil
}

// compact returns ID_CRED_x as it appears in PLAINTEXT_2/3: a KID-only
// ID_CRED is replaced by the KID itself (RFC 9528 §3.5.3.2), encoded
// like a connection identifier. The receiver rebuilds {4: kid}, so a
// Raw that is not exactly that encoding is sent in full.
func (id IDCred) compact() ([]byte, error) {
	if id.KID != nil && id.set() == 1 && len(id.Other) == 0 {
		canon := encSeq([]byte{0xa1}, intItem(labelKID), bstrItem(id.KID))
		if id.Raw == nil || bytes.Equal(id.Raw, canon) {
			return encodeCID(id.KID), nil
		}
	}
	return id.full()
}

// ParseIDCred parses an ID_CRED_x header map, or the compact KID form
// (an integer or byte string).
func ParseIDCred(v cbor.Value) (IDCred, error) {
	return parseIDCred(v, nil)
}

// parseIDCred parses v; raw, when given, is v's encoding, kept as Raw
// and used to take each parameter's value byte-for-byte.
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
	if len(v.Pairs) == 0 {
		return IDCred{}, fmt.Errorf("%w: ID_CRED has no parameters", ErrMessageFormat)
	}
	var vals [][]byte
	if raw != nil {
		var err error
		if vals, err = mapValueBytes(raw, len(v.Pairs)); err != nil {
			return IDCred{}, err
		}
	}
	var id IDCred
	if raw != nil {
		id.Raw = append([]byte{}, raw...)
	}
	for i, p := range v.Pairs {
		enc := func() []byte {
			if vals != nil {
				return append([]byte{}, vals[i]...)
			}
			return item(p.Value)
		}
		if p.Key.Kind == cbor.KindText {
			id.Other = append(id.Other, IDCredParam{Label: p.Key, Value: p.Value})
			continue
		}
		label, err := valueInt(p.Key, "ID_CRED label")
		if err != nil {
			return IDCred{}, err
		}
		if err := id.setParam(label, p.Value, enc); err != nil {
			return IDCred{}, err
		}
	}
	return id, nil
}

// setParam stores one ID_CRED parameter; enc returns its value's
// encoding.
func (id *IDCred) setParam(label int64, val cbor.Value, enc func() []byte) error {
	dup := fmt.Errorf("%w: duplicate ID_CRED label %d", ErrMessageFormat, label)
	switch label {
	case labelKID:
		if val.Kind != cbor.KindBytes {
			return fmt.Errorf("%w: kid must be a byte string", ErrMessageFormat)
		}
		if id.KID != nil {
			return dup
		}
		id.KID = append([]byte{}, val.Bstr...)
	case labelX5T:
		if val.Kind != cbor.KindArray || len(val.Items) != 2 || val.Items[1].Kind != cbor.KindBytes {
			return fmt.Errorf("%w: x5t must be [alg, hash]", ErrMessageFormat)
		}
		alg, err := valueInt(val.Items[0], "x5t alg")
		if err != nil {
			return err
		}
		if id.X5T != nil {
			return dup
		}
		id.X5T = &X5T{Alg: cose.Algorithm(alg), Hash: append([]byte{}, val.Items[1].Bstr...)}
	case labelX5Chain:
		if id.X5Chain != nil {
			return dup
		}
		switch val.Kind {
		case cbor.KindBytes:
			id.X5Chain = [][]byte{append([]byte{}, val.Bstr...)}
		case cbor.KindArray:
			chain := make([][]byte, 0, len(val.Items))
			for _, c := range val.Items {
				if c.Kind != cbor.KindBytes {
					return fmt.Errorf("%w: x5chain entries must be byte strings", ErrMessageFormat)
				}
				chain = append(chain, append([]byte{}, c.Bstr...))
			}
			if len(chain) == 0 {
				return fmt.Errorf("%w: empty x5chain", ErrMessageFormat)
			}
			if len(chain) == 1 {
				// RFC 9360 §2: a single certificate is a byte string.
				return fmt.Errorf("%w: x5chain with one certificate must be a byte string, not an array", ErrMessageFormat)
			}
			id.X5Chain = chain
		default:
			return fmt.Errorf("%w: x5chain must be a byte string or array", ErrMessageFormat)
		}
	case labelKCCS:
		if val.Kind != cbor.KindMap {
			return fmt.Errorf("%w: kccs must be a map", ErrMessageFormat)
		}
		if id.KCCS != nil {
			return dup
		}
		id.KCCS = enc()
	case labelKCWT:
		if id.KCWT != nil {
			return dup
		}
		id.KCWT = enc()
	default:
		id.Other = append(id.Other, IDCredParam{Label: intVal(label), Value: val})
	}
	return nil
}

// mapValueBytes returns the encoding of each value in the n-entry
// definite map encoded in raw, in order.
func mapValueBytes(raw []byte, n int) ([][]byte, error) {
	h := wire.ParseHead(raw)
	if h.N == 0 || h.Major != wire.MajorMap || h.Arg != uint64(n) {
		return nil, fmt.Errorf("%w: ID_CRED map encoding", ErrMessageFormat)
	}
	r := newSeqReader(raw[h.N:])
	out := make([][]byte, n)
	for i := range n {
		if _, _, err := r.next(); err != nil {
			return nil, err
		}
		_, vb, err := r.next()
		if err != nil {
			return nil, err
		}
		out[i] = vb
	}
	return out, nil
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
			return nil, fmt.Errorf("%w: %w %d", ErrAuthentication, ErrCriticalEAD, e.Label)
		}
		items = append(items, e)
	}
	return items, nil
}
