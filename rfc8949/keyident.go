// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"bytes"
	"fmt"
	"math"
	"sync"

	"github.com/jahkeup/corecbor/cbor"
)

// KeyIdentity selects when two map keys are the same key for duplicate
// detection (proposal 024).
type KeyIdentity uint8

const (
	// KeyIdentityValue compares keys in the CBOR data model (RFC 8949
	// §5.6.1 + erratum 8589): 01 and 1800 are the same key, as are
	// f93c00 and fa3f800000; integer 1 and float 1.0 are not. Default.
	KeyIdentityValue KeyIdentity = iota
	// KeyIdentityEncoded treats keys as the same only when their encoded
	// bytes are identical: 01 and 1800 are different keys.
	KeyIdentityEncoded
)

// keysEqual reports whether a and b are the same map key in the CBOR
// data model (RFC 8949 §5.6.1, erratum 8589). With legacyFloat, floats
// compare as v0.2.2 did: same Kind and ==, so NaN never equals NaN and
// half/double never equal single.
func keysEqual(a, b cbor.Value, legacyFloat bool) bool {
	if !legacyFloat {
		// Text and integer keys, the common case, compare inline; the
		// rest use the data-model rule shared with cbor.Value.Equal.
		if a.Kind == b.Kind {
			switch a.Kind {
			case cbor.KindText:
				return a.Str == b.Str
			case cbor.KindUint, cbor.KindNegInt:
				return a.Num == b.Num
			}
		}
		return a.Equal(b)
	}
	af, bf := isFloat(a.Kind), isFloat(b.Kind)
	if af || bf {
		if !af || !bf {
			return false
		}
		if legacyFloat {
			if a.Kind != b.Kind {
				return false
			}
			if a.Kind == cbor.KindFloat32 {
				return a.Float32Val() == b.Float32Val()
			}
			return a.Float64Val() == b.Float64Val()
		}
		return floatKeysEqual(a, b)
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case cbor.KindUint, cbor.KindNegInt, cbor.KindBool, cbor.KindSimple:
		return a.Num == b.Num
	case cbor.KindNull, cbor.KindUndefined:
		return true
	case cbor.KindBytes:
		return bytes.Equal(a.Bstr, b.Bstr)
	case cbor.KindText:
		return a.Str == b.Str
	case cbor.KindArray:
		if len(a.Items) != len(b.Items) {
			return false
		}
		for i := range a.Items {
			if !keysEqual(a.Items[i], b.Items[i], legacyFloat) {
				return false
			}
		}
		return true
	case cbor.KindTag:
		return a.Num == b.Num && len(a.Items) == 1 && len(b.Items) == 1 &&
			keysEqual(a.Items[0], b.Items[0], legacyFloat)
	case cbor.KindMap:
		// Maps are equal when they hold the same pairs, in any order.
		if len(a.Pairs) != len(b.Pairs) {
			return false
		}
		used := make([]bool, len(b.Pairs))
	outer:
		for _, pa := range a.Pairs {
			for j, pb := range b.Pairs {
				if !used[j] && keysEqual(pa.Key, pb.Key, legacyFloat) && keysEqual(pa.Value, pb.Value, legacyFloat) {
					used[j] = true
					continue outer
				}
			}
			return false
		}
		return true
	default:
		return false
	}
}

func isFloat(k cbor.Kind) bool { return k == cbor.KindFloat32 || k == cbor.KindFloat64 }

// floatBits64 returns f's value as binary64 bits, zero-extending a
// single-precision NaN significand rather than converting it, so NaN
// payloads compare as erratum 8589 specifies.
func floatBits64(v cbor.Value) uint64 {
	if v.Kind == cbor.KindFloat32 {
		b := uint32(v.Num)
		if b&0x7f800000 == 0x7f800000 && b&0x7fffff != 0 { // NaN
			return uint64(b>>31)<<63 | 0x7ff<<52 | uint64(b&0x7fffff)<<29
		}
		return math.Float64bits(float64(math.Float32frombits(b)))
	}
	return v.Num
}

func floatKeysEqual(a, b cbor.Value) bool {
	ab, bb := floatBits64(a), floatBits64(b)
	fa, fb := math.Float64frombits(ab), math.Float64frombits(bb)
	an, bn := math.IsNaN(fa), math.IsNaN(fb)
	if an || bn {
		// Erratum 8589: equal when significands (zero-extended to
		// binary64) and sign bits match.
		return an && bn && ab == bb
	}
	return fa == fb // value equality; +0 == -0
}

// FNV-1a over a Value's data-model form. Consistent with keysEqual
// (non-legacy): equal keys hash equally. Legacy float equality is
// strictly finer, so the same hash serves it too.
const (
	fnvOffset = 14695981039346656037
	fnvPrime  = 1099511628211
)

func hashByte(h uint64, b byte) uint64 { return (h ^ uint64(b)) * fnvPrime }

func hashU64(h uint64, n uint64) uint64 {
	for range 8 {
		h = hashByte(h, byte(n))
		n >>= 8
	}
	return h
}

// keyHash hashes a key's data-model form. Text keys, the common case,
// take an inlined loop instead of keyHashInto's recursive switch; the
// result is identical to keyHashInto for them.
func keyHash(v cbor.Value) uint64 {
	if v.Kind == cbor.KindText {
		h := uint64(fnvOffset)
		h = (h ^ uint64(cbor.KindText)) * fnvPrime
		for i := 0; i < len(v.Str); i++ {
			h = (h ^ uint64(v.Str[i])) * fnvPrime
		}
		return h
	}
	return keyHashInto(fnvOffset, v)
}

func keyHashInto(h uint64, v cbor.Value) uint64 {
	switch v.Kind {
	case cbor.KindFloat32, cbor.KindFloat64:
		bits := floatBits64(v)
		f := math.Float64frombits(bits)
		h = hashByte(h, 'f')
		switch {
		case f == 0:
			return hashByte(h, 0) // +0 and -0
		case math.IsNaN(f):
			return hashU64(hashByte(h, 'n'), bits)
		default:
			return hashU64(h, bits)
		}
	case cbor.KindText:
		h = (h ^ uint64(cbor.KindText)) * fnvPrime
		for i := 0; i < len(v.Str); i++ {
			h = (h ^ uint64(v.Str[i])) * fnvPrime
		}
		return h
	case cbor.KindBytes:
		h = (h ^ uint64(cbor.KindBytes)) * fnvPrime
		for _, c := range v.Bstr {
			h = (h ^ uint64(c)) * fnvPrime
		}
		return h
	case cbor.KindArray:
		h = hashU64(hashByte(h, byte(v.Kind)), uint64(len(v.Items)))
		for i := range v.Items {
			h = keyHashInto(h, v.Items[i])
		}
		return h
	case cbor.KindTag:
		h = hashU64(hashByte(h, byte(v.Kind)), v.Num)
		if len(v.Items) == 1 {
			h = keyHashInto(h, v.Items[0])
		}
		return h
	case cbor.KindMap:
		// Order-independent: combine pair hashes by addition.
		var sum uint64
		for i := range v.Pairs {
			ph := keyHashInto(fnvOffset, v.Pairs[i].Key)
			ph = keyHashInto(ph, v.Pairs[i].Value)
			sum += ph
		}
		return hashU64(hashU64(hashByte(h, byte(v.Kind)), uint64(len(v.Pairs))), sum)
	default:
		return hashU64(hashByte(h, byte(v.Kind)), v.Num)
	}
}

// keySet tracks the keys of one map being decoded, for duplicate
// handling under the configured KeyIdentity. Maps of up to
// dedupThreshold entries scan linearly; larger ones hash. Both use the
// same predicate, so the result doesn't depend on map size.
type keySet struct {
	seen   map[uint64][]int
	enc    [][]byte // encoded key per entry (KeyIdentityEncoded)
	hashed bool     // use seen; otherwise scan linearly
}

var keySetPool = sync.Pool{
	New: func() any { return &keySet{seen: make(map[uint64][]int, 32)} },
}

// getKeySet returns the key tracker for a map of count entries (count
// < 0 for indefinite length), or nil when a plain linear scan of the
// decoded entries suffices. Callers must putKeySet a non-nil result.
func getKeySet(count int, opts *DecodeOpts) *keySet {
	if opts.KeepDuplicateMapKeys {
		return nil
	}
	hashed := count < 0 || count > dedupThreshold
	if !hashed && opts.KeyIdentity != KeyIdentityEncoded {
		return nil
	}
	ks := keySetPool.Get().(*keySet)
	clear(ks.seen)
	ks.enc = ks.enc[:0]
	ks.hashed = hashed
	return ks
}

func putKeySet(ks *keySet) {
	if ks != nil {
		clear(ks.enc) // drop references into the source buffer
		keySetPool.Put(ks)
	}
}

// find returns the index of an entry in m whose key is the same key as
// key (encoded as enc), or -1, plus the key's hash when ks hashes, so
// add doesn't hash the key a second time.
func (ks *keySet) find(m []cbor.MapEntry, key cbor.Value, enc []byte, opts *DecodeOpts) (int, uint64) {
	if ks == nil {
		for i := range m {
			if keysEqual(m[i].Key, key, opts.LegacyFloatKeyEquality) {
				return i, 0
			}
		}
		return -1, 0
	}
	if !ks.hashed {
		for i, e := range ks.enc {
			if bytes.Equal(e, enc) {
				return i, 0
			}
		}
		return -1, 0
	}
	encoded := opts.KeyIdentity == KeyIdentityEncoded
	var h uint64
	if encoded {
		h = fnv1a(enc)
	} else {
		h = keyHash(key)
	}
	for _, idx := range ks.seen[h] {
		if encoded {
			if bytes.Equal(ks.enc[idx], enc) {
				return idx, h
			}
		} else if keysEqual(m[idx].Key, key, opts.LegacyFloatKeyEquality) {
			return idx, h
		}
	}
	return -1, h
}

// add records that entry index idx has key (encoded as enc) with hash h
// from find.
func (ks *keySet) add(idx int, enc []byte, h uint64, opts *DecodeOpts) {
	if ks == nil {
		return
	}
	if opts.KeyIdentity == KeyIdentityEncoded {
		ks.enc = append(ks.enc, enc)
	}
	if ks.hashed {
		ks.seen[h] = append(ks.seen[h], idx)
	}
}

// mapInsert adds key/val to m under the configured duplicate policy:
// keep every entry (KeepDuplicateMapKeys), reject a repeat
// (RejectDuplicateMapKeys), or last-write-wins (default: the repeated
// key keeps its first position and takes the new value). It returns the
// index of the entry that now holds val.
func mapInsert(m []cbor.MapEntry, key, val cbor.Value, keyOff int, encodedKey []byte, ks *keySet, opts *DecodeOpts) ([]cbor.MapEntry, int, error) {
	if opts.KeepDuplicateMapKeys {
		return append(m, cbor.MapEntry{Key: key, Value: val}), len(m), nil
	}
	idx, h := ks.find(m, key, encodedKey, opts)
	if idx >= 0 {
		if opts.RejectDuplicateMapKeys {
			return m, idx, decodeErr(cbor.ErrDuplicateMapKey, keyOff)
		}
		m[idx].Value = val
		return m, idx, nil
	}
	ks.add(len(m), encodedKey, h, opts)
	return append(m, cbor.MapEntry{Key: key, Value: val}), len(m), nil
}

// EntrySpan locates one entry of a decoded map in the source bytes: the
// key as it first appeared and the value that was kept for it (the last
// one written, under last-write-wins).
type EntrySpan struct {
	KeyStart, KeyEnd     int
	ValueStart, ValueEnd int
}

// recordSpan records that entry idx was written from the key at
// keyOff..valOff and the value at valOff..valEnd. A repeat key keeps the
// first key span and takes the new value span.
func recordSpan(rec *[]EntrySpan, idx, keyOff, valOff, valEnd int) {
	if idx == len(*rec) {
		*rec = append(*rec, EntrySpan{KeyStart: keyOff, KeyEnd: valOff, ValueStart: valOff, ValueEnd: valEnd})
		return
	}
	(*rec)[idx].ValueStart, (*rec)[idx].ValueEnd = valOff, valEnd
}

// MapEntrySpans decodes the map at the start of src with opts and
// returns it together with the source span of each of its entries, in
// the decoded order. The spans reflect exactly how this decoder resolves
// repeated keys under opts (key identity and duplicate policy), so a
// caller that walks the bytes — for example to hand an Unmarshaler its
// item's original bytes — stays aligned with the decoded Value. src must
// begin with a map head; it is decoded as a nested item (a leading
// self-describe tag is not stripped).
func MapEntrySpans(src []byte, opts DecodeOpts) (cbor.Value, []EntrySpan, error) {
	var spans []EntrySpan
	opts.spans = &spans
	v, _, err := decodeValue(src, 0, 0, opts, false)
	if err != nil {
		return cbor.Value{}, nil, err
	}
	if v.Kind != cbor.KindMap {
		return cbor.Value{}, nil, fmt.Errorf("%w: MapEntrySpans: item is kind %d, not a map", ErrTypeMismatch, v.Kind)
	}
	return v, spans, nil
}
