// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"bytes"
	"math"
	"sync"

	"github.com/jahkeup/corecbor/cbor"
)

// KeyIdentity selects when two map keys are the same key for duplicate
// detection (proposal 024).
type KeyIdentity int

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

func hashBytes(h uint64, b []byte) uint64 {
	for _, c := range b {
		h = hashByte(h, c)
	}
	return h
}

func keyHash(v cbor.Value) uint64 { return keyHashInto(fnvOffset, v) }

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
		h = hashByte(h, byte(v.Kind))
		for i := 0; i < len(v.Str); i++ {
			h = hashByte(h, v.Str[i])
		}
		return h
	case cbor.KindBytes:
		return hashBytes(hashByte(h, byte(v.Kind)), v.Bstr)
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
// key (encoded as enc), or -1.
func (ks *keySet) find(m []cbor.MapEntry, key cbor.Value, enc []byte, opts *DecodeOpts) int {
	encoded := opts.KeyIdentity == KeyIdentityEncoded
	if ks == nil {
		for i := range m {
			if keysEqual(m[i].Key, key, opts.LegacyFloatKeyEquality) {
				return i
			}
		}
		return -1
	}
	if !ks.hashed {
		for i, e := range ks.enc {
			if bytes.Equal(e, enc) {
				return i
			}
		}
		return -1
	}
	var h uint64
	if encoded {
		h = fnv1a(enc)
	} else {
		h = keyHash(key)
	}
	for _, idx := range ks.seen[h] {
		if encoded {
			if bytes.Equal(ks.enc[idx], enc) {
				return idx
			}
		} else if keysEqual(m[idx].Key, key, opts.LegacyFloatKeyEquality) {
			return idx
		}
	}
	return -1
}

// add records that entry index idx has key (encoded as enc).
func (ks *keySet) add(idx int, key cbor.Value, enc []byte, opts *DecodeOpts) {
	if ks == nil {
		return
	}
	encoded := opts.KeyIdentity == KeyIdentityEncoded
	if encoded {
		ks.enc = append(ks.enc, enc)
	}
	if !ks.hashed {
		return
	}
	var h uint64
	if encoded {
		h = fnv1a(enc)
	} else {
		h = keyHash(key)
	}
	ks.seen[h] = append(ks.seen[h], idx)
}

// mapInsert adds key/val to m under the configured duplicate policy:
// keep every entry (KeepDuplicateMapKeys), reject a repeat
// (RejectDuplicateMapKeys), or last-write-wins (default: the repeated
// key keeps its first position and takes the new value).
func mapInsert(m []cbor.MapEntry, key, val cbor.Value, keyOff int, encodedKey []byte, ks *keySet, opts DecodeOpts) ([]cbor.MapEntry, error) {
	if opts.KeepDuplicateMapKeys {
		return append(m, cbor.MapEntry{Key: key, Value: val}), nil
	}
	if idx := ks.find(m, key, encodedKey, &opts); idx >= 0 {
		if opts.RejectDuplicateMapKeys {
			return m, decodeErr(cbor.ErrDuplicateMapKey, keyOff)
		}
		m[idx].Value = val
		return m, nil
	}
	ks.add(len(m), key, encodedKey, &opts)
	return append(m, cbor.MapEntry{Key: key, Value: val}), nil
}
