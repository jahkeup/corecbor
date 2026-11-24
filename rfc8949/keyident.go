// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"bytes"
	"fmt"
	"math"
	"sync"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/internal/pairmatch"
	"github.com/jahkeup/corecbor/internal/seedhash"
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
		if len(a.Pairs) > pairmatch.Small {
			// Linear rather than quadratic (037 C2). Legacy equality is
			// finer than the data model, so keyHash serves it too.
			ap, bp := a.Pairs, b.Pairs
			return pairmatch.Match(len(ap),
				func(i int) uint64 { return pairKeyHash(&ap[i]) },
				func(j int) uint64 { return pairKeyHash(&bp[j]) },
				func(i, j int) bool {
					return keysEqual(ap[i].Key, bp[j].Key, legacyFloat) && keysEqual(ap[i].Value, bp[j].Value, legacyFloat)
				})
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

// keyHash hashes a key's data-model form with the process-keyed hash
// (internal/seedhash), so input can't be crafted to collide (037 C2).
// Consistent with keysEqual (non-legacy): equal keys hash equally.
// Legacy float equality is strictly finer, so the same hash serves it
// too. Text and integer keys, the common case, take the short paths.
func keyHash(v cbor.Value) uint64 {
	switch v.Kind {
	case cbor.KindText:
		return seedhash.String(v.Str) ^ seedhash.Salt(byte(cbor.KindText))
	case cbor.KindBytes:
		return seedhash.Bytes(v.Bstr) ^ seedhash.Salt(byte(cbor.KindBytes))
	case cbor.KindFloat32, cbor.KindFloat64:
		bits := floatBits64(v)
		f := math.Float64frombits(bits)
		switch {
		case f == 0:
			return seedhash.Salt('f') // +0 and -0
		case math.IsNaN(f):
			return seedhash.Mix(bits ^ seedhash.Salt('n'))
		default:
			return seedhash.Mix(bits ^ seedhash.Salt('f'))
		}
	case cbor.KindArray:
		h := seedhash.Mix(uint64(len(v.Items)) ^ seedhash.Salt(byte(cbor.KindArray)))
		for i := range v.Items {
			h = seedhash.Mix(h ^ keyHash(v.Items[i]))
		}
		return h
	case cbor.KindTag:
		h := seedhash.Mix(v.Num ^ seedhash.Salt(byte(cbor.KindTag)))
		if len(v.Items) == 1 {
			h = seedhash.Mix(h ^ keyHash(v.Items[0]))
		}
		return h
	case cbor.KindMap:
		// Order-independent: combine pair hashes by addition.
		var sum uint64
		for i := range v.Pairs {
			sum += pairKeyHash(&v.Pairs[i])
		}
		return seedhash.Mix(sum ^ seedhash.Mix(uint64(len(v.Pairs))^seedhash.Salt(byte(cbor.KindMap))))
	case cbor.KindNull, cbor.KindUndefined, cbor.KindInvalid:
		return seedhash.Salt(byte(v.Kind))
	default: // integers, bool, simple
		return seedhash.Mix(v.Num ^ seedhash.Salt(byte(v.Kind)))
	}
}

// pairKeyHash hashes a map entry, key and value in order.
func pairKeyHash(p *cbor.MapEntry) uint64 {
	return seedhash.Mix(seedhash.Mix(keyHash(p.Key)) ^ keyHash(p.Value))
}

// keySet tracks the keys of one map being decoded, for duplicate
// handling under the configured KeyIdentity. Maps of up to
// dedupThreshold entries scan linearly; larger ones hash. Both use the
// same predicate, so the result doesn't depend on map size.
//
// Hashed lookups use a chain rather than a slice per hash: head maps a
// hash to 1 + the index of the most recent entry with that hash, and
// next[i] is 1 + the index of the previous entry sharing entry i's hash
// (0 ends a chain). Both are reused through keySetPool, so tracking a
// map's keys doesn't allocate per key once the pool is warm.
type keySet struct {
	head   map[uint64]int32
	next   []int32
	enc    [][]byte // encoded key per entry (KeyIdentityEncoded)
	hashed bool     // use head/next; otherwise scan linearly
}

var keySetPool = sync.Pool{
	New: func() any { return &keySet{head: make(map[uint64]int32, 32)} },
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
	clear(ks.head)
	ks.next = ks.next[:0]
	ks.enc = ks.enc[:0]
	ks.hashed = hashed
	return ks
}

// hashKeySet switches the tracker of a map whose entries so far are m
// to hashed lookups, taking one from the pool when ks is nil (a small
// map under value identity tracks no state). The keys in m are distinct.
func hashKeySet(ks *keySet, m []cbor.MapEntry, opts *DecodeOpts) *keySet {
	if ks == nil {
		ks = getKeySet(-1, opts)
	}
	ks.hashed = true
	ks.next = ks.next[:0]
	encoded := opts.KeyIdentity == KeyIdentityEncoded
	for i := range m {
		var h uint64
		if encoded {
			h = seedhash.Bytes(ks.enc[i])
		} else {
			h = keyHash(m[i].Key)
		}
		ks.next = append(ks.next, ks.head[h])
		ks.head[h] = int32(i + 1)
	}
	return ks
}

func putKeySet(ks *keySet) {
	if ks != nil {
		clear(ks.enc) // drop references into the source buffer
		keySetPool.Put(ks)
	}
}

// sameKey reports whether stored key a and key b are the same key in the
// data model. Text and integer keys compare directly; other kinds go
// through keysEqual.
func sameKey(a *cbor.Value, b *cbor.Value, legacyFloat bool) bool {
	switch b.Kind {
	case cbor.KindText, cbor.KindUint, cbor.KindNegInt:
		return a.Kind == b.Kind && a.Num == b.Num && a.Str == b.Str
	}
	return keysEqual(*a, *b, legacyFloat)
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
		h = seedhash.Bytes(enc)
	} else {
		h = keyHash(key)
	}
	for link := ks.head[h]; link != 0; link = ks.next[link-1] {
		idx := int(link - 1)
		if encoded {
			if bytes.Equal(ks.enc[idx], enc) {
				return idx, h
			}
		} else if sameKey(&m[idx].Key, &key, opts.LegacyFloatKeyEquality) {
			return idx, h
		}
	}
	return -1, h
}

// add records that entry index idx (always the next entry, len(m)) has
// key (encoded as enc) with hash h from find.
func (ks *keySet) add(idx int, enc []byte, h uint64, opts *DecodeOpts) {
	if ks == nil {
		return
	}
	if opts.KeyIdentity == KeyIdentityEncoded {
		ks.enc = append(ks.enc, enc)
	}
	if ks.hashed {
		ks.next = append(ks.next, ks.head[h])
		ks.head[h] = int32(idx + 1)
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
	var idx int
	var h uint64
	if ks == nil && (key.Kind == cbor.KindText || key.Kind == cbor.KindUint || key.Kind == cbor.KindNegInt) {
		// Small map with a text or integer key: in the data model such a
		// key equals another key only if both have the same kind and the
		// same string or number, so compare directly instead of going
		// through keysEqual (the forgiving decode hot path).
		idx = -1
		for i := range m {
			k := &m[i].Key
			if k.Kind == key.Kind && k.Num == key.Num && k.Str == key.Str {
				idx = i
				break
			}
		}
	} else {
		idx, h = ks.find(m, key, encodedKey, opts)
	}
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
