// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import "math"

// FNV-1a over a Value's data-model form, consistent with Equal: values
// Equal reports as equal hash equally. It is the same function the
// decoder's map-key tracking uses (rfc8949 keyHashInto); keep the two
// in step.
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

func pairHash(p *MapEntry) uint64 {
	return valueHash(valueHash(fnvOffset, p.Key), p.Value)
}

func valueHash(h uint64, v Value) uint64 {
	switch v.Kind {
	case KindFloat32, KindFloat64:
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
	case KindText:
		h = hashByte(h, byte(KindText))
		for i := 0; i < len(v.Str); i++ {
			h = hashByte(h, v.Str[i])
		}
		return h
	case KindBytes:
		h = hashByte(h, byte(KindBytes))
		for _, c := range v.Bstr {
			h = hashByte(h, c)
		}
		return h
	case KindArray:
		h = hashU64(hashByte(h, byte(v.Kind)), uint64(len(v.Items)))
		for i := range v.Items {
			h = valueHash(h, v.Items[i])
		}
		return h
	case KindTag:
		h = hashU64(hashByte(h, byte(v.Kind)), v.Num)
		if len(v.Items) == 1 {
			h = valueHash(h, v.Items[0])
		}
		return h
	case KindMap:
		// Order-independent: combine pair hashes by addition.
		var sum uint64
		for i := range v.Pairs {
			sum += pairHash(&v.Pairs[i])
		}
		return hashU64(hashU64(hashByte(h, byte(v.Kind)), uint64(len(v.Pairs))), sum)
	case KindNull, KindUndefined, KindInvalid:
		return hashByte(h, byte(v.Kind))
	default:
		return hashU64(hashByte(h, byte(v.Kind)), v.Num)
	}
}
