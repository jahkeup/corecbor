// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"math"

	"github.com/jahkeup/corecbor/internal/seedhash"
)

// valueHash hashes a Value's data-model form with the process-keyed
// hash, consistent with Equal: values Equal reports as equal hash
// equally. Keyed so that input can't be crafted to collide (proposal
// 037 C2); only performance depends on it. It follows the decoder's
// map-key hash (rfc8949 keyHash); keep the two in step.
func valueHash(v Value) uint64 {
	switch v.Kind {
	case KindText:
		return seedhash.String(v.Str) ^ seedhash.Salt(byte(KindText))
	case KindBytes:
		return seedhash.Bytes(v.Bstr) ^ seedhash.Salt(byte(KindBytes))
	case KindFloat32, KindFloat64:
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
	case KindArray:
		h := seedhash.Mix(uint64(len(v.Items)) ^ seedhash.Salt(byte(KindArray)))
		for i := range v.Items {
			h = seedhash.Mix(h ^ valueHash(v.Items[i]))
		}
		return h
	case KindTag:
		h := seedhash.Mix(v.Num ^ seedhash.Salt(byte(KindTag)))
		if len(v.Items) == 1 {
			h = seedhash.Mix(h ^ valueHash(v.Items[0]))
		}
		return h
	case KindMap:
		// Order-independent: combine pair hashes by addition.
		var sum uint64
		for i := range v.Pairs {
			sum += pairHash(&v.Pairs[i])
		}
		return seedhash.Mix(sum ^ seedhash.Mix(uint64(len(v.Pairs))^seedhash.Salt(byte(KindMap))))
	case KindNull, KindUndefined, KindInvalid:
		return seedhash.Salt(byte(v.Kind))
	default: // integers, bool, simple
		return seedhash.Mix(v.Num ^ seedhash.Salt(byte(v.Kind)))
	}
}

// pairHash hashes a map entry, key and value in order.
func pairHash(p *MapEntry) uint64 {
	return seedhash.Mix(seedhash.Mix(valueHash(p.Key)) ^ valueHash(p.Value))
}
