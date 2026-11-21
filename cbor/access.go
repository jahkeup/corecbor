// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"bytes"
	"fmt"
	"math"
)

// Get returns the value associated with key in a Map, comparing keys
// with Equal. It returns false if v is not a Map or the key is absent.
// If the map holds duplicate keys the first match wins; callers that
// must reject duplicates decode with RejectDuplicateMapKeys. Lookup is a
// linear scan.
func (v Value) Get(key Value) (Value, bool) {
	if v.Kind != KindMap {
		return Value{}, false
	}
	for i := range v.Pairs {
		if v.Pairs[i].Key.Equal(key) {
			return v.Pairs[i].Value, true
		}
	}
	return Value{}, false
}

// GetInt is Get with an integer key (Uint for n >= 0, NegInt for n < 0),
// the common case for COSE header labels and CWT claim keys. It doesn't
// match text keys such as "1".
func (v Value) GetInt(n int64) (Value, bool) {
	if v.Kind != KindMap {
		return Value{}, false
	}
	kind, num := KindUint, uint64(n)
	if n < 0 {
		kind, num = KindNegInt, uint64(-1-n)
	}
	for i := range v.Pairs {
		if k := &v.Pairs[i].Key; k.Kind == kind && k.Num == num {
			return v.Pairs[i].Value, true
		}
	}
	return Value{}, false
}

// GetText is Get with a Text key.
func (v Value) GetText(s string) (Value, bool) {
	if v.Kind != KindMap {
		return Value{}, false
	}
	for i := range v.Pairs {
		if k := &v.Pairs[i].Key; k.Kind == KindText && k.Str == s {
			return v.Pairs[i].Value, true
		}
	}
	return Value{}, false
}

// Int64 returns the integer value of a Uint or NegInt. It returns an
// error wrapping ErrOverflow outside [math.MinInt64, math.MaxInt64] and
// ErrTypeMismatch for any other kind.
func (v Value) Int64() (int64, error) {
	switch v.Kind {
	case KindUint:
		if v.Num > math.MaxInt64 {
			return 0, fmt.Errorf("%w: %d does not fit in int64", ErrOverflow, v.Num)
		}
		return int64(v.Num), nil
	case KindNegInt:
		if v.Num > math.MaxInt64 {
			return 0, fmt.Errorf("%w: -1-%d does not fit in int64", ErrOverflow, v.Num)
		}
		return -1 - int64(v.Num), nil
	default:
		return 0, fmt.Errorf("%w: Int64 of %s", ErrTypeMismatch, v.Kind)
	}
}

// Uint64 returns the value of a Uint. It returns an error wrapping
// ErrTypeMismatch for any other kind, including NegInt.
func (v Value) Uint64() (uint64, error) {
	if v.Kind != KindUint {
		return 0, fmt.Errorf("%w: Uint64 of %s", ErrTypeMismatch, v.Kind)
	}
	return v.Num, nil
}

// Equal reports whether v and w are the same value in the CBOR data
// model (RFC 8949 §2, §5.6.1 with erratum 8589), the rule the decoder
// uses for map key identity by default: integers, strings and simple
// values compare by kind and value; floats compare by value whatever
// their encoded width (+0 equals -0; 1.0 as float32 equals 1.0 as
// float64), and NaNs are equal only when their payloads and sign bits
// match; integer 1 and float 1.0 are different; arrays compare
// element-wise; maps compare as unordered sets of pairs; tags compare
// number and content.
func (v Value) Equal(w Value) bool {
	vf, wf := isFloatKind(v.Kind), isFloatKind(w.Kind)
	if vf || wf {
		return vf && wf && floatEqual(v, w)
	}
	if v.Kind != w.Kind {
		return false
	}
	switch v.Kind {
	case KindUint, KindNegInt, KindBool, KindSimple:
		return v.Num == w.Num
	case KindNull, KindUndefined, KindInvalid:
		return true
	case KindBytes:
		return bytes.Equal(v.Bstr, w.Bstr)
	case KindText:
		return v.Str == w.Str
	case KindArray:
		if len(v.Items) != len(w.Items) {
			return false
		}
		for i := range v.Items {
			if !v.Items[i].Equal(w.Items[i]) {
				return false
			}
		}
		return true
	case KindTag:
		return v.Num == w.Num && len(v.Items) == len(w.Items) &&
			(len(v.Items) == 0 || v.Items[0].Equal(w.Items[0]))
	case KindMap:
		if len(v.Pairs) != len(w.Pairs) {
			return false
		}
		used := make([]bool, len(w.Pairs))
	outer:
		for _, p := range v.Pairs {
			for j, q := range w.Pairs {
				if !used[j] && p.Key.Equal(q.Key) && p.Value.Equal(q.Value) {
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

func isFloatKind(k Kind) bool { return k == KindFloat32 || k == KindFloat64 }

// floatBits64 returns a float Value's value as binary64 bits. A float32
// NaN's significand is zero-extended rather than converted, so NaN
// payloads compare as erratum 8589 specifies.
func floatBits64(v Value) uint64 {
	if v.Kind == KindFloat32 {
		b := uint32(v.Num)
		if b&0x7f800000 == 0x7f800000 && b&0x7fffff != 0 { // NaN
			return uint64(b>>31)<<63 | 0x7ff<<52 | uint64(b&0x7fffff)<<29
		}
		return math.Float64bits(float64(math.Float32frombits(b)))
	}
	return v.Num
}

func floatEqual(a, b Value) bool {
	ab, bb := floatBits64(a), floatBits64(b)
	fa, fb := math.Float64frombits(ab), math.Float64frombits(bb)
	an, bn := math.IsNaN(fa), math.IsNaN(fb)
	if an || bn {
		return an && bn && ab == bb
	}
	return fa == fb
}
