// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package asreceived finds data that Core Deterministic encoding would
// change rather than only re-serialize, and recovers the bytes it was
// received as, for the cose, cwt and eat modules. Those modules reject
// such data by default and, on request, carry it through verbatim; they
// never rewrite it silently.
//
// Re-serializing (shortest integers and floats, a bignum value written
// as the integer it equals, definite lengths) keeps the value (RFC 8949
// §3.4.3, §4.2). Two things don't:
//   - a NaN other than the quiet NaN f97e00 (a payload or the sign bit):
//     deterministic encoding writes every NaN as f97e00;
//   - a map key that is a bignum with an integer value: it becomes that
//     integer, which may be a different, registered key.
package asreceived

import (
	"bytes"
	"errors"
	"math"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/rfc8949"
)

// Canonical NaN bit patterns: f97e00 widened to float32 and float64.
const (
	nan32 = 0x7fc00000
	nan64 = 0x7ff8000000000000
)

// NonCanonicalNaN reports whether v is or contains (in an array, map
// key or value, or tag) a NaN that deterministic encoding would replace
// with f97e00.
func NonCanonicalNaN(v cbor.Value) bool {
	switch v.Kind {
	case cbor.KindFloat32:
		return math.IsNaN(float64(v.Float32Val())) && uint32(v.Num) != nan32
	case cbor.KindFloat64:
		return math.IsNaN(v.Float64Val()) && v.Num != nan64
	case cbor.KindArray, cbor.KindTag:
		for _, it := range v.Items {
			if NonCanonicalNaN(it) {
				return true
			}
		}
	case cbor.KindMap:
		for _, e := range v.Pairs {
			if NonCanonicalNaN(e.Key) || NonCanonicalNaN(e.Value) {
				return true
			}
		}
	}
	return false
}

// IntegerBignum reports whether k is a tag 2/3 bignum whose value fits
// a CBOR integer, so deterministic encoding writes it as that integer.
func IntegerBignum(k cbor.Value) bool {
	if k.Kind != cbor.KindTag || (k.Num != cbor.TagUnsignedBignum && k.Num != cbor.TagNegativeBignum) {
		return false
	}
	in := k.TagInner()
	return in.Kind == cbor.KindBytes && len(bytes.TrimLeft(in.Bstr, "\x00")) <= 8
}

// Span is the source bytes of one map entry.
type Span struct{ Key, Value []byte }

var errNotMap = errors.New("asreceived: not a map")

// MapSpans returns the source bytes of each entry of the map encoded in
// src, in order, after any leading self-describe tags (55799), which
// Decode strips the same way. The slices alias src. src must already
// have decoded successfully.
func MapSpans(src []byte) ([]Span, error) {
	for len(src) >= 3 && src[0] == 0xd9 && src[1] == 0xd9 && src[2] == 0xf7 {
		src = src[3:]
	}
	c := rfc8949.NewCursor(src, rfc8949.DecodeOpts{})
	if k, err := c.Kind(); err != nil || k != 0xa0 {
		return nil, errNotMap
	}
	n, err := c.EnterMap()
	if err != nil {
		return nil, err
	}
	var spans []Span
	if n >= 0 {
		spans = make([]Span, 0, n)
	}
	for i := 0; n < 0 || i < n; i++ {
		if n < 0 && c.AtBreak() {
			break
		}
		k, err := c.RawBytes()
		if err != nil {
			return nil, err
		}
		v, err := c.RawBytes()
		if err != nil {
			return nil, err
		}
		spans = append(spans, Span{Key: k, Value: v})
	}
	return spans, nil
}

// OneItem reports whether b is exactly one well-formed data item, so it
// can be spliced into encoder output.
func OneItem(b []byte) bool {
	n, err := rfc8949.NewCursor(b, rfc8949.DecodeOpts{}).Skip()
	return err == nil && n == len(b)
}

// ArraySpans returns the source bytes of each element of the array
// encoded in src, in order, after any leading self-describe tags. The
// slices alias src. src must already have decoded successfully.
func ArraySpans(src []byte) ([][]byte, error) {
	for len(src) >= 3 && src[0] == 0xd9 && src[1] == 0xd9 && src[2] == 0xf7 {
		src = src[3:]
	}
	c := rfc8949.NewCursor(src, rfc8949.DecodeOpts{})
	if k, err := c.Kind(); err != nil || k != 0x80 {
		return nil, errNotArray
	}
	n, err := c.EnterArray()
	if err != nil {
		return nil, err
	}
	var items [][]byte
	for i := 0; n < 0 || i < n; i++ {
		if n < 0 && c.AtBreak() {
			break
		}
		b, err := c.RawBytes()
		if err != nil {
			return nil, err
		}
		items = append(items, b)
	}
	return items, nil
}

var errNotArray = errors.New("asreceived: not an array")

// BignumInt64 returns the value of a bignum IntegerBignum matched, when
// it fits an int64.
func BignumInt64(k cbor.Value) (int64, bool) {
	if !IntegerBignum(k) {
		return 0, false
	}
	var u uint64
	for _, b := range bytes.TrimLeft(k.TagInner().Bstr, "\x00") {
		u = u<<8 | uint64(b)
	}
	if u > math.MaxInt64 {
		return 0, false
	}
	if k.Num == cbor.TagNegativeBignum {
		return -1 - int64(u), true
	}
	return int64(u), true
}
