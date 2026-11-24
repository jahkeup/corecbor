// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"github.com/jahkeup/corecbor/wire"
)

// --- RFC 8746: float arrays of any width, multi-dimensional and
// homogeneous arrays (proposal 037 C18) ---

// RFC 8746 §3 tags.
const (
	TagMultiDimArray            uint64 = 40   // row-major multi-dimensional array
	TagHomogeneousArray         uint64 = 41   // array whose elements share one type
	TagMultiDimArrayColumnMajor uint64 = 1040 // column-major multi-dimensional array
)

// AsFloat64Array returns the elements of an RFC 8746 float16, float32
// or float64 typed array (tags 80–82, 84–86) as float64. Every element
// widens exactly, NaN payloads and signs included. Float128 arrays (83,
// 87) don't fit; use AsFloat128Array. Errors wrap ErrMalformedTag.
func AsFloat64Array(t Value) ([]float64, error) {
	inner, id, err := expectTag(t, "float typed array", 80, 81, 82, 84, 85, 86, 83, 87)
	if err != nil {
		return nil, err
	}
	if id == 83 || id == 87 {
		return nil, fmt.Errorf("%w: tag %d: float128 elements don't fit a float64; use AsFloat128Array", ErrMalformedTag, id)
	}
	size := 2 << (id & 3)
	b, err := typedBytes(inner, id, size)
	if err != nil {
		return nil, err
	}
	var order binary.ByteOrder = binary.BigEndian
	if id >= 84 {
		order = binary.LittleEndian
	}
	out := make([]float64, len(b)/size)
	for i := range out {
		e := b[i*size:]
		switch size {
		case 2:
			out[i] = wire.DecodeFloat16(order.Uint16(e))
		case 4:
			out[i] = math.Float64frombits(floatBits64(Float32(math.Float32frombits(order.Uint32(e)))))
		default:
			out[i] = math.Float64frombits(order.Uint64(e))
		}
	}
	return out, nil
}

// AsFloat128Array returns the elements of an RFC 8746 float128 typed
// array (tags 83, 87) as exact big.Float values (113-bit precision);
// infinities become ±Inf. A NaN element has no big.Float form and is an
// error. Errors wrap ErrMalformedTag.
func AsFloat128Array(t Value) ([]*big.Float, error) {
	inner, id, err := expectTag(t, "float128 typed array", 83, 87)
	if err != nil {
		return nil, err
	}
	b, err := typedBytes(inner, id, 16)
	if err != nil {
		return nil, err
	}
	out := make([]*big.Float, len(b)/16)
	for i := range out {
		e := b[i*16 : i*16+16]
		var hi, lo uint64
		if id == 83 {
			hi, lo = binary.BigEndian.Uint64(e), binary.BigEndian.Uint64(e[8:])
		} else {
			lo, hi = binary.LittleEndian.Uint64(e), binary.LittleEndian.Uint64(e[8:])
		}
		f, ok := float128(hi, lo)
		if !ok {
			return nil, fmt.Errorf("%w: tag %d: element %d is a NaN, which big.Float can't hold", ErrMalformedTag, id, i)
		}
		out[i] = f
	}
	return out, nil
}

// float128 converts IEEE 754 binary128 bits to an exact big.Float. It
// reports false for a NaN.
func float128(hi, lo uint64) (*big.Float, bool) {
	neg := hi>>63 != 0
	exp := int(hi >> 48 & 0x7fff)
	mhi := hi & (1<<48 - 1) // top 48 of the 112 fraction bits
	f := new(big.Float).SetPrec(113)
	if exp == 0x7fff {
		if mhi != 0 || lo != 0 {
			return nil, false
		}
		return f.SetInf(neg), true
	}
	m := new(big.Int).Lsh(new(big.Int).SetUint64(mhi), 64)
	m.Or(m, new(big.Int).SetUint64(lo))
	if exp == 0 {
		exp = 1 // subnormal: no implicit bit
	} else {
		m.SetBit(m, 112, 1)
	}
	f.SetInt(m)
	f.SetMantExp(f, exp-16383-112)
	if neg {
		f.Neg(f)
	}
	return f, true
}

// typedBytes checks a typed array's content: a byte string whose length
// is a multiple of size.
func typedBytes(inner Value, id uint64, size int) ([]byte, error) {
	if inner.Kind != KindBytes {
		return nil, fmt.Errorf("%w: tag %d content must be a byte string", ErrMalformedTag, id)
	}
	if len(inner.Bstr)%size != 0 {
		return nil, fmt.Errorf("%w: tag %d: %d bytes is not a whole number of %d-byte elements", ErrMalformedTag, id, len(inner.Bstr), size)
	}
	return inner.Bstr, nil
}

// typedArrayLen returns the element count of an RFC 8746 typed array
// Value, or false if v isn't a well-formed one.
func typedArrayLen(v Value) (uint64, bool) {
	if v.Kind != KindTag || v.Num < 64 || v.Num > 87 || v.Num == 76 || len(v.Items) != 1 || v.Items[0].Kind != KindBytes {
		return 0, false
	}
	size := 1 << (v.Num & 3)
	if v.Num&0x10 != 0 {
		size <<= 1 // floats: 2, 4, 8, 16 bytes
	}
	n := len(v.Items[0].Bstr)
	return uint64(n / size), n%size == 0
}

// MultiDimArray is an RFC 8746 §3.1 multi-dimensional array: Shape
// lists the dimensions, and Data holds their product of elements in
// row-major order, or column-major when ColumnMajor is set (tag 1040
// rather than 40). Data is an array or an RFC 8746 typed array.
type MultiDimArray struct {
	Shape       []uint64
	Data        Value
	ColumnMajor bool
}

// MultiDimArrayTo returns m as tag 40 (or 1040 when column-major)
// around [dimensions, data]. It returns an error wrapping
// ErrMalformedTag when Shape is empty or Data isn't an array or typed
// array of exactly the product of the dimensions.
func MultiDimArrayTo(m MultiDimArray) (Value, error) {
	if err := checkMultiDim(m.Shape, m.Data); err != nil {
		return Value{}, err
	}
	dims := make([]Value, len(m.Shape))
	for i, d := range m.Shape {
		dims[i] = Uint(d)
	}
	tag := TagMultiDimArray
	if m.ColumnMajor {
		tag = TagMultiDimArrayColumnMajor
	}
	return MakeTag(tag, MakeArray(MakeArrayFromSlice(dims), m.Data)), nil
}

// AsMultiDimArray requires tag 40 or 1040 around [dimensions, data],
// with at least one dimension, each an unsigned integer, and data an
// array or typed array of their product of elements. Errors wrap
// ErrMalformedTag.
func AsMultiDimArray(t Value) (MultiDimArray, error) {
	inner, id, err := expectTag(t, "multi-dimensional array", TagMultiDimArray, TagMultiDimArrayColumnMajor)
	if err != nil {
		return MultiDimArray{}, err
	}
	if inner.Kind != KindArray || len(inner.Items) != 2 || inner.Items[0].Kind != KindArray {
		return MultiDimArray{}, fmt.Errorf("%w: tag %d content must be [dimensions, data]", ErrMalformedTag, id)
	}
	shape := make([]uint64, len(inner.Items[0].Items))
	for i, d := range inner.Items[0].Items {
		if d.Kind != KindUint {
			return MultiDimArray{}, fmt.Errorf("%w: tag %d: dimension %d is not an unsigned integer", ErrMalformedTag, id, i)
		}
		shape[i] = d.Num
	}
	if err := checkMultiDim(shape, inner.Items[1]); err != nil {
		return MultiDimArray{}, err
	}
	return MultiDimArray{Shape: shape, Data: inner.Items[1], ColumnMajor: id == TagMultiDimArrayColumnMajor}, nil
}

func checkMultiDim(shape []uint64, data Value) error {
	if len(shape) == 0 {
		return fmt.Errorf("%w: multi-dimensional array has no dimensions", ErrMalformedTag)
	}
	want := uint64(1)
	for _, d := range shape {
		hi, lo := bits.Mul64(want, d)
		if hi != 0 {
			return fmt.Errorf("%w: multi-dimensional array dimensions overflow", ErrMalformedTag)
		}
		want = lo
	}
	var have uint64
	switch data.Kind {
	case KindArray:
		have = uint64(len(data.Items))
	default:
		n, ok := typedArrayLen(data)
		if !ok {
			return fmt.Errorf("%w: multi-dimensional array data must be an array or a typed array", ErrMalformedTag)
		}
		have = n
	}
	if have != want {
		return fmt.Errorf("%w: multi-dimensional array holds %d elements, dimensions need %d", ErrMalformedTag, have, want)
	}
	return nil
}

// HomogeneousArrayTo returns items as tag 41, a homogeneous array
// (RFC 8746 §3.2). Items must all be of one type: the same Kind, with
// Uint and NegInt counting as integers and Float32 and Float64 as
// floats, and the same tag number for tags. Otherwise the error wraps
// ErrMalformedTag.
func HomogeneousArrayTo(items []Value) (Value, error) {
	if i, ok := homogeneous(items); !ok {
		return Value{}, fmt.Errorf("%w: homogeneous array element %d differs in type from element 0", ErrMalformedTag, i)
	}
	return MakeTag(TagHomogeneousArray, MakeArrayFromSlice(items)), nil
}

// AsHomogeneousArray requires tag 41 around an array whose elements are
// all of one type, as HomogeneousArrayTo defines it, and returns them.
// Errors wrap ErrMalformedTag.
func AsHomogeneousArray(t Value) ([]Value, error) {
	inner, _, err := expectTag(t, "homogeneous array", TagHomogeneousArray)
	if err != nil {
		return nil, err
	}
	if inner.Kind != KindArray {
		return nil, fmt.Errorf("%w: tag 41 content must be an array", ErrMalformedTag)
	}
	if i, ok := homogeneous(inner.Items); !ok {
		return nil, fmt.Errorf("%w: homogeneous array element %d differs in type from element 0", ErrMalformedTag, i)
	}
	return inner.Items, nil
}

// homogeneous reports whether items share one type, or the index of the
// first that doesn't.
func homogeneous(items []Value) (int, bool) {
	for i := 1; i < len(items); i++ {
		if !sameElemType(items[0], items[i]) {
			return i, false
		}
	}
	return 0, true
}

func sameElemType(a, b Value) bool {
	class := func(v Value) Kind {
		switch v.Kind {
		case KindNegInt:
			return KindUint
		case KindFloat32:
			return KindFloat64
		}
		return v.Kind
	}
	if class(a) != class(b) {
		return false
	}
	return a.Kind != KindTag || a.Num == b.Num
}
