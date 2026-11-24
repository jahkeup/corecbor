// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"encoding/binary"
	"fmt"
	"math"
)

// --- RFC 8746 §2: typed arrays ---

// TypedArrayElem lists the Go element types of the RFC 8746 typed
// arrays these helpers support: tags 64–75 and 77–79 (integers, in
// either byte order) and 81, 82, 85, 86 (float32 and float64). The
// float16 (80, 84) and float128 (83, 87) arrays have no Go element type;
// AsTypedArray rejects them. Read them with AsFloat64Array (float16,
// widened exactly) and AsFloat128Array.
type TypedArrayElem interface {
	uint8 | uint16 | uint32 | uint64 | int8 | int16 | int32 | int64 | float32 | float64
}

// TagUint8ClampedArray is the RFC 8746 tag for a uint8 array with
// clamped arithmetic (Uint8ClampedArray). AsTypedArray[uint8] accepts
// it; TypedArrayTo writes tag 64.
const TagUint8ClampedArray uint64 = 68

// typedArrayTags returns T's big- and little-endian typed array tags
// and its element size.
func typedArrayTags[T TypedArrayElem]() (be, le uint64, size int) {
	var zero T
	switch any(zero).(type) {
	case uint8:
		return 64, 64, 1
	case uint16:
		return 65, 69, 2
	case uint32:
		return 66, 70, 4
	case uint64:
		return 67, 71, 8
	case int8:
		return 72, 72, 1
	case int16:
		return 73, 77, 2
	case int32:
		return 74, 78, 4
	case int64:
		return 75, 79, 8
	case float32:
		return 81, 85, 4
	default: // float64
		return 82, 86, 8
	}
}

// TypedArrayTo returns s as an RFC 8746 typed array in big-endian
// (network) byte order: the tag for T around a byte string of the
// elements. A []uint8 or []int8 has a single tag (64, 72).
func TypedArrayTo[T TypedArrayElem](s []T) Value {
	be, _, size := typedArrayTags[T]()
	return MakeTag(be, Bytes(packTyped(s, size, binary.BigEndian)))
}

// TypedArrayToLE is TypedArrayTo in little-endian byte order.
func TypedArrayToLE[T TypedArrayElem](s []T) Value {
	_, le, size := typedArrayTags[T]()
	return MakeTag(le, Bytes(packTyped(s, size, binary.LittleEndian)))
}

// AsTypedArray returns the elements of t, an RFC 8746 typed array of T
// in either byte order; []uint8 also accepts the clamped array (tag
// 68). Errors wrap ErrMalformedTag: t is another tag or not a tag, its
// content is not a byte string, or the length is not a multiple of the
// element size.
func AsTypedArray[T TypedArrayElem](t Value) ([]T, error) {
	be, le, size := typedArrayTags[T]()
	ids := []uint64{be, le}
	if be == 64 {
		ids = append(ids, TagUint8ClampedArray)
	}
	inner, id, err := expectTag(t, "typed array", ids...)
	if err != nil {
		return nil, err
	}
	if inner.Kind != KindBytes {
		return nil, fmt.Errorf("%w: tag %d content must be a byte string", ErrMalformedTag, id)
	}
	b := inner.BytesVal()
	if len(b)%size != 0 {
		return nil, fmt.Errorf("%w: tag %d: %d bytes is not a whole number of %d-byte elements", ErrMalformedTag, id, len(b), size)
	}
	var order binary.ByteOrder = binary.BigEndian
	if id == le && le != be {
		order = binary.LittleEndian
	}
	return unpackTyped[T](b, size, order), nil
}

// packTyped writes the elements of s as size-byte values in order.
func packTyped[T TypedArrayElem](s []T, size int, order binary.ByteOrder) []byte {
	b := make([]byte, len(s)*size)
	switch s := any(s).(type) {
	case []uint8:
		copy(b, s)
	case []int8:
		for i, v := range s {
			b[i] = byte(v)
		}
	case []uint16:
		for i, v := range s {
			order.PutUint16(b[2*i:], v)
		}
	case []int16:
		for i, v := range s {
			order.PutUint16(b[2*i:], uint16(v))
		}
	case []uint32:
		for i, v := range s {
			order.PutUint32(b[4*i:], v)
		}
	case []int32:
		for i, v := range s {
			order.PutUint32(b[4*i:], uint32(v))
		}
	case []float32:
		for i, v := range s {
			order.PutUint32(b[4*i:], math.Float32bits(v))
		}
	case []uint64:
		for i, v := range s {
			order.PutUint64(b[8*i:], v)
		}
	case []int64:
		for i, v := range s {
			order.PutUint64(b[8*i:], uint64(v))
		}
	case []float64:
		for i, v := range s {
			order.PutUint64(b[8*i:], math.Float64bits(v))
		}
	}
	return b
}

// unpackTyped reads len(b)/size elements of T from b.
func unpackTyped[T TypedArrayElem](b []byte, size int, order binary.ByteOrder) []T {
	out := make([]T, len(b)/size)
	switch s := any(out).(type) {
	case []uint8:
		copy(s, b)
	case []int8:
		for i := range s {
			s[i] = int8(b[i])
		}
	case []uint16:
		for i := range s {
			s[i] = order.Uint16(b[2*i:])
		}
	case []int16:
		for i := range s {
			s[i] = int16(order.Uint16(b[2*i:]))
		}
	case []uint32:
		for i := range s {
			s[i] = order.Uint32(b[4*i:])
		}
	case []int32:
		for i := range s {
			s[i] = int32(order.Uint32(b[4*i:]))
		}
	case []float32:
		for i := range s {
			s[i] = math.Float32frombits(order.Uint32(b[4*i:]))
		}
	case []uint64:
		for i := range s {
			s[i] = order.Uint64(b[8*i:])
		}
	case []int64:
		for i := range s {
			s[i] = int64(order.Uint64(b[8*i:]))
		}
	case []float64:
		for i := range s {
			s[i] = math.Float64frombits(order.Uint64(b[8*i:]))
		}
	}
	return out
}
