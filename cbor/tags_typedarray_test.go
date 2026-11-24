// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"bytes"
	"errors"
	"math"
	"slices"
	"testing"
)

func roundTripTyped[T TypedArrayElem](t *testing.T, s []T, be, le uint64) {
	t.Helper()
	for _, tc := range []struct {
		v   Value
		tag uint64
	}{{TypedArrayTo(s), be}, {TypedArrayToLE(s), le}} {
		if tc.v.TagID() != tc.tag {
			t.Fatalf("%T: tag %d, want %d", s, tc.v.TagID(), tc.tag)
		}
		got, err := AsTypedArray[T](tc.v)
		if err != nil || !slices.Equal(got, s) {
			t.Fatalf("%T tag %d: %v, %v; want %v", s, tc.tag, got, err, s)
		}
	}
}

// 037 C18: RFC 8746 typed arrays round-trip for every supported element
// type and byte order, with the RFC's tag numbers.
func TestTypedArrays(t *testing.T) {
	roundTripTyped(t, []uint8{0, 1, 255}, 64, 64)
	roundTripTyped(t, []uint16{1, 0xabcd}, 65, 69)
	roundTripTyped(t, []uint32{1, 0xdeadbeef}, 66, 70)
	roundTripTyped(t, []uint64{1, math.MaxUint64}, 67, 71)
	roundTripTyped(t, []int8{-128, 0, 127}, 72, 72)
	roundTripTyped(t, []int16{-1, math.MaxInt16}, 73, 77)
	roundTripTyped(t, []int32{-1, math.MinInt32}, 74, 78)
	roundTripTyped(t, []int64{-1, math.MinInt64}, 75, 79)
	roundTripTyped(t, []float32{1.5, float32(math.Inf(-1))}, 81, 85)
	roundTripTyped(t, []float64{-0.25, math.MaxFloat64}, 82, 86)
	roundTripTyped(t, []uint16{}, 65, 69)

	// Byte layout.
	if b := TypedArrayTo([]uint16{1, 2}).TagInner().BytesVal(); !bytes.Equal(b, []byte{0, 1, 0, 2}) {
		t.Fatalf("uint16 BE bytes %x", b)
	}
	if b := TypedArrayToLE([]uint16{1, 2}).TagInner().BytesVal(); !bytes.Equal(b, []byte{1, 0, 2, 0}) {
		t.Fatalf("uint16 LE bytes %x", b)
	}
	// Clamped uint8 is readable as []uint8.
	if got, err := AsTypedArray[uint8](MakeTag(TagUint8ClampedArray, Bytes([]byte{7}))); err != nil || got[0] != 7 {
		t.Fatalf("clamped: %v, %v", got, err)
	}

	for _, v := range []Value{
		MakeTag(65, Bytes([]byte{1})),          // odd length
		MakeTag(65, Text("ab")),                // not bytes
		MakeTag(66, Bytes([]byte{0, 0, 0, 1})), // uint32 read as uint16
		MakeTag(80, Bytes([]byte{0, 0})),       // float16: no Go type
		Bytes([]byte{0, 1}),                    // not a tag
	} {
		if _, err := AsTypedArray[uint16](v); !errors.Is(err, ErrMalformedTag) {
			t.Errorf("AsTypedArray[uint16](%v): err = %v, want ErrMalformedTag", v, err)
		}
	}
}
