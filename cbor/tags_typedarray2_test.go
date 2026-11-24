// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"errors"
	"math"
	"math/big"
	"slices"
	"testing"
)

// 037 C18: AsFloat64Array widens float16, float32 and float64 typed
// arrays exactly, in either byte order.
func TestAsFloat64Array(t *testing.T) {
	want := []float64{1.5, -2, math.Inf(1), 65504}
	for _, tc := range []struct {
		tag uint64
		b   []byte
	}{
		{80, []byte{0x3e, 0x00, 0xc0, 0x00, 0x7c, 0x00, 0x7b, 0xff}},
		{84, []byte{0x00, 0x3e, 0x00, 0xc0, 0x00, 0x7c, 0xff, 0x7b}},
	} {
		got, err := AsFloat64Array(MakeTag(tc.tag, Bytes(tc.b)))
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("tag %d: %v, %v", tc.tag, got, err)
		}
	}
	for _, v := range []Value{TypedArrayTo([]float32{1.5, -2}), TypedArrayToLE([]float64{1.5, -2})} {
		got, err := AsFloat64Array(v)
		if err != nil || !slices.Equal(got, []float64{1.5, -2}) {
			t.Fatalf("%v: %v, %v", v, got, err)
		}
	}
	// A float16 NaN keeps its payload bits (widened, not canonicalized).
	got, err := AsFloat64Array(MakeTag(80, Bytes([]byte{0x7e, 0x01})))
	if err != nil || math.Float64bits(got[0]) != 0x7ff8040000000000 {
		t.Fatalf("NaN payload: %x, %v", math.Float64bits(got[0]), err)
	}
	for _, v := range []Value{
		MakeTag(83, Bytes(make([]byte, 16))), // float128 doesn't fit
		MakeTag(81, Bytes([]byte{1, 2, 3})),  // length
		MakeTag(65, Bytes([]byte{0, 1})),     // integer array
		Uint(1),
	} {
		if _, err := AsFloat64Array(v); !errors.Is(err, ErrMalformedTag) {
			t.Errorf("AsFloat64Array(%v): %v, want ErrMalformedTag", v, err)
		}
	}
}

// 037 C18: float128 typed arrays decode exactly to big.Float.
func TestAsFloat128Array(t *testing.T) {
	// 1.0, -2.5, the smallest subnormal, +Inf.
	be := [][]byte{
		{0x3f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0xc0, 0x00, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		{0x7f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	var b, le []byte
	for _, e := range be {
		b = append(b, e...)
		r := slices.Clone(e)
		slices.Reverse(r)
		le = append(le, r...)
	}
	tiny := new(big.Float).SetMantExp(big.NewFloat(1), -16494)
	for _, v := range []Value{MakeTag(83, Bytes(b)), MakeTag(87, Bytes(le))} {
		got, err := AsFloat128Array(v)
		if err != nil || len(got) != 4 {
			t.Fatalf("%v: %v", got, err)
		}
		if got[0].Cmp(big.NewFloat(1)) != 0 || got[1].Cmp(big.NewFloat(-2.5)) != 0 || got[2].Cmp(tiny) != 0 || !got[3].IsInf() || got[3].Sign() < 0 {
			t.Fatalf("values %v", got)
		}
	}
	nan := make([]byte, 16)
	nan[0], nan[1], nan[2] = 0x7f, 0xff, 0x80
	if _, err := AsFloat128Array(MakeTag(83, Bytes(nan))); !errors.Is(err, ErrMalformedTag) {
		t.Fatalf("NaN: %v", err)
	}
}

// 037 C18: multi-dimensional arrays (tags 40 and 1040).
func TestMultiDimArray(t *testing.T) {
	m := MultiDimArray{Shape: []uint64{2, 3}, Data: TypedArrayTo([]uint16{1, 2, 3, 4, 5, 6})}
	v, err := MultiDimArrayTo(m)
	if err != nil || v.TagID() != 40 {
		t.Fatalf("MultiDimArrayTo: %v, %v", v, err)
	}
	back, err := AsMultiDimArray(v)
	if err != nil || !slices.Equal(back.Shape, m.Shape) || back.ColumnMajor || !back.Data.Equal(m.Data) {
		t.Fatalf("AsMultiDimArray: %+v, %v", back, err)
	}
	m.ColumnMajor = true
	m.Data = MakeArray(Uint(1), Uint(2), Uint(3), Uint(4), Uint(5), Uint(6))
	v, err = MultiDimArrayTo(m)
	if err != nil || v.TagID() != 1040 {
		t.Fatalf("column-major: %v, %v", v, err)
	}
	if back, err := AsMultiDimArray(v); err != nil || !back.ColumnMajor || len(back.Data.Items) != 6 {
		t.Fatalf("column-major back: %+v, %v", back, err)
	}
	for _, bad := range []MultiDimArray{
		{Shape: []uint64{2, 2}, Data: MakeArray(Uint(1))},         // too few
		{Shape: nil, Data: MakeArray()},                           // no dimensions
		{Shape: []uint64{1 << 40, 1 << 40}, Data: MakeArray()},    // product overflows
		{Shape: []uint64{2}, Data: Text("ab")},                    // not an array
		{Shape: []uint64{1}, Data: MakeTag(65, Bytes([]byte{0}))}, // bad typed array
	} {
		if _, err := MultiDimArrayTo(bad); !errors.Is(err, ErrMalformedTag) {
			t.Errorf("MultiDimArrayTo(%+v): %v", bad, err)
		}
	}
	for _, bad := range []Value{
		MakeTag(40, MakeArray(MakeArray(Uint(2)), MakeArray(Uint(1)))),
		MakeTag(40, MakeArray(MakeArray(Text("a")), MakeArray(Uint(1)))),
		MakeTag(40, MakeArray(MakeArray(Uint(1)))),
		MakeTag(41, MakeArray()),
	} {
		if _, err := AsMultiDimArray(bad); !errors.Is(err, ErrMalformedTag) {
			t.Errorf("AsMultiDimArray(%v): %v", bad, err)
		}
	}
}

// 037 C18: homogeneous arrays (tag 41).
func TestHomogeneousArray(t *testing.T) {
	for _, items := range [][]Value{
		{Uint(1), NegInt(0)},                          // integers
		{Float32(1), Float64(2)},                      // floats at any width
		{Text("a"), Text("b")},                        // text
		{MakeTag(1, Uint(1)), MakeTag(1, Float64(1))}, // same tag number
		{},
	} {
		v, err := HomogeneousArrayTo(items)
		if err != nil || v.TagID() != 41 {
			t.Fatalf("HomogeneousArrayTo(%v): %v", items, err)
		}
		back, err := AsHomogeneousArray(v)
		if err != nil || len(back) != len(items) {
			t.Fatalf("AsHomogeneousArray: %v, %v", back, err)
		}
	}
	for _, items := range [][]Value{
		{Uint(1), Text("a")},
		{Uint(1), Float64(1)},
		{MakeTag(1, Uint(1)), MakeTag(2, Bytes(nil))},
		{Bool(true), Null()},
	} {
		if _, err := HomogeneousArrayTo(items); !errors.Is(err, ErrMalformedTag) {
			t.Errorf("HomogeneousArrayTo(%v): %v", items, err)
		}
		if _, err := AsHomogeneousArray(MakeTag(41, MakeArrayFromSlice(items))); !errors.Is(err, ErrMalformedTag) {
			t.Errorf("AsHomogeneousArray(%v): %v", items, err)
		}
	}
}
