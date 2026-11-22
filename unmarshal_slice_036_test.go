// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"errors"
	"math"
	"math/rand/v2"
	"reflect"
	"testing"
)

// Named element types never take the scalar fast paths (they could have
// methods), so they decode through the generic per-element path.
type (
	genU64  uint64
	genI64  int64
	genU8   uint8
	genF64  float64
	genF32  float32
	genStr  string
	genBool bool
)

// sliceErrClass reduces an error to what callers can match on.
func sliceErrClass(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrOverflow):
		return "overflow"
	case errors.Is(err, ErrTypeMismatch):
		return "mismatch"
	default:
		return "other:" + err.Error()
	}
}

// sameAsGeneric decodes data into a fast-path slice and into the
// equivalent named-element slice and requires identical outcomes:
// error class, and element values on success.
func sameAsGeneric[F any, G any](t *testing.T, data []byte) {
	t.Helper()
	var fast []F
	var gen []G
	ef := Unmarshal(data, &fast)
	eg := Unmarshal(data, &gen)
	if sliceErrClass(ef) != sliceErrClass(eg) {
		t.Fatalf("%T: fast %v, generic %v", fast, ef, eg)
	}
	if ef != nil {
		return
	}
	if len(fast) != len(gen) {
		t.Fatalf("%T: len %d vs %d", fast, len(fast), len(gen))
	}
	for i := range fast {
		fv := reflect.ValueOf(fast[i])
		gv := reflect.ValueOf(gen[i]).Convert(fv.Type())
		if !reflect.DeepEqual(fv.Interface(), gv.Interface()) {
			// NaN never DeepEquals; compare bits for floats.
			if fv.CanFloat() && math.Float64bits(fv.Float()) == math.Float64bits(gv.Float()) {
				continue
			}
			t.Fatalf("%T[%d]: fast %v, generic %v", fast, i, fv, gv)
		}
	}
}

func TestUnmarshalScalarSliceMatchesGeneric(t *testing.T) {
	kinds := []Value{
		Uint(0), Uint(7), Uint(255), Uint(256), Uint(math.MaxInt64), Uint(math.MaxUint64),
		NegInt(0), NegInt(127), NegInt(128), NegInt(math.MaxInt64), NegInt(math.MaxUint64),
		Float64(1.5), Float64(-2), Float64(math.Inf(1)), Float64(math.NaN()), Float32(3),
		Bool(true), Bool(false), Text("x"), Text(""), Bytes([]byte{1}), Null(), Undefined(),
		MakeTag(1, Uint(5)), MakeArray(Uint(1)),
	}
	enc := New(ModePermissive, AllowNonFiniteFloats())
	r := rand.New(rand.NewPCG(3, 6))
	check := func(items []Value) {
		data, err := enc.Encode(nil, MakeArrayFromSlice(items))
		if err != nil {
			t.Fatal(err)
		}
		sameAsGeneric[uint64, genU64](t, data)
		sameAsGeneric[int64, genI64](t, data)
		sameAsGeneric[uint8, genU8](t, data)
		sameAsGeneric[float64, genF64](t, data)
		sameAsGeneric[float32, genF32](t, data)
		sameAsGeneric[string, genStr](t, data)
		sameAsGeneric[bool, genBool](t, data)
	}
	// Homogeneous arrays (the typed fast paths) and single-kind runs.
	for _, k := range kinds {
		check([]Value{k, k, k})
	}
	// Mixed arrays, including a mismatch after a run that the typed path
	// accepts (exercises its fall-back to the generic loop).
	for range 2000 {
		n := r.IntN(6)
		items := make([]Value, n)
		for i := range items {
			items[i] = kinds[r.IntN(len(kinds))]
		}
		check(items)
	}
}

// Go arrays and a reused, larger slice behave as before.
func TestUnmarshalScalarArrayAndReuse(t *testing.T) {
	data, _ := Marshal([]uint64{1, 2, 3})
	var a [2]uint64
	if err := Unmarshal(data, &a); err != nil || a != [2]uint64{1, 2} {
		t.Fatalf("array: %v %v", a, err)
	}
	s := make([]uint64, 5, 8)
	if err := Unmarshal(data, &s); err != nil || !reflect.DeepEqual(s, []uint64{1, 2, 3}) {
		t.Fatalf("reuse: %v %v", s, err)
	}
	// A slice field inside a struct (addressable via the struct).
	var st struct {
		V []string `cbor:"v"`
	}
	data, _ = Marshal(map[string]any{"v": []string{"a", "b"}})
	if err := Unmarshal(data, &st); err != nil || !reflect.DeepEqual(st.V, []string{"a", "b"}) {
		t.Fatalf("struct field: %v %v", st.V, err)
	}
}
