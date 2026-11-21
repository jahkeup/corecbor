// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"errors"
	"math"
	"os/exec"
	"strings"
	"testing"
)

func TestValueGet(t *testing.T) {
	m := MakeMap(
		MapEntry{Key: Uint(1), Value: Text("one")},
		MapEntry{Key: NegInt(0), Value: Text("minus one")},
		MapEntry{Key: Text("1"), Value: Text("text one")},
		MapEntry{Key: Float64(2.0), Value: Text("two")},
		MapEntry{Key: Uint(1), Value: Text("dup")},
	)
	for _, tc := range []struct {
		name string
		get  func() (Value, bool)
		want string
		ok   bool
	}{
		{"GetInt(1)", func() (Value, bool) { return m.GetInt(1) }, "one", true},
		{"GetInt(-1)", func() (Value, bool) { return m.GetInt(-1) }, "minus one", true},
		{"GetInt(2) not float key", func() (Value, bool) { return m.GetInt(2) }, "", false},
		{"GetText(1)", func() (Value, bool) { return m.GetText("1") }, "text one", true},
		{"GetText(x)", func() (Value, bool) { return m.GetText("x") }, "", false},
		{"Get(float32 2.0)", func() (Value, bool) { return m.Get(Float32(2.0)) }, "two", true},
		{"Get(Uint 1) first wins", func() (Value, bool) { return m.Get(Uint(1)) }, "one", true},
		{"not a map", func() (Value, bool) { return Text("x").GetInt(1) }, "", false},
	} {
		v, ok := tc.get()
		if ok != tc.ok || (ok && v.Str != tc.want) {
			t.Errorf("%s = %v, %v; want %q, %v", tc.name, v, ok, tc.want, tc.ok)
		}
	}
}

func TestValueInt64(t *testing.T) {
	for _, tc := range []struct {
		v    Value
		want int64
		err  error
	}{
		{Uint(0), 0, nil},
		{Uint(math.MaxInt64), math.MaxInt64, nil},
		{Uint(1 << 63), 0, ErrOverflow},
		{NegInt(0), -1, nil},
		{NegInt(math.MaxInt64), math.MinInt64, nil},
		{NegInt(1 << 63), 0, ErrOverflow},
		{Text("1"), 0, ErrTypeMismatch},
		{Float64(1), 0, ErrTypeMismatch},
	} {
		got, err := tc.v.Int64()
		if !errors.Is(err, tc.err) || (tc.err == nil && (err != nil || got != tc.want)) {
			t.Errorf("%v.Int64() = %d, %v; want %d, %v", tc.v, got, err, tc.want, tc.err)
		}
	}
	if n, err := Uint(math.MaxUint64).Uint64(); err != nil || n != math.MaxUint64 {
		t.Errorf("Uint64 = %d, %v", n, err)
	}
	if _, err := NegInt(0).Uint64(); !errors.Is(err, ErrTypeMismatch) {
		t.Errorf("NegInt.Uint64 err = %v, want ErrTypeMismatch", err)
	}
}

func TestValueEqual(t *testing.T) {
	nan := func(bits uint64) Value { return Value{Kind: KindFloat64, Num: bits} }
	for _, tc := range []struct {
		a, b Value
		want bool
	}{
		{Uint(1), Uint(1), true},
		{Uint(1), NegInt(1), false},
		{Uint(1), Float64(1), false}, // integer 1 and float 1.0 differ (§5.6.1)
		{Float32(1), Float64(1), true},
		{Float64(0), Float64(math.Copysign(0, -1)), true},
		{nan(0x7ff8000000000000), Float32(float32(math.NaN())), true},
		{nan(0x7ff8000000000000), nan(0xfff8000000000000), false}, // erratum 8589: sign bit
		{nan(0x7ff8000000000001), nan(0x7ff8000000000000), false},
		{Text("a"), Bytes([]byte("a")), false},
		{MakeArray(Uint(1), Text("x")), MakeArray(Uint(1), Text("x")), true},
		{MakeArray(Uint(1)), MakeArray(Uint(1), Uint(2)), false},
		{
			MakeMap(MapEntry{Key: Uint(1), Value: Uint(2)}, MapEntry{Key: Uint(3), Value: Uint(4)}),
			MakeMap(MapEntry{Key: Uint(3), Value: Uint(4)}, MapEntry{Key: Uint(1), Value: Uint(2)}),
			true, // maps are unordered in the data model
		},
		{MakeTag(1, Uint(2)), MakeTag(1, Uint(2)), true},
		{MakeTag(1, Uint(2)), MakeTag(2, Uint(2)), false},
		{Null(), Null(), true},
		{Null(), Undefined(), false},
	} {
		if got := tc.a.Equal(tc.b); got != tc.want {
			t.Errorf("%v.Equal(%v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
		if got := tc.b.Equal(tc.a); got != tc.want {
			t.Errorf("%v.Equal(%v) (swapped) = %v, want %v", tc.b, tc.a, got, tc.want)
		}
	}
}

func TestKindString(t *testing.T) {
	if got := KindMap.String(); got != "map" {
		t.Errorf("KindMap = %q", got)
	}
	if got := Kind(200).String(); got != "Kind(200)" {
		t.Errorf("Kind(200) = %q", got)
	}
	for k := KindInvalid; k <= KindSimple; k++ {
		if strings.HasPrefix(k.String(), "Kind(") {
			t.Errorf("kind %d has no name", k)
		}
	}
}

func TestValueStringCompact(t *testing.T) {
	v := MakeMap(MapEntry{Key: Text("a"), Value: MakeArray(Uint(1), NegInt(1), Bytes([]byte{0xff}), Float64(1.5))})
	if got, want := v.String(), `{"a":[1,-2,h'ff',1.5]}`; got != want {
		t.Errorf("String = %s, want %s", got, want)
	}
}

// Package cbor must not depend on rfc8949 (which imports cbor).
func TestNoRFC8949Dependency(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	if strings.Contains(string(out), "github.com/jahkeup/corecbor/rfc8949") {
		t.Fatal("package cbor depends on rfc8949")
	}
}
