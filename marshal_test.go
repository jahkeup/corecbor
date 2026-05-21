// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cbor"
)

func TestMarshal_Bool(t *testing.T) {
	data, err := Marshal(true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte{0xf5}) {
		t.Fatalf("got %x, want f5", data)
	}

	data, err = Marshal(false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte{0xf4}) {
		t.Fatalf("got %x, want f4", data)
	}
}

func TestMarshal_Integers(t *testing.T) {
	tests := []struct {
		name string
		val  any
		want []byte
	}{
		{"zero", int(0), []byte{0x00}},
		{"one", int(1), []byte{0x01}},
		{"23", int(23), []byte{0x17}},
		{"24", int(24), []byte{0x18, 0x18}},
		{"255", uint8(255), []byte{0x18, 0xff}},
		{"256", uint16(256), []byte{0x19, 0x01, 0x00}},
		{"65535", uint16(65535), []byte{0x19, 0xff, 0xff}},
		{"neg1", int(-1), []byte{0x20}},
		{"neg10", int(-10), []byte{0x29}},
		{"neg100", int(-100), []byte{0x38, 0x63}},
		{"uint64max", uint64(math.MaxUint64), []byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := Marshal(tt.val)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, tt.want) {
				t.Fatalf("got %x, want %x", data, tt.want)
			}
		})
	}
}

func TestMarshal_Float(t *testing.T) {
	data, err := Marshal(float32(0.0))
	if err != nil {
		t.Fatal(err)
	}
	// CoreDeterministic shortest form: 0.0 → f16 0xf90000
	if !bytes.Equal(data, []byte{0xf9, 0x00, 0x00}) {
		t.Fatalf("got %x, want f90000", data)
	}

	data, err = Marshal(float64(1.1))
	if err != nil {
		t.Fatal(err)
	}
	// 1.1 cannot be f16 or f32 losslessly, stays f64
	if len(data) != 9 || data[0] != 0xfb {
		t.Fatalf("got %x, want 9-byte float64", data)
	}
}

func TestMarshal_String(t *testing.T) {
	data, err := Marshal("hello")
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0x65}, []byte("hello")...)
	if !bytes.Equal(data, want) {
		t.Fatalf("got %x, want %x", data, want)
	}
}

func TestMarshal_Bytes(t *testing.T) {
	data, err := Marshal([]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x43, 1, 2, 3}
	if !bytes.Equal(data, want) {
		t.Fatalf("got %x, want %x", data, want)
	}
}

func TestMarshal_Slice(t *testing.T) {
	data, err := Marshal([]int{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x83, 0x01, 0x02, 0x03}
	if !bytes.Equal(data, want) {
		t.Fatalf("got %x, want %x", data, want)
	}
}

func TestMarshal_NilSlice(t *testing.T) {
	var s []int
	data, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x80}
	if !bytes.Equal(data, want) {
		t.Fatalf("got %x, want %x (empty array)", data, want)
	}
}

func TestMarshal_Map(t *testing.T) {
	data, err := Marshal(map[string]int{"a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	// CoreDeterministic sorts keys by bytewise-lex of encoded form
	// "a" encodes to 6161, "b" encodes to 6162 → a < b
	want := []byte{0xa2, 0x61, 'a', 0x01, 0x61, 'b', 0x02}
	if !bytes.Equal(data, want) {
		t.Fatalf("got %x, want %x", data, want)
	}
}

func TestMarshal_Struct(t *testing.T) {
	type S struct {
		Name string `cbor:"name"`
		Age  int    `cbor:"age"`
	}
	data, err := Marshal(S{Name: "Alice", Age: 30})
	if err != nil {
		t.Fatal(err)
	}
	// Verify round-trip
	var out S
	if err := Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Name != "Alice" || out.Age != 30 {
		t.Fatalf("got %+v", out)
	}
}

func TestMarshal_NestedStruct(t *testing.T) {
	type Inner struct {
		X int `cbor:"x"`
	}
	type Outer struct {
		I Inner `cbor:"i"`
		Y int   `cbor:"y"`
	}
	orig := Outer{I: Inner{X: 42}, Y: 7}
	data, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var out Outer
	if err := Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out != orig {
		t.Fatalf("got %+v, want %+v", out, orig)
	}
}

func TestMarshal_Pointer(t *testing.T) {
	n := 42
	data, err := Marshal(&n)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x18, 42}
	if !bytes.Equal(data, want) {
		t.Fatalf("got %x, want %x", data, want)
	}

	var nilPtr *int
	data, err = Marshal(nilPtr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte{0xf6}) {
		t.Fatalf("got %x, want f6 (null)", data)
	}
}

func TestMarshal_Time(t *testing.T) {
	ts := time.Unix(1000, 0).UTC()
	data, err := Marshal(ts)
	if err != nil {
		t.Fatal(err)
	}
	// Tag 1, Uint 1000 → c1 1903e8
	want := []byte{0xc1, 0x19, 0x03, 0xe8}
	if !bytes.Equal(data, want) {
		t.Fatalf("got %x, want %x", data, want)
	}

	// Sub-second time uses float
	ts2 := time.Unix(1000, 500000000).UTC()
	data2, err := Marshal(ts2)
	if err != nil {
		t.Fatal(err)
	}
	if data2[0] != 0xc1 {
		t.Fatal("expected tag 1")
	}
}

func TestMarshal_BigInt(t *testing.T) {
	n := big.NewInt(0)
	n.SetString("18446744073709551616", 10) // 2^64
	data, err := Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	if data[0] != 0xc2 {
		t.Fatalf("expected tag 2, got %x", data[0])
	}

	neg := big.NewInt(-1)
	neg.Sub(neg, n) // -(2^64 + 1)
	data, err = Marshal(neg)
	if err != nil {
		t.Fatal(err)
	}
	if data[0] != 0xc3 {
		t.Fatalf("expected tag 3, got %x", data[0])
	}
}

func TestMarshal_Omitempty(t *testing.T) {
	type S struct {
		A string `cbor:"a,omitempty"`
		B int    `cbor:"b,omitempty"`
		C bool   `cbor:"c"`
	}
	data, err := Marshal(S{C: false})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["a"]; ok {
		t.Fatal("empty string 'a' should be omitted")
	}
	if _, ok := m["b"]; ok {
		t.Fatal("zero int 'b' should be omitted")
	}
	if _, ok := m["c"]; !ok {
		t.Fatal("'c' should be present even when false")
	}
}

func TestMarshal_IntegerKey(t *testing.T) {
	type S struct {
		Alg int `cbor:"1"`
	}
	data, err := Marshal(S{Alg: 7})
	if err != nil {
		t.Fatal(err)
	}
	// key should be Uint(1), not Text("1")
	// a1 01 07
	want := []byte{0xa1, 0x01, 0x07}
	if !bytes.Equal(data, want) {
		t.Fatalf("got %x, want %x", data, want)
	}
}

func TestMarshal_SkipField(t *testing.T) {
	type S struct {
		A int `cbor:"a"`
		B int `cbor:"-"`
	}
	data, err := Marshal(S{A: 1, B: 2})
	if err != nil {
		t.Fatal(err)
	}
	// only "a" should be present
	want := []byte{0xa1, 0x61, 'a', 0x01}
	if !bytes.Equal(data, want) {
		t.Fatalf("got %x, want %x", data, want)
	}
}

type customMarshaler struct {
	val int
}

func (c customMarshaler) MarshalCBOR() ([]byte, error) {
	return Marshal(c.val * 2)
}

func (c *customMarshaler) UnmarshalCBOR(data []byte) error {
	var n int
	if err := Unmarshal(data, &n); err != nil {
		return err
	}
	c.val = n / 2
	return nil
}

func TestMarshal_MarshalerInterface(t *testing.T) {
	v := customMarshaler{val: 21}
	data, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	// 21*2 = 42
	want := []byte{0x18, 42}
	if !bytes.Equal(data, want) {
		t.Fatalf("got %x, want %x", data, want)
	}
}

func TestMarshal_ValuePassthrough(t *testing.T) {
	v := cbor.Text("direct")
	data, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0x66}, []byte("direct")...)
	if !bytes.Equal(data, want) {
		t.Fatalf("got %x, want %x", data, want)
	}
}

func TestUnmarshal_Scalars(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want any
		into any
	}{
		{"uint", []byte{0x18, 0x64}, uint64(100), new(uint64)},
		{"negint", []byte{0x38, 0x63}, int64(-100), new(int64)},
		{"bool_true", []byte{0xf5}, true, new(bool)},
		{"bool_false", []byte{0xf4}, false, new(bool)},
		{"text", append([]byte{0x63}, []byte("foo")...), "foo", new(string)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Unmarshal(tt.data, tt.into); err != nil {
				t.Fatal(err)
			}
			got := deref(tt.into)
			if got != tt.want {
				t.Fatalf("got %v (%T), want %v (%T)", got, got, tt.want, tt.want)
			}
		})
	}
}

func TestUnmarshal_Struct(t *testing.T) {
	type S struct {
		Name string `cbor:"name"`
		Age  int    `cbor:"age"`
	}
	data, _ := Marshal(S{Name: "Bob", Age: 25})
	var out S
	if err := Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Name != "Bob" || out.Age != 25 {
		t.Fatalf("got %+v", out)
	}
}

func TestUnmarshal_Map(t *testing.T) {
	orig := map[string]int{"x": 1, "y": 2}
	data, _ := Marshal(orig)
	var out map[string]int
	if err := Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out["x"] != 1 || out["y"] != 2 {
		t.Fatalf("got %v", out)
	}
}

func TestUnmarshal_Slice(t *testing.T) {
	data, _ := Marshal([]int{10, 20, 30})
	var out []int
	if err := Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out[0] != 10 || out[1] != 20 || out[2] != 30 {
		t.Fatalf("got %v", out)
	}
}

func TestUnmarshal_Time(t *testing.T) {
	ts := time.Unix(1000, 0).UTC()
	data, _ := Marshal(ts)
	var out time.Time
	if err := Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Equal(ts) {
		t.Fatalf("got %v, want %v", out, ts)
	}
}

func TestUnmarshal_IntoAny(t *testing.T) {
	data, _ := Marshal(map[string]int{"a": 1})
	var out any
	if err := Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", out)
	}
	if m["a"] != uint64(1) {
		t.Fatalf("got %v (%T)", m["a"], m["a"])
	}
}

func TestUnmarshal_UnmarshalerInterface(t *testing.T) {
	data, _ := Marshal(42)
	var v customMarshaler
	if err := Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if v.val != 21 {
		t.Fatalf("got %d, want 21", v.val)
	}
}

func TestUnmarshal_Overflow(t *testing.T) {
	data, _ := Marshal(uint64(math.MaxUint64))
	var n int64
	err := Unmarshal(data, &n)
	if !errors.Is(err, ErrOverflow) {
		t.Fatalf("expected ErrOverflow, got %v", err)
	}

	data, _ = Marshal(int(-1))
	var u uint64
	err = Unmarshal(data, &u)
	if !errors.Is(err, ErrOverflow) {
		t.Fatalf("expected ErrOverflow, got %v", err)
	}
}

func TestUnmarshal_NotPointer(t *testing.T) {
	data, _ := Marshal(1)
	var n int
	err := Unmarshal(data, n)
	if !errors.Is(err, ErrNotPointer) {
		t.Fatalf("expected ErrNotPointer, got %v", err)
	}
}

func TestMarshalUnmarshal_RoundTrip(t *testing.T) {
	type Inner struct {
		Tags []string `cbor:"tags"`
	}
	type Msg struct {
		ID    uint64  `cbor:"id"`
		Name  string  `cbor:"name"`
		Score float64 `cbor:"score"`
		Inner Inner   `cbor:"inner"`
	}
	orig := Msg{
		ID:    999,
		Name:  "test",
		Score: 3.14,
		Inner: Inner{Tags: []string{"a", "b"}},
	}
	data, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var out Msg
	if err := Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.ID != orig.ID || out.Name != orig.Name || out.Inner.Tags[0] != "a" || out.Inner.Tags[1] != "b" {
		t.Fatalf("round-trip mismatch: got %+v", out)
	}
	if math.Abs(out.Score-orig.Score) > 1e-10 {
		t.Fatalf("score mismatch: got %f, want %f", out.Score, orig.Score)
	}
}

func TestEncoder_Marshal(t *testing.T) {
	permissive := New(ModePermissive)
	deterministic := New(ModeCoreDeterministic)

	m := map[string]int{"b": 2, "a": 1}

	pd, err := permissive.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	dd, err := deterministic.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	// Deterministic output always has "a" before "b"
	wantDet := []byte{0xa2, 0x61, 'a', 0x01, 0x61, 'b', 0x02}
	if !bytes.Equal(dd, wantDet) {
		t.Fatalf("deterministic: got %x, want %x", dd, wantDet)
	}

	// Permissive output is valid CBOR (just maybe different order)
	var out map[string]int
	if err := Unmarshal(pd, &out); err != nil {
		t.Fatal(err)
	}
	if out["a"] != 1 || out["b"] != 2 {
		t.Fatalf("got %v", out)
	}
}

func TestDecoder_Unmarshal_Strict(t *testing.T) {
	dec := StrictDecoder()
	// Non-shortest encoding of integer 0: 0x1800 instead of 0x00
	data := []byte{0x18, 0x00}
	var n int
	err := dec.Unmarshal(data, &n)
	if err == nil {
		t.Fatal("expected error for non-shortest encoding in strict mode")
	}
}

func deref(v any) any {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		return rv.Elem().Interface()
	}
	return v
}
