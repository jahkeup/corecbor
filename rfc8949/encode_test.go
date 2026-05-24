// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestEncodeUint(t *testing.T) {
	tests := []struct {
		val  uint64
		want string
	}{
		{0, "00"}, {1, "01"}, {10, "0a"}, {23, "17"},
		{24, "1818"}, {25, "1819"}, {100, "1864"}, {255, "18ff"},
		{256, "190100"}, {1000, "1903e8"}, {65535, "19ffff"},
		{65536, "1a00010000"}, {1000000, "1a000f4240"},
		{0xffffffff, "1affffffff"}, {0x100000000, "1b0000000100000000"},
		{math.MaxUint64, "1bffffffffffffffff"},
	}
	for _, tt := range tests {
		got, err := Encode(nil, cbor.Uint(tt.val), EncodeOpts{})
		if err != nil {
			t.Fatalf("Encode(%d): %v", tt.val, err)
		}
		want := mustHex(tt.want)
		if !bytes.Equal(got, want) {
			t.Errorf("Encode(%d) = %x, want %s", tt.val, got, tt.want)
		}
	}
}

func TestEncodeNegInt(t *testing.T) {
	tests := []struct {
		val  uint64
		want string
	}{
		{0, "20"}, {9, "29"}, {99, "3863"}, {999, "3903e7"},
	}
	for _, tt := range tests {
		got, err := Encode(nil, cbor.NegInt(tt.val), EncodeOpts{})
		if err != nil {
			t.Fatalf("Encode(NegInt(%d)): %v", tt.val, err)
		}
		want := mustHex(tt.want)
		if !bytes.Equal(got, want) {
			t.Errorf("Encode(NegInt(%d)) = %x, want %s", tt.val, got, tt.want)
		}
	}
}

func TestEncodeBytes(t *testing.T) {
	tests := []struct {
		val  []byte
		want string
	}{
		{[]byte{}, "40"},
		{[]byte{0x01, 0x02, 0x03, 0x04}, "4401020304"},
		{mustHex("0102030405060708090a0b0c0d0e0f101112131415161718"), "58180102030405060708090a0b0c0d0e0f101112131415161718"},
	}
	for _, tt := range tests {
		got, err := Encode(nil, cbor.Bytes(tt.val), EncodeOpts{})
		if err != nil {
			t.Fatalf("Encode(Bytes): %v", err)
		}
		want := mustHex(tt.want)
		if !bytes.Equal(got, want) {
			t.Errorf("Encode(Bytes(%x)) = %x, want %s", tt.val, got, tt.want)
		}
	}
}

func TestEncodeText(t *testing.T) {
	tests := []struct {
		val  string
		want string
	}{
		{"", "60"}, {"a", "6161"}, {"IETF", "6449455446"},
		{"\"\\", "62225c"}, {"\u00fc", "62c3bc"}, {"\u6c34", "63e6b0b4"},
	}
	for _, tt := range tests {
		got, err := Encode(nil, cbor.Text(tt.val), EncodeOpts{})
		if err != nil {
			t.Fatalf("Encode(Text(%q)): %v", tt.val, err)
		}
		want := mustHex(tt.want)
		if !bytes.Equal(got, want) {
			t.Errorf("Encode(Text(%q)) = %x, want %s", tt.val, got, tt.want)
		}
	}
}

func TestEncodeArray(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		got, err := Encode(nil, cbor.MakeArray(), EncodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("80"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("[1,2,3]", func(t *testing.T) {
		got, err := Encode(nil, cbor.MakeArray(cbor.Uint(1), cbor.Uint(2), cbor.Uint(3)), EncodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("83010203"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("nested", func(t *testing.T) {
		got, err := Encode(nil, cbor.MakeArray(
			cbor.Uint(1),
			cbor.MakeArray(cbor.Uint(2), cbor.Uint(3)),
			cbor.MakeArray(cbor.Uint(4), cbor.Uint(5)),
		), EncodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("8301820203820405"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})
}

func TestEncodeMap(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		got, err := Encode(nil, cbor.MakeMap(), EncodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("a0"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("{1:2, 3:4}", func(t *testing.T) {
		got, err := Encode(nil, cbor.MakeMap(
			cbor.MapEntry{Key: cbor.Uint(1), Value: cbor.Uint(2)},
			cbor.MapEntry{Key: cbor.Uint(3), Value: cbor.Uint(4)},
		), EncodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("a201020304"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})
}

func TestEncodeMapDeterministic(t *testing.T) {
	m := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Uint(3), Value: cbor.Text("three")},
		cbor.MapEntry{Key: cbor.Uint(1), Value: cbor.Text("one")},
	)
	got, err := EncodeDeterministic(nil, m, EncodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex("a2" + "01" + "636f6e65" + "03" + "657468726565")
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}

	pairs := m.Map()
	if pairs[0].Key.UintVal() != 3 {
		t.Error("input map was mutated")
	}
}

func TestEncodeTag(t *testing.T) {
	got, err := Encode(nil, cbor.MakeTag(1, cbor.Uint(1363896240)), EncodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex("c11a514b67b0"); !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}

func TestEncodeBoolNullUndefined(t *testing.T) {
	tests := []struct {
		val  cbor.Value
		want string
	}{
		{cbor.Bool(false), "f4"},
		{cbor.Bool(true), "f5"},
		{cbor.Null(), "f6"},
		{cbor.Undefined(), "f7"},
	}
	for _, tt := range tests {
		got, err := Encode(nil, tt.val, EncodeOpts{})
		if err != nil {
			t.Fatalf("Encode(kind %d): %v", tt.val.Kind(), err)
		}
		want := mustHex(tt.want)
		if !bytes.Equal(got, want) {
			t.Errorf("Encode(kind %d) = %x, want %s", tt.val.Kind(), got, tt.want)
		}
	}
}

func TestEncodeFloat(t *testing.T) {
	t.Run("permissive preserves width", func(t *testing.T) {
		got, err := Encode(nil, cbor.Float32(1.5), EncodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("fa3fc00000"); !bytes.Equal(got, want) {
			t.Errorf("Float32(1.5) = %x, want %s", got, "fa3fc00000")
		}
		got, err = Encode(nil, cbor.Float64(1.5), EncodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("fb3ff8000000000000"); !bytes.Equal(got, want) {
			t.Errorf("Float64(1.5) = %x, want %s", got, "fb3ff8000000000000")
		}
	})

	t.Run("deterministic shortest", func(t *testing.T) {
		tests := []struct {
			val  cbor.Value
			want string
		}{
			{cbor.Float64(0.0), "f90000"},
			{cbor.Float64(1.0), "f93c00"},
			{cbor.Float64(1.5), "f93e00"},
			{cbor.Float64(65504.0), "f97bff"},
			{cbor.Float64(-4.0), "f9c400"},
			{cbor.Float32(0.0), "f90000"},
			{cbor.Float32(1.5), "f93e00"},
		}
		for _, tt := range tests {
			got, err := EncodeDeterministic(nil, tt.val, EncodeOpts{})
			if err != nil {
				t.Fatalf("EncodeDeterministic(%v): %v", tt.val, err)
			}
			want := mustHex(tt.want)
			if !bytes.Equal(got, want) {
				t.Errorf("EncodeDeterministic(%v) = %x, want %s", tt.val, got, tt.want)
			}
		}
	})

	t.Run("negative zero deterministic", func(t *testing.T) {
		negZero := math.Copysign(0, -1)
		got, err := EncodeDeterministic(nil, cbor.Float64(negZero), EncodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("f98000"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want f98000", got)
		}
	})

	t.Run("inf allowed", func(t *testing.T) {
		got, err := EncodeDeterministic(nil, cbor.Float64(math.Inf(1)), EncodeOpts{AllowNonFiniteFloats: true})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("f97c00"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want f97c00", got)
		}
	})

	t.Run("nan deterministic canonical", func(t *testing.T) {
		got, err := EncodeDeterministic(nil, cbor.Float64(math.NaN()), EncodeOpts{AllowNonFiniteFloats: true})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("f97e00"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want f97e00", got)
		}
	})
}

func TestEncodeRejectsNaN(t *testing.T) {
	_, err := Encode(nil, cbor.Float64(math.NaN()), EncodeOpts{})
	if err == nil {
		t.Fatal("expected error for NaN")
	}
	if !errors.Is(err, cbor.ErrNonFiniteFloat) {
		t.Errorf("got %v, want ErrNonFiniteFloat", err)
	}
	_, err = Encode(nil, cbor.Float32(float32(math.NaN())), EncodeOpts{})
	if err == nil {
		t.Fatal("expected error for NaN float32")
	}
	if !errors.Is(err, cbor.ErrNonFiniteFloat) {
		t.Errorf("got %v, want ErrNonFiniteFloat", err)
	}
	_, err = Encode(nil, cbor.Float64(math.Inf(1)), EncodeOpts{})
	if err == nil {
		t.Fatal("expected error for Inf")
	}
	if !errors.Is(err, cbor.ErrNonFiniteFloat) {
		t.Errorf("got %v, want ErrNonFiniteFloat", err)
	}
}

func TestEncodeRejectsInvalidUTF8(t *testing.T) {
	invalid := cbor.Text(string([]byte{0xff, 0xfe}))
	_, err := Encode(nil, invalid, EncodeOpts{})
	if err == nil {
		t.Fatal("expected error for invalid UTF-8")
	}
	if !errors.Is(err, cbor.ErrInvalidUTF8) {
		t.Errorf("got %v, want ErrInvalidUTF8", err)
	}
	_, err = Encode(nil, invalid, EncodeOpts{AllowInvalidUTF8: true})
	if err != nil {
		t.Fatalf("AllowInvalidUTF8 should permit invalid: %v", err)
	}
}

func TestEncodeNilValue(t *testing.T) {
	_, err := Encode(nil, cbor.Value{}, EncodeOpts{})
	if err == nil {
		t.Fatal("expected error for zero value")
	}
	if !errors.Is(err, cbor.ErrNilValue) {
		t.Errorf("got %v, want ErrNilValue", err)
	}
}

func TestEncodeTagNilInner(t *testing.T) {
	_, err := Encode(nil, cbor.MakeTag(1, cbor.Value{}), EncodeOpts{})
	if err == nil {
		t.Fatal("expected error for nil Tag inner")
	}
	if !errors.Is(err, cbor.ErrNilValue) {
		t.Errorf("got %v, want ErrNilValue", err)
	}
}

func TestEncodeSimple(t *testing.T) {
	tests := []struct {
		val  uint8
		want string
	}{
		{16, "f0"}, {32, "f820"}, {255, "f8ff"},
	}
	for _, tt := range tests {
		got, err := Encode(nil, cbor.Simple(tt.val), EncodeOpts{})
		if err != nil {
			t.Fatalf("Encode(Simple(%d)): %v", tt.val, err)
		}
		want := mustHex(tt.want)
		if !bytes.Equal(got, want) {
			t.Errorf("Encode(Simple(%d)) = %x, want %s", tt.val, got, tt.want)
		}
	}
}
