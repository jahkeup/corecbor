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
		val  cbor.Uint
		want string
	}{
		{0, "00"},
		{1, "01"},
		{10, "0a"},
		{23, "17"},
		{24, "1818"},
		{25, "1819"},
		{100, "1864"},
		{255, "18ff"},
		{256, "190100"},
		{1000, "1903e8"},
		{65535, "19ffff"},
		{65536, "1a00010000"},
		{1000000, "1a000f4240"},
		{0xffffffff, "1affffffff"},
		{0x100000000, "1b0000000100000000"},
		{math.MaxUint64, "1bffffffffffffffff"},
	}
	for _, tt := range tests {
		got, err := Encode(nil, tt.val, EncodeOpts{})
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
		val  cbor.NegInt
		want string
	}{
		{0, "20"},       // -1
		{9, "29"},       // -10
		{99, "3863"},    // -100
		{999, "3903e7"}, // -1000
	}
	for _, tt := range tests {
		got, err := Encode(nil, tt.val, EncodeOpts{})
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
		val  cbor.Bytes
		want string
	}{
		{cbor.Bytes{}, "40"},
		{cbor.Bytes{0x01, 0x02, 0x03, 0x04}, "4401020304"},
		{mustHex("0102030405060708090a0b0c0d0e0f101112131415161718"), "58180102030405060708090a0b0c0d0e0f101112131415161718"},
	}
	for _, tt := range tests {
		got, err := Encode(nil, tt.val, EncodeOpts{})
		if err != nil {
			t.Fatalf("Encode(Bytes): %v", err)
		}
		want := mustHex(tt.want)
		if !bytes.Equal(got, want) {
			t.Errorf("Encode(Bytes(%x)) = %x, want %s", []byte(tt.val), got, tt.want)
		}
	}
}

func TestEncodeText(t *testing.T) {
	tests := []struct {
		val  cbor.Text
		want string
	}{
		{"", "60"},
		{"a", "6161"},
		{"IETF", "6449455446"},
		{"\"\\", "62225c"},
		{"\u00fc", "62c3bc"},
		{"\u6c34", "63e6b0b4"},
	}
	for _, tt := range tests {
		got, err := Encode(nil, tt.val, EncodeOpts{})
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
		got, err := Encode(nil, cbor.Array{}, EncodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("80"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("[1,2,3]", func(t *testing.T) {
		got, err := Encode(nil, cbor.Array{cbor.Uint(1), cbor.Uint(2), cbor.Uint(3)}, EncodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("83010203"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("nested", func(t *testing.T) {
		// [1, [2, 3], [4, 5]]
		got, err := Encode(nil, cbor.Array{
			cbor.Uint(1),
			cbor.Array{cbor.Uint(2), cbor.Uint(3)},
			cbor.Array{cbor.Uint(4), cbor.Uint(5)},
		}, EncodeOpts{})
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
		got, err := Encode(nil, cbor.Map{}, EncodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("a0"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("{1:2, 3:4}", func(t *testing.T) {
		got, err := Encode(nil, cbor.Map{
			{Key: cbor.Uint(1), Value: cbor.Uint(2)},
			{Key: cbor.Uint(3), Value: cbor.Uint(4)},
		}, EncodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("a201020304"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})
}

func TestEncodeMapDeterministic(t *testing.T) {
	// Keys given out of order: 3, 1 → deterministic must produce 1, 3 order.
	m := cbor.Map{
		{Key: cbor.Uint(3), Value: cbor.Text("three")},
		{Key: cbor.Uint(1), Value: cbor.Text("one")},
	}
	got, err := EncodeDeterministic(nil, m, EncodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Sorted: key 0x01 before key 0x03.
	// a2 01 63"one" 03 65"three"
	want := mustHex("a2" + "01" + "636f6e65" + "03" + "657468726565")
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}

	// Verify input not mutated.
	if uint64(m[0].Key.(cbor.Uint)) != 3 {
		t.Error("input map was mutated")
	}
}

func TestEncodeTag(t *testing.T) {
	// Tag 1 with Uint(1363896240) — RFC 8949 example
	got, err := Encode(nil, cbor.Tag{ID: 1, Inner: cbor.Uint(1363896240)}, EncodeOpts{})
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
		{cbor.Null{}, "f6"},
		{cbor.Undefined{}, "f7"},
	}
	for _, tt := range tests {
		got, err := Encode(nil, tt.val, EncodeOpts{})
		if err != nil {
			t.Fatalf("Encode(%T): %v", tt.val, err)
		}
		want := mustHex(tt.want)
		if !bytes.Equal(got, want) {
			t.Errorf("Encode(%T) = %x, want %s", tt.val, got, tt.want)
		}
	}
}

func TestEncodeFloat(t *testing.T) {
	t.Run("permissive preserves width", func(t *testing.T) {
		// Float32(1.5) → float32 encoding
		got, err := Encode(nil, cbor.Float32(1.5), EncodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex("fa3fc00000"); !bytes.Equal(got, want) {
			t.Errorf("Float32(1.5) = %x, want %s", got, "fa3fc00000")
		}

		// Float64(1.5) → float64 encoding
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
		// -0.0 fits in float16: 0xf98000
		if want := mustHex("f98000"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want f98000", got)
		}
	})

	t.Run("inf allowed", func(t *testing.T) {
		got, err := EncodeDeterministic(nil, cbor.Float64(math.Inf(1)), EncodeOpts{AllowNonFiniteFloats: true})
		if err != nil {
			t.Fatal(err)
		}
		// +Inf fits in float16: 0xf97c00
		if want := mustHex("f97c00"); !bytes.Equal(got, want) {
			t.Errorf("got %x, want f97c00", got)
		}
	})

	t.Run("nan deterministic canonical", func(t *testing.T) {
		got, err := EncodeDeterministic(nil, cbor.Float64(math.NaN()), EncodeOpts{AllowNonFiniteFloats: true})
		if err != nil {
			t.Fatal(err)
		}
		// Canonical NaN: 0xf97e00
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

	// With AllowInvalidUTF8, it should succeed.
	_, err = Encode(nil, invalid, EncodeOpts{AllowInvalidUTF8: true})
	if err != nil {
		t.Fatalf("AllowInvalidUTF8 should permit invalid: %v", err)
	}
}

func TestEncodeNilValue(t *testing.T) {
	_, err := Encode(nil, nil, EncodeOpts{})
	if err == nil {
		t.Fatal("expected error for nil value")
	}
	if !errors.Is(err, cbor.ErrNilValue) {
		t.Errorf("got %v, want ErrNilValue", err)
	}
}

func TestEncodeTagNilInner(t *testing.T) {
	_, err := Encode(nil, cbor.Tag{ID: 1, Inner: nil}, EncodeOpts{})
	if err == nil {
		t.Fatal("expected error for nil Tag.Inner")
	}
	if !errors.Is(err, cbor.ErrNilValue) {
		t.Errorf("got %v, want ErrNilValue", err)
	}
}

func TestEncodeSimple(t *testing.T) {
	tests := []struct {
		val  cbor.Simple
		want string
	}{
		{16, "f0"},   // simple(16) — inline
		{32, "f820"}, // simple(32) — one-byte follow
		{255, "f8ff"},
	}
	for _, tt := range tests {
		got, err := Encode(nil, tt.val, EncodeOpts{})
		if err != nil {
			t.Fatalf("Encode(Simple(%d)): %v", tt.val, err)
		}
		want := mustHex(tt.want)
		if !bytes.Equal(got, want) {
			t.Errorf("Encode(Simple(%d)) = %x, want %s", tt.val, got, tt.want)
		}
	}
}
