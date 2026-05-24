// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type vectorCase struct {
	name       string
	value      Value
	hexEncoded string
	decodeOnly bool // true if encoder is not expected to produce this encoding
}

var rfc8949Vectors = []vectorCase{
	// Unsigned integers
	{"Uint(0)", Uint(0), "00", false},
	{"Uint(1)", Uint(1), "01", false},
	{"Uint(10)", Uint(10), "0a", false},
	{"Uint(23)", Uint(23), "17", false},
	{"Uint(24)", Uint(24), "1818", false},
	{"Uint(25)", Uint(25), "1819", false},
	{"Uint(100)", Uint(100), "1864", false},
	{"Uint(1000)", Uint(1000), "1903e8", false},
	{"Uint(1000000)", Uint(1000000), "1a000f4240", false},
	{"Uint(1000000000000)", Uint(1000000000000), "1b000000e8d4a51000", false},
	{"Uint(MaxUint64)", Uint(18446744073709551615), "1bffffffffffffffff", false},

	// Negative integers
	{"NegInt(0)=-1", NegInt(0), "20", false},
	{"NegInt(9)=-10", NegInt(9), "29", false},
	{"NegInt(99)=-100", NegInt(99), "3863", false},
	{"NegInt(999)=-1000", NegInt(999), "3903e7", false},

	// Byte strings
	{"Bytes(nil)", Bytes(nil), "40", false},
	{"Bytes([1,2,3,4])", Bytes([]byte{1, 2, 3, 4}), "4401020304", false},

	// Text strings
	{`Text("")`, Text(""), "60", false},
	{`Text("a")`, Text("a"), "6161", false},
	{`Text("IETF")`, Text("IETF"), "6449455446", false},
	{`Text("\"\\")`, Text("\"\\"), "62225c", false},

	// Simple values
	{"Bool(false)", Bool(false), "f4", false},
	{"Bool(true)", Bool(true), "f5", false},
	{"Null()", Null(), "f6", false},
	{"Undefined()", Undefined(), "f7", false},

	// Arrays
	{"MakeArray()", MakeArray(), "80", false},
	{"MakeArray(1,2,3)", MakeArray(Uint(1), Uint(2), Uint(3)), "83010203", false},

	// Maps
	{"MakeMap()", MakeMap(), "a0", false},
	{"Map{1:2,3:4}", MakeMap(MapEntry{Key: Uint(1), Value: Uint(2)}, MapEntry{Key: Uint(3), Value: Uint(4)}), "a201020304", false},

	// Tags
	{"Tag{1,1363896240}", MakeTag(1, Uint(1363896240)), "c11a514b67b0", false},

	// Decode-only: float16 → Float64
	{"f16 0.0", Float64(0.0), "f90000", true},
	{"f16 1.0", Float64(1.0), "f93c00", true},
	{"f16 1.5", Float64(1.5), "f93e00", true},
	{"f16 65504.0", Float64(65504.0), "f97bff", true},

	// Decode-only: float32
	{"f32 100000.0", Float32(100000.0), "fa47c35000", true},

	// Decode-only: float64
	{"f64 1.1", Float64(1.1), "fb3ff199999999999a", true},

	// Decode-only: indefinite-length
	{"indef empty array", MakeArray(), "9fff", true},
	{"indef byte string", Bytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05}), "5f42010243030405ff", true},
	{"indef text string", Text("streaming"), "7f657374726561646d696e67ff", true},
}

func TestRFC8949AppendixA(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	for _, tc := range rfc8949Vectors {
		t.Run(tc.name, func(t *testing.T) {
			expectedBytes, err := hex.DecodeString(tc.hexEncoded)
			if err != nil {
				t.Fatalf("bad test hex %q: %v", tc.hexEncoded, err)
			}

			// Encode test (skip for decode-only vectors)
			if !tc.decodeOnly {
				got, err := enc.Encode(nil, tc.value)
				if err != nil {
					t.Fatalf("Encode(%v): %v", tc.value, err)
				}
				if !bytes.Equal(got, expectedBytes) {
					t.Errorf("Encode(%v) = %x, want %x", tc.value, got, expectedBytes)
				}
			}

			// Decode test
			decoded, err := dec.Decode(expectedBytes)
			if err != nil {
				t.Fatalf("Decode(%x): %v", expectedBytes, err)
			}

			// Compare decoded value by re-encoding in deterministic mode
			// This handles structural equality correctly.
			gotEnc, err := enc.Encode(nil, decoded)
			if err != nil {
				t.Fatalf("re-encode decoded value: %v", err)
			}
			wantEnc, err := enc.Encode(nil, tc.value)
			if err != nil {
				t.Fatalf("encode expected value: %v", err)
			}
			if !bytes.Equal(gotEnc, wantEnc) {
				t.Errorf("Decode(%x) produced value encoding %x, want %x", expectedBytes, gotEnc, wantEnc)
			}

			// Round-trip test for encode vectors
			if !tc.decodeOnly {
				roundTrip, err := enc.Encode(nil, decoded)
				if err != nil {
					t.Fatalf("round-trip encode: %v", err)
				}
				if !bytes.Equal(roundTrip, expectedBytes) {
					t.Errorf("round-trip: got %x, want %x", roundTrip, expectedBytes)
				}
			}
		})
	}
}
