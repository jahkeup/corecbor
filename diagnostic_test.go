// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/hex"
	"math"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func TestDiagnostic_Uint(t *testing.T) {
	tests := []struct {
		val  Value
		want string
	}{
		{Uint(0), "0"},
		{Uint(23), "23"},
		{Uint(1000000), "1000000"},
		{Uint(math.MaxUint64), "18446744073709551615"},
	}
	for _, tc := range tests {
		got := DiagnosticValue(tc.val)
		if got != tc.want {
			t.Errorf("DiagnosticValue(%v) = %q, want %q", tc.val, got, tc.want)
		}
	}
}

func TestDiagnostic_NegInt(t *testing.T) {
	tests := []struct {
		val  Value
		want string
	}{
		{NegInt(0), "-1"},
		{NegInt(9), "-10"},
		{NegInt(999), "-1000"},
	}
	for _, tc := range tests {
		got := DiagnosticValue(tc.val)
		if got != tc.want {
			t.Errorf("DiagnosticValue(%v) = %q, want %q", tc.val, got, tc.want)
		}
	}
}

func TestDiagnostic_Bytes(t *testing.T) {
	tests := []struct {
		val  Value
		want string
	}{
		{Bytes(nil), "h''"},
		{Bytes([]byte{}), "h''"},
		{Bytes([]byte{0x01, 0x02, 0x03, 0x04}), "h'01020304'"},
		{Bytes([]byte{0xde, 0xad, 0xbe, 0xef}), "h'deadbeef'"},
	}
	for _, tc := range tests {
		got := DiagnosticValue(tc.val)
		if got != tc.want {
			t.Errorf("DiagnosticValue(%v) = %q, want %q", tc.val, got, tc.want)
		}
	}
}

func TestDiagnostic_Text(t *testing.T) {
	tests := []struct {
		val  Value
		want string
	}{
		{Text("hello"), `"hello"`},
		{Text(""), `""`},
		{Text("café"), `"café"`},
		{Text("line\nbreak"), `"line\nbreak"`},
		{Text("tab\there"), `"tab\there"`},
		{Text(`quote"`), `"quote\""`},
		{Text(`back\slash`), `"back\\slash"`},
		{Text("\x00"), `"\u0000"`},
		{Text("\x1f"), `"\u001f"`},
	}
	for _, tc := range tests {
		got := DiagnosticValue(tc.val)
		if got != tc.want {
			t.Errorf("DiagnosticValue(%v) = %q, want %q", tc.val, got, tc.want)
		}
	}
}

func TestDiagnostic_Array(t *testing.T) {
	tests := []struct {
		val  Value
		want string
	}{
		{Array(nil), "[]"},
		{Array{Uint(1), Uint(2), Uint(3)}, "[1, 2, 3]"},
		{Array{Array{Uint(1)}, Array{Uint(2)}}, "[[1], [2]]"},
		{Array{Text("a"), Uint(1), Bool(true)}, `["a", 1, true]`},
	}
	for _, tc := range tests {
		got := DiagnosticValue(tc.val)
		if got != tc.want {
			t.Errorf("DiagnosticValue(%v) = %q, want %q", tc.val, got, tc.want)
		}
	}
}

func TestDiagnostic_Map(t *testing.T) {
	tests := []struct {
		val  Value
		want string
	}{
		{Map(nil), "{}"},
		{Map{{Key: Text("a"), Value: Uint(1)}}, `{"a": 1}`},
		{Map{{Key: Uint(1), Value: Text("x")}}, `{1: "x"}`},
		{Map{
			{Key: Text("a"), Value: Uint(1)},
			{Key: Uint(2), Value: Text("b")},
		}, `{"a": 1, 2: "b"}`},
	}
	for _, tc := range tests {
		got := DiagnosticValue(tc.val)
		if got != tc.want {
			t.Errorf("DiagnosticValue(%v) = %q, want %q", tc.val, got, tc.want)
		}
	}
}

func TestDiagnostic_Tag(t *testing.T) {
	tests := []struct {
		val  Value
		want string
	}{
		{Tag{ID: 1, Inner: Uint(1363896240)}, "1(1363896240)"},
		{Tag{ID: 0, Inner: Text("2013-03-21T20:04:00Z")}, `0("2013-03-21T20:04:00Z")`},
		{Tag{ID: 24, Inner: Bytes([]byte{0x01})}, "24(h'01')"},
	}
	for _, tc := range tests {
		got := DiagnosticValue(tc.val)
		if got != tc.want {
			t.Errorf("DiagnosticValue(%v) = %q, want %q", tc.val, got, tc.want)
		}
	}
}

func TestDiagnostic_Floats(t *testing.T) {
	tests := []struct {
		val  Value
		want string
	}{
		{Float64(0.0), "0.0"},
		{Float64(math.Copysign(0, -1)), "-0.0"},
		{Float64(1.5), "1.5"},
		{Float64(math.Inf(1)), "Infinity"},
		{Float64(math.Inf(-1)), "-Infinity"},
		{Float64(math.NaN()), "NaN"},
		{Float32(0.0), "0.0"},
		{Float32(float32(math.Copysign(0, -1))), "-0.0"},
		{Float32(1.5), "1.5"},
		{Float64(1000000.0), "1000000.0"},
		{Float64(1.1), "1.1"},
	}
	for _, tc := range tests {
		got := DiagnosticValue(tc.val)
		if got != tc.want {
			t.Errorf("DiagnosticValue(%v) = %q, want %q", tc.val, got, tc.want)
		}
	}
}

func TestDiagnostic_Bool_Null_Undefined(t *testing.T) {
	tests := []struct {
		val  Value
		want string
	}{
		{Bool(true), "true"},
		{Bool(false), "false"},
		{Null{}, "null"},
		{Undefined{}, "undefined"},
	}
	for _, tc := range tests {
		got := DiagnosticValue(tc.val)
		if got != tc.want {
			t.Errorf("DiagnosticValue(%v) = %q, want %q", tc.val, got, tc.want)
		}
	}
}

func TestDiagnostic_Simple(t *testing.T) {
	tests := []struct {
		val  Value
		want string
	}{
		{Simple(0), "simple(0)"},
		{Simple(19), "simple(19)"},
		{Simple(32), "simple(32)"},
		{Simple(255), "simple(255)"},
	}
	for _, tc := range tests {
		got := DiagnosticValue(tc.val)
		if got != tc.want {
			t.Errorf("DiagnosticValue(%v) = %q, want %q", tc.val, got, tc.want)
		}
	}
}

func TestDiagnostic_Compact(t *testing.T) {
	tests := []struct {
		val  Value
		want string
	}{
		{Array{Uint(1), Uint(2), Uint(3)}, "[1,2,3]"},
		{Map{{Key: Text("a"), Value: Uint(1)}, {Key: Text("b"), Value: Uint(2)}}, `{"a":1,"b":2}`},
	}
	for _, tc := range tests {
		got := DiagnosticValue(tc.val, DiagCompact())
		if got != tc.want {
			t.Errorf("DiagnosticValue compact = %q, want %q", got, tc.want)
		}
	}
}

func TestDiagnostic_FromBytes(t *testing.T) {
	tests := []struct {
		hexInput string
		want     string
	}{
		{"00", "0"},
		{"1864", "100"},
		{"3863", "-100"},
		{"f5", "true"},
		{"f6", "null"},
		{"6568656c6c6f", `"hello"`},
		{"8401020383010203", "[1, 2, 3, [1, 2, 3]]"},
	}
	for _, tc := range tests {
		data, err := hex.DecodeString(tc.hexInput)
		if err != nil {
			t.Fatalf("bad hex %q: %v", tc.hexInput, err)
		}
		got, err := Diagnostic(data)
		if err != nil {
			t.Errorf("Diagnostic(%s) error: %v", tc.hexInput, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Diagnostic(%s) = %q, want %q", tc.hexInput, got, tc.want)
		}
	}
}

func TestDiagnosticValue_RFC8949Examples(t *testing.T) {
	tests := []struct {
		name string
		val  cbor.Value
		want string
	}{
		{"zero", Uint(0), "0"},
		{"one", Uint(1), "1"},
		{"ten", Uint(10), "10"},
		{"twentythree", Uint(23), "23"},
		{"twentyfour", Uint(24), "24"},
		{"hundred", Uint(100), "100"},
		{"thousand", Uint(1000), "1000"},
		{"million", Uint(1000000), "1000000"},
		{"neg1", NegInt(0), "-1"},
		{"neg10", NegInt(9), "-10"},
		{"neg100", NegInt(99), "-100"},
		{"neg1000", NegInt(999), "-1000"},
		{"empty_bytes", Bytes(nil), "h''"},
		{"bytes_01020304", Bytes([]byte{0x01, 0x02, 0x03, 0x04}), "h'01020304'"},
		{"empty_text", Text(""), `""`},
		{"text_a", Text("a"), `"a"`},
		{"text_IETF", Text("IETF"), `"IETF"`},
		{"text_escape", Text("\"\\"), `"\"\\"`},
		{"empty_array", Array{}, "[]"},
		{"array_123", Array{Uint(1), Uint(2), Uint(3)}, "[1, 2, 3]"},
		{
			"nested_array",
			Array{Uint(1), Array{Uint(2), Uint(3)}, Array{Uint(4), Uint(5)}},
			"[1, [2, 3], [4, 5]]",
		},
		{"false", Bool(false), "false"},
		{"true", Bool(true), "true"},
		{"null", Null{}, "null"},
		{"undefined", Undefined{}, "undefined"},
		{"float_1.5", Float64(1.5), "1.5"},
		{"tag_epoch", Tag{ID: 1, Inner: Uint(1363896240)}, "1(1363896240)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DiagnosticValue(tc.val)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
