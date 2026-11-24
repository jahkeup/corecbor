// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// 037 C12: under InvalidUTF8Reject each chunk of an indefinite-length
// text string must be valid UTF-8 by itself: a character split across
// chunks is rejected (RFC 8949 §3.2.3).
func TestC12SplitUTF8AcrossChunks(t *testing.T) {
	split := []byte{0x7f, 0x61, 0xc3, 0x61, 0xa9, 0xff} // "é" split in two chunks
	whole := []byte{0x7f, 0x62, 0xc3, 0xa9, 0x60, 0xff}
	if _, err := NewDecoder(RejectInvalidUTF8()).Decode(split); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("split: err = %v, want ErrInvalidUTF8", err)
	}
	for _, src := range [][]byte{split, whole} {
		v, err := NewDecoder().Decode(src)
		if err != nil || v.Str != "é" {
			t.Fatalf("%x: default = %q, %v", src, v.Str, err)
		}
	}
	if v, err := NewDecoder(RejectInvalidUTF8()).Decode(whole); err != nil || v.Str != "é" {
		t.Fatalf("whole chunks: %q, %v", v.Str, err)
	}
	// In a map key and inside an array too.
	for _, src := range [][]byte{
		append(append([]byte{0xa1}, split...), 0x01),
		append([]byte{0x81}, split...),
	} {
		if _, err := NewDecoder(RejectInvalidUTF8()).Decode(src); !errors.Is(err, ErrInvalidUTF8) {
			t.Fatalf("%x: err = %v, want ErrInvalidUTF8", src, err)
		}
	}
}

// 037 C11: ModePreferredPlus rejects maps with repeated keys, as the
// other deterministic modes do; Permissive writes them unless
// CheckDuplicateMapKeys is set. Keys compare in the data model.
func TestC11EncoderDuplicateKeys(t *testing.T) {
	big := make([]MapEntry, 40)
	for i := range big {
		big[i] = MapEntry{Key: Uint(uint64(i)), Value: Null()}
	}
	bigDup := append(append([]MapEntry{}, big...), MapEntry{Key: Uint(7), Value: Null()})
	for _, tc := range []struct {
		name string
		m    Value
		dup  bool
	}{
		{"distinct", cbor.MakeMap(MapEntry{Key: Text("a"), Value: Uint(1)}, MapEntry{Key: Text("b"), Value: Uint(2)}), false},
		{"text", cbor.MakeMap(MapEntry{Key: Text("a"), Value: Uint(1)}, MapEntry{Key: Text("a"), Value: Uint(2)}), true},
		{"float widths", cbor.MakeMap(MapEntry{Key: Float32(1), Value: Uint(1)}, MapEntry{Key: Float64(1), Value: Uint(2)}), true},
		{"signed zero", cbor.MakeMap(MapEntry{Key: Float64(0), Value: Uint(1)}, MapEntry{Key: Float64(math.Copysign(0, -1)), Value: Uint(2)}), true},
		{"int and float", cbor.MakeMap(MapEntry{Key: Uint(1), Value: Uint(1)}, MapEntry{Key: Float64(1), Value: Uint(2)}), false},
		{"large distinct", cbor.MakeMapFromSlice(big), false},
		{"large", cbor.MakeMapFromSlice(bigDup), true},
		{"nested", MakeArray(cbor.MakeMap(MapEntry{Key: Text("a"), Value: Uint(1)}, MapEntry{Key: Text("a"), Value: Uint(2)})), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, e := range map[string]*Encoder{
				"PreferredPlus":                    New(ModePreferredPlus, AllowNonFiniteFloats()),
				"Permissive+CheckDuplicateMapKeys": New(ModePermissive, CheckDuplicateMapKeys()),
			} {
				_, err := e.Encode(nil, tc.m)
				if tc.dup && !errors.Is(err, ErrDuplicateMapKey) {
					t.Errorf("%s: err = %v, want ErrDuplicateMapKey", name, err)
				}
				if !tc.dup && err != nil {
					t.Errorf("%s: %v", name, err)
				}
			}
			// Permissive keeps writing what it's given by default.
			out, err := New(ModePermissive).Encode(nil, tc.m)
			if err != nil {
				t.Fatalf("Permissive: %v", err)
			}
			if tc.dup && tc.name == "text" && !bytes.Equal(out, []byte{0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02}) {
				t.Fatalf("Permissive: %x", out)
			}
		})
	}
}
