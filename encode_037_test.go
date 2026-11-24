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
