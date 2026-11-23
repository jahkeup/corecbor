// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cose"
)

// okpKey is an Ed25519 public COSE_Key with one extra parameter: the
// map header counts it, and extra is appended as label + value.
func okpKey(extra string) []byte {
	b, _ := hex.DecodeString("a4" + "0101" + "2006" + "215820" +
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" + extra)
	return b
}

// TestParseKeyRejectsNonFinite: a key whose parameters hold NaN or ±Inf
// can't be re-encoded, so ParseKey reports it with the label.
func TestParseKeyRejectsNonFinite(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		label       any
	}{
		{"float32 NaN", "30" + "faffff3030", int64(-17)},
		{"float16 NaN", "30" + "f97e00", int64(-17)},
		{"float64 +Inf", "30" + "fb7ff0000000000000", int64(-17)},
		{"-Inf in an array", "30" + "8201f9fc00", int64(-17)},
		{"NaN in a map", "30" + "a101f97e00", int64(-17)},
		{"text label", "6178" + "f97e00", "x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cose.ParseKey(okpKey(tc.extra))
			if !errors.Is(err, cose.ErrNonFiniteKeyParam) || !errors.Is(err, cose.ErrMalformed) {
				t.Fatalf("err = %v, want ErrNonFiniteKeyParam and ErrMalformed", err)
			}
			var pe *cose.KeyParamError
			if !errors.As(err, &pe) || pe.Label != tc.label {
				t.Fatalf("err = %v, want a *KeyParamError with label %v", err, tc.label)
			}
		})
	}

	// A finite float parameter still parses and round-trips.
	in := okpKey("30" + "fa3fc00000")
	k, err := cose.ParseKey(in)
	if err != nil {
		t.Fatalf("finite float: %v", err)
	}
	out, err := k.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}
	if _, err := cose.ParseKey(out); err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	// ParseKeySet reports the same error.
	set := append([]byte{0x81}, okpKey("30f97e00")...)
	if _, err := cose.ParseKeySet(set); !errors.Is(err, cose.ErrNonFiniteKeyParam) {
		t.Fatalf("ParseKeySet err = %v, want ErrNonFiniteKeyParam", err)
	}
}
