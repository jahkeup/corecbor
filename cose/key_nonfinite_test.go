// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose_test

import (
	"bytes"
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

// TestKeepParamsAsReceived: with the option, a non-finite parameter is
// kept byte for byte, listed by ReceivedParams, written back verbatim
// by MarshalCBOR, and removable with DeleteReceivedParam.
func TestKeepParamsAsReceived(t *testing.T) {
	keep := cose.KeepParamsAsReceived()
	for _, val := range []string{"faffff3030", "f97e01", "fb7ff0000000000000", "8201f9fe00"} {
		in := okpKey("30" + val)
		k, err := cose.ParseKey(in, keep)
		if err != nil {
			t.Fatalf("%s: %v", val, err)
		}
		got := k.ReceivedParams()
		if len(got) != 1 || hex.EncodeToString(got[int64(-17)]) != val {
			t.Fatalf("%s: ReceivedParams = %x", val, got)
		}
		out, err := k.MarshalCBOR()
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("%s: MarshalCBOR = %x, %v; want %x", val, out, err, in)
		}
		pub, err := k.Public()
		if err != nil || len(pub.ReceivedParams()) != 1 {
			t.Fatalf("%s: Public kept %v, %v", val, pub.ReceivedParams(), err)
		}
	}

	// A text label is kept too; ReceivedParams returns a copy.
	k, err := cose.ParseKey(okpKey("6178"+"f97e00"), keep)
	if err != nil {
		t.Fatal(err)
	}
	k.ReceivedParams()["x"][0] = 0
	if hex.EncodeToString(k.ReceivedParams()["x"]) != "f97e00" {
		t.Fatal("ReceivedParams aliases the key")
	}

	// Cleaning up: delete the parameter and the key marshals normally.
	k, _ = cose.ParseKey(okpKey("30f97e01"), keep)
	k.DeleteReceivedParam(-17)
	if k.ReceivedParams() != nil {
		t.Fatalf("after delete: %x", k.ReceivedParams())
	}
	out, err := k.MarshalCBOR()
	if err != nil || out[0] != 0xa3 {
		t.Fatalf("after delete MarshalCBOR = %x, %v", out, err)
	}

	// Defined labels are always parsed and checked.
	_, err = cose.ParseKey(okpKey("03f97e01"), keep)
	var pe *cose.KeyParamError
	if !errors.As(err, &pe) || pe.Label != int64(3) || !errors.Is(err, cose.ErrNonFiniteKeyParam) {
		t.Fatalf("alg NaN with keep: err = %v", err)
	}
}

func TestKeepParamsAsReceivedSetAndPrefix(t *testing.T) {
	keep := cose.KeepParamsAsReceived()
	one, two := okpKey("30f97e01"), okpKey("30f90000")
	set := append(append([]byte{0x82}, one...), two...)
	ks, err := cose.ParseKeySet(set, keep)
	if err != nil {
		t.Fatal(err)
	}
	if len(ks[0].ReceivedParams()) != 1 || ks[1].ReceivedParams() != nil {
		t.Fatalf("ReceivedParams = %x, %x", ks[0].ReceivedParams(), ks[1].ReceivedParams())
	}
	if out, err := ks.MarshalCBOR(); err != nil || !bytes.Equal(out, set) {
		t.Fatalf("KeySet MarshalCBOR = %x, %v; want %x", out, err, set)
	}

	k, rest, err := cose.ParseKeyPrefix(append(bytes.Clone(one), 0x01, 0x02), keep)
	if err != nil || !bytes.Equal(rest, []byte{1, 2}) || len(k.ReceivedParams()) != 1 {
		t.Fatalf("ParseKeyPrefix = %v, %x, %v", k, rest, err)
	}
}
