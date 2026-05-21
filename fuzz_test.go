package corecbor

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func FuzzDecodeNeverPanics(f *testing.F) {
	for _, tc := range rfc8949Vectors {
		b, _ := hex.DecodeString(tc.hexEncoded)
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Add([]byte{0x9f, 0x01, 0x02, 0xff})

	dec := NewDecoder()
	f.Fuzz(func(t *testing.T, data []byte) {
		dec.Decode(data) //nolint:errcheck
	})
}

func FuzzDecodeRoundTripPermissive(f *testing.F) {
	for _, tc := range rfc8949Vectors {
		b, _ := hex.DecodeString(tc.hexEncoded)
		f.Add(b)
	}

	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := dec.Decode(data)
		if err != nil {
			return
		}

		encoded, err := enc.Encode(nil, v)
		if err != nil {
			return
		}

		v2, err := dec.Decode(encoded)
		if err != nil {
			t.Fatalf("re-decode failed: %v (encoded: %x)", err, encoded)
		}

		encoded2, err := enc.Encode(nil, v2)
		if err != nil {
			t.Fatalf("re-encode failed: %v", err)
		}

		if !bytes.Equal(encoded, encoded2) {
			t.Fatalf("round-trip mismatch:\n  first:  %x\n  second: %x", encoded, encoded2)
		}
	})
}

func FuzzEncodeStrictDeterminism(f *testing.F) {
	for _, tc := range rfc8949Vectors {
		b, _ := hex.DecodeString(tc.hexEncoded)
		f.Add(b)
	}

	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := dec.Decode(data)
		if err != nil {
			return
		}

		first, err := enc.Encode(nil, v)
		if err != nil {
			return
		}

		for i := range 9 {
			got, err := enc.Encode(nil, v)
			if err != nil {
				t.Fatalf("encode iteration %d: %v", i+1, err)
			}
			if !bytes.Equal(first, got) {
				t.Fatalf("non-deterministic at iteration %d:\n  first: %x\n  got:   %x", i+1, first, got)
			}
		}
	})
}
