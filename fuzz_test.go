package corecbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/rand/v2"
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

func FuzzDecodeRoundTripStrict(f *testing.F) {
	for _, tc := range rfc8949Vectors {
		if !tc.decodeOnly {
			b, _ := hex.DecodeString(tc.hexEncoded)
			f.Add(b)
		}
	}

	enc := New(ModeCoreDeterministic)
	strictDec := StrictDecoder()
	permDec := NewDecoder()

	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := strictDec.Decode(data)
		if err != nil {
			return
		}

		canonical, err := enc.Encode(nil, v)
		if err != nil {
			t.Fatalf("det-encode failed: %v", err)
		}

		// The canonical form must be a fixed point: decode → encode → same bytes.
		v2, err := permDec.Decode(canonical)
		if err != nil {
			t.Fatalf("re-decode of canonical failed: %v (canonical: %x)", err, canonical)
		}

		canonical2, err := enc.Encode(nil, v2)
		if err != nil {
			t.Fatalf("re-encode failed: %v", err)
		}

		if !bytes.Equal(canonical, canonical2) {
			t.Fatalf("det-encode not idempotent:\n  first:  %x\n  second: %x", canonical, canonical2)
		}
	})
}

func FuzzMapKeyOrderInvariance(f *testing.F) {
	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	seeds := []Map{
		{{Key: Uint(1), Value: Uint(2)}, {Key: Uint(3), Value: Uint(4)}},
		{{Key: Text("a"), Value: Uint(1)}, {Key: Text("b"), Value: Uint(2)}, {Key: Text("c"), Value: Uint(3)}},
		{{Key: Uint(10), Value: Bool(true)}, {Key: NegInt(0), Value: Bool(false)}, {Key: Bytes([]byte{1}), Value: Null{}}},
	}
	for _, m := range seeds {
		b, _ := enc.Encode(nil, m)
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := dec.Decode(data)
		if err != nil {
			return
		}
		m, ok := v.(Map)
		if !ok || len(m) < 2 {
			return
		}

		// Skip maps with duplicate encoded keys (unstable sort for equal keys).
		seen := make(map[string]struct{}, len(m))
		for _, entry := range m {
			kb, err := enc.Encode(nil, entry.Key)
			if err != nil {
				return
			}
			s := string(kb)
			if _, dup := seen[s]; dup {
				return
			}
			seen[s] = struct{}{}
		}

		canonical, err := enc.Encode(nil, m)
		if err != nil {
			return
		}

		rng := rand.New(rand.NewPCG(uint64(len(data)), uint64(data[0])))
		shuffled := make(Map, len(m))
		copy(shuffled, m)
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})

		reEncoded, err := enc.Encode(nil, shuffled)
		if err != nil {
			t.Fatalf("re-encode shuffled failed: %v", err)
		}
		if !bytes.Equal(canonical, reEncoded) {
			t.Fatalf("map key order affected output:\n  canonical: %x\n  shuffled:  %x", canonical, reEncoded)
		}
	})
}

func FuzzResourceLimits(f *testing.F) {
	// Adversarial seeds: deep nesting, huge declared lengths.
	f.Add([]byte{0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00})
	f.Add([]byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x00})
	f.Add([]byte{0x83, 0x01, 0x02, 0x03})

	dec := NewDecoder(
		WithMaxNestingDepth(16),
		WithMaxArrayLength(64),
		WithMaxByteStringLength(256),
	)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, err := dec.Decode(data)
		if err == nil {
			return
		}
		if errors.Is(err, ErrMaxNestingDepth) ||
			errors.Is(err, ErrMaxArrayLength) ||
			errors.Is(err, ErrMaxByteStringLength) ||
			errors.Is(err, ErrTruncated) ||
			errors.Is(err, ErrTrailingBytes) ||
			errors.Is(err, ErrReservedAI) ||
			errors.Is(err, ErrNonShortest) ||
			errors.Is(err, ErrIndefiniteLength) ||
			errors.Is(err, ErrInvalidUTF8) ||
			errors.Is(err, ErrDuplicateMapKey) ||
			errors.Is(err, ErrNonFiniteFloat) ||
			errors.Is(err, ErrNullMapKey) ||
			errors.Is(err, ErrUnknownTag) {
			return
		}
		// Any other decode error is acceptable (malformed input).
	})
}

func FuzzTagPreservation(f *testing.F) {
	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	seeds := []Value{
		Tag{ID: 1, Inner: Uint(1000)},
		Tag{ID: 24, Inner: Bytes([]byte{0x01})},
		Tag{ID: 100, Inner: Text("hello")},
		Tag{ID: 1, Inner: Tag{ID: 2, Inner: Uint(42)}},
	}
	for _, s := range seeds {
		b, _ := enc.Encode(nil, s)
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := dec.Decode(data)
		if err != nil {
			return
		}

		tag, ok := v.(Tag)
		if !ok {
			return
		}

		encoded, err := enc.Encode(nil, tag)
		if err != nil {
			return
		}

		v2, err := dec.Decode(encoded)
		if err != nil {
			t.Fatalf("re-decode failed: %v (encoded: %x)", err, encoded)
		}

		tag2, ok := v2.(Tag)
		if !ok {
			t.Fatalf("re-decoded value is %T, not Tag", v2)
		}

		if tag.ID != tag2.ID {
			t.Fatalf("tag ID mismatch: %d vs %d", tag.ID, tag2.ID)
		}

		innerEnc1, err := enc.Encode(nil, tag.Inner)
		if err != nil {
			return
		}
		innerEnc2, err := enc.Encode(nil, tag2.Inner)
		if err != nil {
			t.Fatalf("re-encode inner failed: %v", err)
		}
		if !bytes.Equal(innerEnc1, innerEnc2) {
			t.Fatalf("tag inner mismatch:\n  first:  %x\n  second: %x", innerEnc1, innerEnc2)
		}
	})
}
