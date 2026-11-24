// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// Proposal 037: regression tests for the root-module release blockers.

// C1: a long chain of leading self-describe tags can't overflow the
// stack in any entry point that strips it.
func TestC1SelfDescribeChain(t *testing.T) {
	src := append(bytes.Repeat([]byte{0xd9, 0xd9, 0xf7}, 2<<20), 0x82, 0x01, 0x02)

	if s, err := Diagnostic(src); err != nil || s != "[1, 2]" {
		t.Fatalf("Diagnostic = %q, %v; want [1, 2]", s, err)
	}
	var got []int
	if err := Unmarshal(src, &got); err != nil || len(got) != 2 {
		t.Fatalf("Unmarshal = %v, %v", got, err)
	}
	if _, err := DeterministicDecoder().Decode(src); err != nil {
		t.Fatalf("DeterministicDecoder: %v", err)
	}
	s := NewDecoder().Stream(bytes.NewReader(src))
	if !s.Next() || s.Err() != nil {
		t.Fatalf("Stream.Next: %v", s.Err())
	}
}

// C4: Decoder.DecodeFrom and Stream apply the memory budget to each
// item, buffered bytes included.
func TestC4StreamBudgetPerItem(t *testing.T) {
	item := append([]byte{0x58, 200}, bytes.Repeat([]byte{0xaa}, 200)...)
	src := bytes.Repeat(item, 50)
	dec := NewDecoder(WithMemoryBudget(1000))
	s := dec.Stream(bytes.NewReader(src))
	n := 0
	for s.Next() {
		n++
	}
	if s.Err() != nil || n != 50 {
		t.Fatalf("stream: %d items, err %v; want 50, nil", n, s.Err())
	}
	r := bytes.NewReader(src)
	for i := range 50 {
		if _, err := dec.DecodeFrom(r); err != nil {
			t.Fatalf("DecodeFrom item %d: %v", i, err)
		}
	}
	// A single item larger than the budget fails without being read whole.
	big := append([]byte{0x5a, 0x00, 0x10, 0x00, 0x00}, bytes.Repeat([]byte{0xaa}, 1<<20)...)
	r = bytes.NewReader(big)
	if _, err := dec.DecodeFrom(r); !errors.Is(err, cbor.ErrMemoryBudgetExceeded) {
		t.Fatalf("1 MiB item under a 1000-byte budget: err = %v", err)
	}
	if read := len(big) - r.Len(); read > 1<<17 {
		t.Fatalf("read %d bytes of an item over budget", read)
	}
}

// C6: Stream.Next reports a truncated last item instead of ending
// cleanly; only a stream that ends between items ends without error.
func TestC6StreamTruncatedLastItem(t *testing.T) {
	for _, tc := range []struct {
		name  string
		src   []byte
		items int
		want  error
	}{
		{"clean end", []byte{0x01, 0x02}, 2, nil},
		{"empty", nil, 0, nil},
		{"truncated head", []byte{0x01, 0x19, 0x01}, 1, ErrTruncated},
		{"truncated array", []byte{0x01, 0x82, 0x01}, 1, ErrTruncated},
		{"truncated string", []byte{0x01, 0x43, 0x01}, 1, ErrTruncated},
		{"truncated indefinite", []byte{0x01, 0x9f, 0x01}, 1, ErrTruncated},
		{"wrong chunk type", []byte{0x01, 0x5f, 0x61, 0x61, 0xff}, 1, ErrInvalidChunk},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, budget := range []int{0, 1 << 20} {
				s := NewDecoder(WithMemoryBudget(budget)).Stream(bytes.NewReader(tc.src))
				n := 0
				for s.Next() {
					n++
				}
				if n != tc.items {
					t.Fatalf("budget %d: %d items, want %d", budget, n, tc.items)
				}
				if tc.want == nil && s.Err() != nil || tc.want != nil && !errors.Is(s.Err(), tc.want) {
					t.Fatalf("budget %d: Err() = %v, want %v", budget, s.Err(), tc.want)
				}
			}
		})
	}
}

// C6: a chunk of the wrong type in an indefinite-length string is a
// well-formedness error of its own, not truncation, everywhere.
func TestC6WrongChunkType(t *testing.T) {
	for _, src := range [][]byte{
		{0x5f, 0x61, 0x61, 0xff},       // text chunk in bytes
		{0x7f, 0x41, 0x61, 0xff},       // bytes chunk in text
		{0x5f, 0x5f, 0xff, 0xff},       // nested indefinite chunk
		{0x7f, 0x01, 0xff},             // integer chunk
		{0x81, 0x7f, 0x60, 0x41, 0x00}, // inside an array
	} {
		if _, err := NewDecoder().Decode(src); !errors.Is(err, ErrInvalidChunk) || errors.Is(err, ErrTruncated) {
			t.Errorf("Decode(%x) = %v, want ErrInvalidChunk", src, err)
		}
		if _, err := NewDecoder().DecodeFrom(bytes.NewReader(src)); !errors.Is(err, ErrInvalidChunk) {
			t.Errorf("DecodeFrom(%x) = %v, want ErrInvalidChunk", src, err)
		}
		if _, err := NewDecoder().Cursor(src).Skip(); !errors.Is(err, ErrInvalidChunk) {
			t.Errorf("Cursor.Skip(%x) = %v, want ErrInvalidChunk", src, err)
		}
	}
}

// dupMarshaler returns fixed bytes from MarshalCBOR.
type dupMarshaler []byte

func (d dupMarshaler) MarshalCBOR() ([]byte, error) { return d, nil }

// C8: Marshaler output with repeated map keys is never merged: the
// deterministic modes reject it, and Permissive keeps every entry.
func TestC8MarshalerDuplicateKeys(t *testing.T) {
	dup := []byte{0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02} // {"a": 1, "a": 2}
	sameKey := []byte{0xa2, 0x01, 0x01, 0x18, 0x01, 0x02}   // {1: 1, 1 (non-shortest): 2}
	for _, mode := range []Mode{ModeCoreDeterministic, ModeCanonical, ModeCTAP2, ModePreferredPlus} {
		for _, in := range []any{RawMessage(dup), dupMarshaler(dup), RawMessage(sameKey), []any{dupMarshaler(sameKey)}} {
			out, err := New(mode).Marshal(in)
			if !errors.Is(err, ErrDuplicateMapKey) {
				t.Errorf("mode %d %T(%x): Marshal = %x, %v; want ErrDuplicateMapKey", mode, in, in, out, err)
			}
		}
	}
	out, err := New(ModePermissive).Marshal(dupMarshaler(dup))
	if err != nil || !bytes.Equal(out, dup) {
		t.Fatalf("Permissive: %x, %v; want %x", out, err, dup)
	}
}

// C9: RequireDeterministic accepts only the NaN the deterministic
// encoders write (f97e00), so re-encoding reproduces accepted input;
// AllowNaNPayloads restores the RFC 8949 §4.2.1 rule alone.
func TestC9DeterministicNaN(t *testing.T) {
	enc := New(ModeCoreDeterministic, AllowNonFiniteFloats())
	for _, tc := range []struct {
		src      []byte
		def, rfc bool // accepted by default, with AllowNaNPayloads
	}{
		{[]byte{0xf9, 0x7e, 0x00}, true, true},
		{[]byte{0xf9, 0x7e, 0x01}, false, true},             // payload
		{[]byte{0xf9, 0xfe, 0x00}, false, true},             // sign
		{[]byte{0xfa, 0x7f, 0xc0, 0x00, 0x01}, false, true}, // payload needs single
		{[]byte{0xfa, 0x7f, 0xc0, 0x00, 0x00}, false, false},
		{[]byte{0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0}, false, false},
		{[]byte{0xf9, 0x7c, 0x00}, true, true}, // +Inf is reproduced
	} {
		v, err := NewDecoder(RequireDeterministic()).Decode(tc.src)
		if (err == nil) != tc.def {
			t.Errorf("RequireDeterministic(%x): err = %v, want accepted=%v", tc.src, err, tc.def)
		}
		if err == nil {
			if out, err := enc.Encode(nil, v); err != nil || !bytes.Equal(out, tc.src) {
				t.Errorf("%x accepted but re-encodes as %x, %v", tc.src, out, err)
			}
		} else if !errors.Is(err, ErrNotPreferred) {
			t.Errorf("RequireDeterministic(%x): err = %v, want ErrNotPreferred", tc.src, err)
		}
		for _, d := range []*Decoder{
			NewDecoder(RequireDeterministic(), AllowNaNPayloads()),
			NewDecoder(AllowNaNPayloads(), RequireDeterministic()),
		} {
			if _, err := d.Decode(tc.src); (err == nil) != tc.rfc {
				t.Errorf("AllowNaNPayloads(%x): err = %v, want accepted=%v", tc.src, err, tc.rfc)
			}
		}
		// DeterministicDecoder rejects every non-finite float, as
		// StrictDecoder does.
		if _, err := DeterministicDecoder().Decode(tc.src); !errors.Is(err, ErrNonFiniteFloat) {
			t.Errorf("DeterministicDecoder(%x): err = %v, want ErrNonFiniteFloat", tc.src, err)
		}
	}
	// RequirePreferredPlus keeps its own NaN rule.
	if _, err := NewDecoder(RequirePreferredPlus(), AllowNaNPayloads()).Decode([]byte{0xf9, 0x7e, 0x01}); !errors.Is(err, ErrNotPreferred) {
		t.Errorf("RequirePreferredPlus + AllowNaNPayloads: err = %v", err)
	}
}

// C5: a sequence of scalars is charged for its items, and each call
// starts from a fresh budget.
func TestC5SequenceBudget(t *testing.T) {
	src := bytes.Repeat([]byte{0x00}, 1000)
	dec := NewDecoder(WithMemoryBudget(10_000))
	if _, err := dec.DecodeSequence(src); !errors.Is(err, cbor.ErrMemoryBudgetExceeded) {
		t.Fatalf("1000 items in a 10 kB budget: err = %v", err)
	}
	if _, err := dec.DecodeSequence(src[:50]); err != nil {
		t.Fatalf("50 items: %v", err)
	}
	if _, err := dec.DecodeSequence(src[:50]); err != nil {
		t.Fatalf("50 items again: %v", err)
	}
}
