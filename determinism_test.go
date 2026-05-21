package corecbor

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

func TestEncodeDeterminism(t *testing.T) {
	// Encode the same complex Value tree 100 times in CoreDeterministic mode.
	// Assert all 100 outputs are byte-equal.
	enc := New(ModeCoreDeterministic)

	complexValue := Map{
		{Key: Uint(1), Value: Array{Uint(10), Text("hello"), Bytes([]byte{0xde, 0xad})}},
		{Key: Text("key"), Value: Map{
			{Key: Uint(99), Value: Bool(true)},
			{Key: NegInt(5), Value: Null{}},
		}},
		{Key: NegInt(0), Value: Tag{ID: 1, Inner: Uint(1234567890)}},
		{Key: Bytes([]byte{0x01}), Value: Float64(3.14159)},
		{Key: Bool(false), Value: Array{Undefined{}, Float32(1.5)}},
	}

	first, err := enc.Encode(nil, complexValue)
	if err != nil {
		t.Fatalf("first encode failed: %v", err)
	}

	for i := range 99 {
		got, err := enc.Encode(nil, complexValue)
		if err != nil {
			t.Fatalf("encode iteration %d failed: %v", i+1, err)
		}
		if !bytes.Equal(first, got) {
			t.Fatalf("non-deterministic at iteration %d:\n  first: %x\n  got:   %x", i+1, first, got)
		}
	}
}

func TestEncodeDeterminism_MapKeyShuffle(t *testing.T) {
	// Build the same logical map with 100 different []MapEntry orderings.
	// Encode each in CoreDeterministic. Assert all 100 encoded forms are byte-equal.
	enc := New(ModeCoreDeterministic)

	baseEntries := []MapEntry{
		{Key: Uint(1), Value: Text("one")},
		{Key: Uint(2), Value: Text("two")},
		{Key: Uint(3), Value: Text("three")},
		{Key: Text("alpha"), Value: Uint(100)},
		{Key: Text("beta"), Value: Uint(200)},
		{Key: NegInt(0), Value: Bool(true)},
		{Key: Bytes([]byte{0x01, 0x02}), Value: Null{}},
		{Key: Bool(false), Value: Float64(2.718)},
	}

	// Encode with the original order to get reference output.
	m := make(Map, len(baseEntries))
	copy(m, baseEntries)
	first, err := enc.Encode(nil, m)
	if err != nil {
		t.Fatalf("first encode failed: %v", err)
	}

	rng := rand.New(rand.NewPCG(42, 99))

	for i := range 99 {
		// Shuffle entries.
		shuffled := make(Map, len(baseEntries))
		copy(shuffled, baseEntries)
		rng.Shuffle(len(shuffled), func(a, b int) {
			shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
		})

		got, err := enc.Encode(nil, shuffled)
		if err != nil {
			t.Fatalf("encode iteration %d failed: %v", i+1, err)
		}
		if !bytes.Equal(first, got) {
			t.Fatalf("non-deterministic at iteration %d (shuffled input):\n  first: %x\n  got:   %x", i+1, first, got)
		}
	}
}
