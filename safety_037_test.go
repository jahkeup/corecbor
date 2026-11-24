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
