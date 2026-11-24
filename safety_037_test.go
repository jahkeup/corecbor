// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"testing"
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
