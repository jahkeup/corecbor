// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"bytes"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// Proposal 037: regression tests for the root-module release blockers.

// selfDescribeChain returns n self-describe tag heads (d9d9f7) followed
// by item.
func selfDescribeChain(n int, item ...byte) []byte {
	b := bytes.Repeat([]byte{0xd9, 0xd9, 0xf7}, n)
	return append(b, item...)
}

// C1: a long chain of leading self-describe tags is stripped without
// recursion, so it can't overflow the stack (about 6 MB of d9d9f7 used
// to crash the process).
func TestC1SelfDescribeChainNoStackOverflow(t *testing.T) {
	const n = 2 << 20 // 6 MiB of tag heads
	src := selfDescribeChain(n, 0x82, 0x01, 0x02)

	v, used, err := Decode(src, DecodeOpts{})
	if err != nil || used != len(src) || v.Kind != cbor.KindArray || len(v.Items) != 2 {
		t.Fatalf("Decode = %v, %d, %v; want [1, 2], %d, nil", v, used, err, len(src))
	}

	// The checking decoder walks the same bytes.
	if _, _, err := Decode(src, DecodeOpts{RequirePreferred: true, RequireSortedMapKeys: true}); err != nil {
		t.Fatalf("checking Decode: %v", err)
	}

	c := NewCursor(src, DecodeOpts{})
	if skipped, err := c.Skip(); err != nil || skipped != len(src) {
		t.Fatalf("Cursor.Skip = %d, %v; want %d, nil", skipped, err, len(src))
	}

	got, err := DecodeFrom(bytes.NewReader(src), DecodeOpts{})
	if err != nil || !got.Equal(v) {
		t.Fatalf("DecodeFrom = %v, %v; want %v", got, err, v)
	}
}

// C1: valid input keeps its result. Nested self-describe tags (inside
// another item) still count as tags and toward nesting depth.
func TestC1SelfDescribeChainResults(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  []byte
		want cbor.Value
	}{
		{"one", selfDescribeChain(1, 0x01), cbor.Uint(1)},
		{"three", selfDescribeChain(3, 0x01), cbor.Uint(1)},
		{"nested kept", []byte{0x81, 0xd9, 0xd9, 0xf7, 0x01}, cbor.MakeArray(cbor.MakeTag(55799, cbor.Uint(1)))},
		{"after other tag kept", []byte{0xc1, 0xd9, 0xd9, 0xf7, 0x01}, cbor.MakeTag(1, cbor.MakeTag(55799, cbor.Uint(1)))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, _, err := Decode(tc.src, DecodeOpts{})
			if err != nil || !v.Equal(tc.want) {
				t.Fatalf("Decode = %v, %v; want %v", v, err, tc.want)
			}
		})
	}
	// A non-shortest self-describe head is still checked.
	src := append([]byte{0xda, 0x00, 0x00, 0xd9, 0xf7}, selfDescribeChain(2, 0x01)...)
	if _, _, err := Decode(src, DecodeOpts{RejectNonShortest: true}); err == nil {
		t.Fatal("non-shortest self-describe head accepted under RejectNonShortest")
	}
	// Truncated after the chain.
	if _, _, err := Decode(selfDescribeChain(4), DecodeOpts{}); err == nil {
		t.Fatal("chain with no item accepted")
	}
}
