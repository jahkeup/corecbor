// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"errors"
	"runtime"
	"testing"

	"github.com/jahkeup/corecbor/rfc8949"
)

// decodeAllocBytes reports the bytes allocated by one Decode of src
// through a decoder with no internal arena (so earlier calls can't
// pre-grow storage and hide the cost).
func decodeAllocBytes(t *testing.T, src []byte) (uint64, error) {
	t.Helper()
	dec := NewDecoder(WithoutInternalArena())
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := dec.Decode(src)
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc, err
}

// TestDecodeAllocationBoundedByInput guards against declared-length
// amplification: a container's head may claim far more items than the
// input holds, and nested heads must not multiply that claim. Found by
// FuzzDecodeNeverPanics (testdata/fuzz/FuzzDecodeNeverPanics/72fd2e5633027730),
// which allocated ~3.8 GB from 3.8 KB of input.
func TestDecodeAllocationBoundedByInput(t *testing.T) {
	const depth = 200
	cases := map[string][]byte{
		// Indefinite array, five items, then nested 2-byte-length maps
		// each claiming 0xb9b9 pairs (the fuzz finding's shape).
		"nested-map-heads": append(
			[]byte{0x9f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f},
			bytes.Repeat([]byte{0xb9, 0xb9, 0xb9}, depth)...,
		),
		// Nested arrays, each claiming 0xffff elements.
		"nested-array-heads": bytes.Repeat([]byte{0x99, 0xff, 0xff}, depth),
		// Nested arrays whose claims are each individually satisfiable
		// by the remaining input, but not all at once.
		"nested-array-overlapping-claims": func() []byte {
			var b []byte
			for i := range depth {
				claim := uint16(3*(depth-i) + 64)
				b = append(b, 0x99, byte(claim>>8), byte(claim))
			}
			return append(b, bytes.Repeat([]byte{0x00}, 64)...)
		}(),
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := decodeAllocBytes(t, src)
			if !errors.Is(err, ErrTruncated) && !errors.Is(err, ErrMaxNestingDepth) {
				t.Fatalf("err = %v, want ErrTruncated or ErrMaxNestingDepth", err)
			}
			// A decoded Value is 104 bytes, so allow ~256 bytes of
			// allocation per input byte plus fixed overhead.
			limit := uint64(len(src))*256 + 64<<10
			if got > limit {
				t.Fatalf("allocated %d bytes for %d input bytes (limit %d)", got, len(src), limit)
			}
		})
	}
}

// TestHomogeneousArrayHugeCount checks that a length near 2^64 is
// rejected instead of wrapping negative and panicking in make.
func TestHomogeneousArrayHugeCount(t *testing.T) {
	src := []byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	opts := rfc8949.DecodeOpts{MaxArrayLength: 1 << 62}
	if _, _, err := rfc8949.DecodeUintArray(src, opts); err == nil {
		t.Fatal("DecodeUintArray: want error")
	}
	if _, _, err := rfc8949.DecodeFloat64Array(src, opts); err == nil {
		t.Fatal("DecodeFloat64Array: want error")
	}
	if _, _, err := rfc8949.DecodeBytesArray(src, opts); err == nil {
		t.Fatal("DecodeBytesArray: want error")
	}
	if _, _, err := rfc8949.DecodeTextArray(src, opts); err == nil {
		t.Fatal("DecodeTextArray: want error")
	}
}
