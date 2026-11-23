// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"errors"
	"math"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// TestSkipLimitOrderMatchesDecode: a definite-length container that is
// both too long and too deep reports the length limit from Skip, as it
// does from Decode and the stream reader.
func TestSkipLimitOrderMatchesDecode(t *testing.T) {
	opts := DecodeOpts{MaxNestingDepth: 1, MaxArrayLength: 4}
	for name, src := range map[string][]byte{
		"array": {0x81, 0x85, 0, 0, 0, 0, 0}, // [[5 items]] at depth 2
		"map":   {0x81, 0xa5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, decErr := Decode(src, opts)
			_, skipErr := NewCursor(src, opts).Skip()
			if !errors.Is(decErr, cbor.ErrMaxArrayLength) {
				t.Fatalf("Decode err = %v, want ErrMaxArrayLength", decErr)
			}
			if !errors.Is(skipErr, cbor.ErrMaxArrayLength) {
				t.Fatalf("Skip err = %v, want ErrMaxArrayLength", skipErr)
			}
		})
	}
}

// TestFindMapKeyHugeTextLength: a text key whose length doesn't fit an
// int used to wrap negative and panic slicing the source.
func TestFindMapKeyHugeTextLength(t *testing.T) {
	for _, h := range []string{
		"a17b800000000000000001",
		"a17bffffffffffffffff01",
		"a17bfffffffffffffff001",
	} {
		c := NewCursor(mustHex(h), DecodeOpts{})
		if _, err := c.EnterMap(); err != nil {
			t.Fatalf("%s: EnterMap: %v", h, err)
		}
		if err := c.FindMapKey("a"); err == nil || errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("%s: FindMapKey err = %v, want a decode error", h, err)
		}
	}
}

// TestEnterChecksHead: EnterArray and EnterMap apply Decode's structural
// rules and limits to the container head, and don't move on error.
func TestEnterChecksHead(t *testing.T) {
	for _, tc := range []struct {
		name  string
		src   string
		opts  DecodeOpts
		isMap bool
		want  error
	}{
		{"reserved AI", "9c", DecodeOpts{}, false, cbor.ErrReservedAI},
		{"reserved AI map", "bd", DecodeOpts{}, true, cbor.ErrReservedAI},
		{"indefinite rejected", "9fff", DecodeOpts{RejectIndefiniteLength: true}, false, cbor.ErrIndefiniteLength},
		{"non-shortest", "980100", DecodeOpts{RejectNonShortest: true}, false, cbor.ErrNonShortest},
		{"too long", "83010203", DecodeOpts{MaxArrayLength: 2}, false, cbor.ErrMaxArrayLength},
		{"count wraps int", "9b8000000000000000", DecodeOpts{}, false, cbor.ErrMaxArrayLength},
		{"map count doubling", "bb7fffffffffffffff", DecodeOpts{MaxArrayLength: math.MaxInt}, true, cbor.ErrTruncated},
		{"count exceeds input", "8301", DecodeOpts{}, false, cbor.ErrTruncated},
		{"map count exceeds input", "a20102", DecodeOpts{}, true, cbor.ErrTruncated},
		{"too deep", "8100", DecodeOpts{MaxNestingDepth: 0}, false, nil}, // control: default depth allows it
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCursor(mustHex(tc.src), tc.opts)
			var err error
			if tc.isMap {
				_, err = c.EnterMap()
			} else {
				_, err = c.EnterArray()
			}
			if tc.want == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if c.Offset() != 0 || c.depth() != 0 {
				t.Fatalf("cursor moved on error: offset %d depth %d", c.Offset(), c.depth())
			}
		})
	}
}

// TestCursorDepthLimit: entering containers and decoding inside them
// count against MaxNestingDepth together, as Decode counts them.
func TestCursorDepthLimit(t *testing.T) {
	src := mustHex("81818100") // [[[0]]], depth 3
	opts := DecodeOpts{MaxNestingDepth: 2}
	if _, _, err := Decode(src, opts); !errors.Is(err, cbor.ErrMaxNestingDepth) {
		t.Fatalf("Decode err = %v, want ErrMaxNestingDepth", err)
	}

	c := NewCursor(src, opts)
	if _, err := c.EnterArray(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.EnterArray(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.EnterArray(); !errors.Is(err, cbor.ErrMaxNestingDepth) {
		t.Fatalf("third EnterArray err = %v, want ErrMaxNestingDepth", err)
	}

	c = NewCursor(src, opts)
	if _, err := c.EnterArray(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decode(); !errors.Is(err, cbor.ErrMaxNestingDepth) {
		t.Fatalf("Decode at depth 1 err = %v, want ErrMaxNestingDepth", err)
	}

	// Within the limit both still work.
	c = NewCursor(mustHex("818100"), opts)
	if _, err := c.EnterArray(); err != nil {
		t.Fatal(err)
	}
	if v, err := c.Decode(); err != nil || v.Kind != cbor.KindArray {
		t.Fatalf("Decode = %v, %v", v, err)
	}
}
