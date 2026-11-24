// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// homogeneous runs each of the four homogeneous array decoders on src.
func homogeneous(src []byte, opts DecodeOpts) map[string]error {
	_, _, eu := DecodeUintArray(src, opts)
	_, _, ef := DecodeFloat64Array(src, opts)
	_, _, eb := DecodeBytesArray(src, opts)
	_, _, et := DecodeTextArray(src, opts)
	return map[string]error{"uint": eu, "float": ef, "bytes": eb, "text": et}
}

// C3: a string element whose length doesn't fit the input (or an int)
// is an error, not a panic.
func TestC3HomogeneousHugeLengthNoPanic(t *testing.T) {
	for _, tc := range []struct {
		fn  string
		src []byte
	}{
		{"bytes", []byte{0x81, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"bytes", []byte{0x81, 0x5b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"text", []byte{0x81, 0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"text", []byte{0x81, 0x7b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	} {
		for name, err := range homogeneous(tc.src, DecodeOpts{}) {
			if err == nil {
				t.Errorf("%s(%x): accepted", name, tc.src)
			}
		}
		if err := homogeneous(tc.src, DecodeOpts{})[tc.fn]; !errors.Is(err, cbor.ErrMaxByteStringLength) {
			t.Errorf("%s(%x): err = %v, want ErrMaxByteStringLength", tc.fn, tc.src, err)
		}
	}
	// Within MaxByteStringLength but past the input: truncated.
	src := []byte{0x81, 0x5a, 0x00, 0x00, 0x10, 0x00, 0x00}
	if _, _, err := DecodeBytesArray(src, DecodeOpts{}); !errors.Is(err, cbor.ErrTruncated) {
		t.Errorf("bytes past input: err = %v, want ErrTruncated", err)
	}
}

// C3: reserved additional information (28–31) is rejected as Decode
// rejects it, in the array head and in elements.
func TestC3HomogeneousReservedAI(t *testing.T) {
	for _, src := range [][]byte{
		{0x9c},
		{0x9d},
		{0x9e},
		{0x81, 0x1c},
		{0x81, 0x1d},
		{0x81, 0x1e},
		{0x81, 0x1f},
		{0x81, 0xfc},
		{0x81, 0x5c},
		{0x81, 0x7d},
	} {
		if _, _, err := Decode(src, DecodeOpts{}); !errors.Is(err, cbor.ErrReservedAI) {
			t.Fatalf("Decode(%x) = %v; test input should be reserved AI", src, err)
		}
		for name, err := range homogeneous(src, DecodeOpts{}) {
			if !errors.Is(err, cbor.ErrReservedAI) {
				t.Errorf("%s(%x): err = %v, want ErrReservedAI", name, src, err)
			}
		}
	}
}

// C3: the decoders apply the options Decode applies.
func TestC3HomogeneousOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   string
		src  []byte
		opts DecodeOpts
		want error
	}{
		{"non-shortest head", "uint", []byte{0x98, 0x01, 0x01}, DecodeOpts{RejectNonShortest: true}, cbor.ErrNonShortest},
		{"non-shortest uint", "uint", []byte{0x81, 0x18, 0x01}, DecodeOpts{RejectNonShortest: true}, cbor.ErrNonShortest},
		{"non-shortest bytes", "bytes", []byte{0x81, 0x58, 0x01, 0x00}, DecodeOpts{RejectNonShortest: true}, cbor.ErrNonShortest},
		{"non-shortest text", "text", []byte{0x81, 0x78, 0x01, 0x61}, DecodeOpts{RejectNonShortest: true}, cbor.ErrNonShortest},
		{"indefinite rejected", "uint", []byte{0x9f, 0x01, 0xff}, DecodeOpts{RejectIndefiniteLength: true}, cbor.ErrIndefiniteLength},
		{"indefinite chunked bytes", "bytes", []byte{0x81, 0x5f, 0x41, 0x00, 0xff}, DecodeOpts{RejectIndefiniteLength: true}, cbor.ErrIndefiniteLength},
		{"bytes limit", "bytes", []byte{0x81, 0x43, 1, 2, 3}, DecodeOpts{MaxByteStringLength: 2}, cbor.ErrMaxByteStringLength},
		{"text limit", "text", []byte{0x81, 0x63, 'a', 'b', 'c'}, DecodeOpts{MaxByteStringLength: 2}, cbor.ErrMaxByteStringLength},
		{"array limit", "float", []byte{0x82, 0xf9, 0, 0, 0xf9, 0, 0}, DecodeOpts{MaxArrayLength: 1}, cbor.ErrMaxArrayLength},
		{"non-finite", "float", []byte{0x81, 0xf9, 0x7e, 0x00}, DecodeOpts{RejectNonFiniteFloats: true}, cbor.ErrNonFiniteFloat},
		{"budget", "bytes", []byte{0x81, 0x44, 1, 2, 3, 4}, DecodeOpts{Budget: NewBudget(8)}, cbor.ErrMemoryBudgetExceeded},
		{"preferred float", "float", []byte{0x81, 0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0}, DecodeOpts{RequirePreferred: true}, cbor.ErrNotPreferred},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := homogeneous(tc.src, tc.opts)[tc.fn]; !errors.Is(err, tc.want) {
				t.Fatalf("%s(%x) err = %v, want %v", tc.fn, tc.src, err, tc.want)
			}
			// Decode agrees.
			if tc.opts.Budget != nil {
				tc.opts.Budget = NewBudget(tc.opts.Budget.Limit)
			}
			if _, _, err := Decode(tc.src, tc.opts); !errors.Is(err, tc.want) {
				t.Fatalf("Decode(%x) err = %v, want %v", tc.src, err, tc.want)
			}
		})
	}
}

// C3: valid input keeps its result.
func TestC3HomogeneousValid(t *testing.T) {
	u, n, err := DecodeUintArray([]byte{0x83, 0x01, 0x18, 0x18, 0x19, 0x01, 0x00}, StrictOpts())
	if err != nil || n != 7 || len(u) != 3 || u[0] != 1 || u[1] != 24 || u[2] != 256 {
		t.Fatalf("uint = %v, %d, %v", u, n, err)
	}
	b, _, err := DecodeBytesArray([]byte{0x82, 0x41, 0x07, 0x40}, StrictOpts())
	if err != nil || len(b) != 2 || b[0][0] != 7 || len(b[1]) != 0 {
		t.Fatalf("bytes = %v, %v", b, err)
	}
	s, _, err := DecodeTextArray([]byte{0x82, 0x61, 'a', 0x60}, StrictOpts())
	if err != nil || len(s) != 2 || s[0] != "a" || s[1] != "" {
		t.Fatalf("text = %v, %v", s, err)
	}
	f, _, err := DecodeFloat64Array([]byte{0x82, 0xf9, 0x3c, 0x00, 0xfa, 0x3f, 0xc0, 0, 0}, StrictOpts())
	if err != nil || len(f) != 2 || f[0] != 1 || f[1] != 1.5 {
		t.Fatalf("float = %v, %v", f, err)
	}
}
