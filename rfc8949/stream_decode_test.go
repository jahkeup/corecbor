// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"runtime"
	"testing"
	"testing/iotest"

	"github.com/jahkeup/corecbor/cbor"
)

// repeatReader yields b forever.
type repeatReader struct{ b byte }

func (r repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

// 021 D10: limits apply while reading, so an endless or oversized item
// fails at its head instead of being buffered.
func TestDecodeFromLimitsWhileReading(t *testing.T) {
	// Endless nesting: 0x81 repeated.
	if _, err := DecodeFrom(repeatReader{0x81}, DecodeOpts{}); !errors.Is(err, cbor.ErrMaxNestingDepth) {
		t.Fatalf("endless nesting: err = %v, want ErrMaxNestingDepth", err)
	}
	// Endless indefinite array of zeros.
	r := io.MultiReader(bytes.NewReader([]byte{0x9f}), repeatReader{0x00})
	if _, err := DecodeFrom(r, DecodeOpts{MaxArrayLength: 1000}); !errors.Is(err, cbor.ErrMaxArrayLength) {
		t.Fatalf("endless indefinite array: err = %v, want ErrMaxArrayLength", err)
	}
	// Byte string longer than the limit.
	if _, err := DecodeFrom(bytes.NewReader([]byte{0x5a, 0x01, 0, 0, 0}), DecodeOpts{MaxByteStringLength: 1 << 20}); !errors.Is(err, cbor.ErrMaxByteStringLength) {
		t.Fatalf("oversized string: err = %v, want ErrMaxByteStringLength", err)
	}
}

// A declared length is never allocated ahead of the data that backs it.
func TestDecodeFromNoAllocationAheadOfData(t *testing.T) {
	src := []byte{0x5a, 0x40, 0, 0, 0, 0xaa} // 1 GiB string, 1 byte present
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := DecodeFrom(bytes.NewReader(src), DecodeOpts{MaxByteStringLength: 2 << 30})
	runtime.ReadMemStats(&after)
	if !errors.Is(err, cbor.ErrTruncated) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want ErrTruncated and io.ErrUnexpectedEOF", err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
		t.Fatalf("allocated %d bytes for a 6-byte input", got)
	}
}

// 021 D10: cost is linear in item size. v0.2 re-decoded the whole buffer
// after every Read, which with a one-byte reader allocated O(n²).
func TestDecodeFromLinear(t *testing.T) {
	const n = 20000
	src := []byte{0x99, n >> 8, n & 0xff}
	src = append(src, bytes.Repeat([]byte{0x01}, n)...)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	v, err := DecodeFrom(iotest.OneByteReader(bytes.NewReader(src)), DecodeOpts{})
	runtime.ReadMemStats(&after)
	if err != nil || len(v.Items) != n {
		t.Fatalf("v has %d items, err %v", len(v.Items), err)
	}
	// 104 bytes per Value plus buffer growth; quadratic re-decoding would
	// be gigabytes.
	if got := after.TotalAlloc - before.TotalAlloc; got > 16<<20 {
		t.Fatalf("allocated %d bytes for a %d-byte item", got, len(src))
	}
}

// opaqueReader hides io.ByteReader so the plain-Read path is exercised.
type opaqueReader struct{ r io.Reader }

func (o opaqueReader) Read(p []byte) (int, error) { return o.r.Read(p) }

var decodeFromSentinels = []error{
	cbor.ErrNonShortest, cbor.ErrIndefiniteLength, cbor.ErrInvalidUTF8,
	cbor.ErrDuplicateMapKey, cbor.ErrUnknownTag, cbor.ErrNonFiniteFloat,
	cbor.ErrNullMapKey, cbor.ErrTruncated, cbor.ErrMaxNestingDepth,
	cbor.ErrMaxArrayLength, cbor.ErrMaxByteStringLength, cbor.ErrReservedAI,
	cbor.ErrUnexpectedBreak, cbor.ErrMemoryBudgetExceeded,
}

func errClass(err error) error {
	for _, s := range decodeFromSentinels {
		if errors.Is(err, s) {
			return s
		}
	}
	return nil
}

// structuralEarlyStop lists errors DecodeFrom may report as soon as it
// reads the offending head, before content Decode would reject first.
var structuralEarlyStop = map[error]bool{
	cbor.ErrMaxNestingDepth:     true,
	cbor.ErrMaxArrayLength:      true,
	cbor.ErrMaxByteStringLength: true,
	cbor.ErrReservedAI:          true,
	cbor.ErrUnexpectedBreak:     true,
	cbor.ErrTruncated:           true,
}

// FuzzDecodeFromMatchesDecode checks that DecodeFrom over a reader
// returns what Decode returns for the same bytes, and consumes exactly
// the item.
func FuzzDecodeFromMatchesDecode(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		{0x00},
		{0xff},
		{0x1f},
		{0x82, 0x01, 0x02, 0x03},
		{0x9f, 0x01, 0xff},
		{0xbf, 0x61, 0x61, 0x01, 0xff},
		{0x5f, 0x41, 0x00, 0xff},
		{0xd9, 0xd9, 0xf7, 0x01},
		{0xa2, 0x01, 0x02, 0x01, 0x03},
		{0x7f, 0x61, 0xff, 0xff},
		{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, data []byte, strict bool) {
		opts := DecodeOpts{MaxNestingDepth: 64, MaxArrayLength: 1 << 12, MaxByteStringLength: 1 << 16}
		if strict {
			opts = StrictOpts()
			opts.MaxNestingDepth, opts.MaxArrayLength, opts.MaxByteStringLength = 64, 1<<12, 1<<16
		}
		want, n, wantErr := Decode(data, opts)
		for _, opaque := range []bool{false, true} {
			br := bytes.NewReader(data)
			var r io.Reader = br
			if opaque {
				r = opaqueReader{br}
			}
			got, err := DecodeFrom(r, opts)
			consumed := len(data) - br.Len()
			switch {
			case len(data) == 0:
				if !errors.Is(err, io.EOF) {
					t.Fatalf("empty input: err = %v, want io.EOF", err)
				}
			case wantErr == nil:
				if err != nil {
					t.Fatalf("Decode ok, DecodeFrom err %v (opaque=%v)", err, opaque)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("DecodeFrom = %#v, Decode = %#v", got, want)
				}
				if consumed != n {
					t.Fatalf("consumed %d bytes, item is %d", consumed, n)
				}
			default:
				if err == nil {
					t.Fatalf("Decode err %v, DecodeFrom ok (opaque=%v)", wantErr, opaque)
				}
				if gc, wc := errClass(err), errClass(wantErr); gc != wc && !structuralEarlyStop[gc] {
					t.Fatalf("DecodeFrom class %v (%v), Decode class %v (%v)", gc, err, wc, wantErr)
				}
			}
		}
	})
}
