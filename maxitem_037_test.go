// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// 037 C4: reader-based decoding is bounded by MaxItemSize even without
// a memory budget: 64 MiB by default, configurable, removable.
func TestC4MaxItemSize(t *testing.T) {
	// An endless indefinite array of 8 MiB byte strings: each under the
	// string and array limits, so only the item size bounds it.
	elem := []byte{0x5a, 0x00, 0x80, 0x00, 0x00}
	r := &chunkedArray{elem: elem, size: 8 << 20}
	_, err := NewDecoder().DecodeFrom(r)
	if !errors.Is(err, ErrMaxItemSize) {
		t.Fatalf("default: err = %v, want ErrMaxItemSize", err)
	}
	if r.n > DefaultMaxItemSize+(1<<20) {
		t.Fatalf("default: read %d bytes", r.n)
	}

	// A declared length past the limit fails at its head, unread.
	small := NewDecoder(WithMaxItemSize(1 << 10))
	src := append([]byte{0x59, 0x08, 0x00}, bytes.Repeat([]byte{1}, 2048)...)
	br := bytes.NewReader(src)
	if _, err := small.DecodeFrom(br); !errors.Is(err, ErrMaxItemSize) {
		t.Fatalf("1 KiB limit: err = %v", err)
	}
	if read := len(src) - br.Len(); read > 16 {
		t.Fatalf("read %d bytes of an item over the limit", read)
	}
	s := small.Stream(bytes.NewReader(src))
	if s.Next() || !errors.Is(s.Err(), ErrMaxItemSize) {
		t.Fatalf("Stream: %v", s.Err())
	}
	ok := append([]byte{0x59, 0x03, 0x00}, bytes.Repeat([]byte{1}, 0x300)...)
	if _, err := small.DecodeFrom(bytes.NewReader(ok)); err != nil {
		t.Fatalf("768-byte item under a 1 KiB limit: %v", err)
	}
	// Removed with a negative limit.
	big := append([]byte{0x5a, 0x04, 0x10, 0x00, 0x00}, make([]byte, 0x04100000)...)
	if _, err := NewDecoder(WithMaxByteStringLength(1 << 30)).DecodeFrom(bytes.NewReader(big)); !errors.Is(err, ErrMaxItemSize) {
		t.Fatalf("65 MiB item under the default: %v", err)
	}
	if _, err := NewDecoder(WithMaxByteStringLength(1<<30), WithMaxItemSize(-1)).DecodeFrom(bytes.NewReader(big)); err != nil {
		t.Fatalf("no limit: %v", err)
	}
	// Decode from a byte slice is not affected.
	if _, err := NewDecoder(WithMaxByteStringLength(1<<30), WithMaxItemSize(1<<10)).Decode(big); err != nil {
		t.Fatalf("Decode: %v", err)
	}
}

// chunkedArray yields an endless indefinite-length array of byte
// strings of size bytes, each preceded by elem (its head).
type chunkedArray struct {
	elem []byte
	size int
	n    int
}

func (c *chunkedArray) Read(p []byte) (int, error) {
	for i := range p {
		if c.n == 0 {
			p[i] = 0x9f
		} else {
			k := (c.n - 1) % (len(c.elem) + c.size)
			if k < len(c.elem) {
				p[i] = c.elem[k]
			} else {
				p[i] = 0xaa
			}
		}
		c.n++
	}
	return len(p), nil
}

var _ io.Reader = (*chunkedArray)(nil)
