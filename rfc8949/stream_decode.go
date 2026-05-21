// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"io"

	"github.com/jahkeup/corecbor/cbor"
)

// DecodeFrom reads exactly one CBOR value from r. It buffers enough bytes
// to complete one data item, then decodes it.
func DecodeFrom(r io.Reader, opts DecodeOpts) (cbor.Value, error) {
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		v, consumed, decErr := Decode(buf, opts)
		if decErr == nil {
			if consumed < len(buf) {
				_ = consumed
			}
			return v, nil
		}
		if err != nil {
			if len(buf) == 0 {
				return nil, err
			}
			return nil, decErr
		}
	}
}

// BufferedReader wraps an io.Reader with a leftover buffer for the Stream.
type BufferedReader struct {
	r        io.Reader
	leftover []byte
}

func (br *BufferedReader) Read(p []byte) (int, error) {
	if len(br.leftover) > 0 {
		n := copy(p, br.leftover)
		br.leftover = br.leftover[n:]
		return n, nil
	}
	return br.r.Read(p)
}

// DecodeFromBuffered reads one CBOR value from br, preserving leftover bytes
// for subsequent reads.
func DecodeFromBuffered(br *BufferedReader, opts DecodeOpts) (cbor.Value, error) {
	buf := make([]byte, 0, 256)
	if len(br.leftover) > 0 {
		buf = append(buf, br.leftover...)
		br.leftover = nil
	}
	tmp := make([]byte, 256)
	for {
		v, consumed, decErr := Decode(buf, opts)
		if decErr == nil {
			if consumed < len(buf) {
				br.leftover = append(br.leftover, buf[consumed:]...)
			}
			return v, nil
		}
		n, err := br.r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			continue
		}
		if err != nil {
			if len(buf) == 0 {
				return nil, err
			}
			return nil, decErr
		}
	}
}

// NewBufferedReader wraps an io.Reader for use with DecodeFromBuffered.
func NewBufferedReader(r io.Reader) *BufferedReader {
	return &BufferedReader{r: r}
}
