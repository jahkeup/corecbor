// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"fmt"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cbor"
)

// seqEnc encodes protocol items deterministically (RFC 8949 §4.2.1).
var seqEnc = corecbor.NewShared(corecbor.ModeCoreDeterministic)

// item encodes v; protocol items are well-formed by construction.
func item(v cbor.Value) []byte {
	b, err := seqEnc.Encode(nil, v)
	if err != nil {
		// Only invalid Values fail to encode, and every caller builds
		// its Value from typed fields.
		panic(fmt.Sprintf("edhoc: encoding protocol item: %v", err))
	}
	return b
}

func intItem(n int64) []byte {
	if n >= 0 {
		return item(cbor.Uint(uint64(n)))
	}
	return item(cbor.NegInt(uint64(-1 - n)))
}

func uintItem(n uint64) []byte { return item(cbor.Uint(n)) }

func bstrItem(b []byte) []byte {
	if b == nil {
		b = []byte{}
	}
	return item(cbor.Bytes(b))
}

// encSeq concatenates encoded items into a CBOR sequence.
func encSeq(items ...[]byte) []byte {
	n := 0
	for _, it := range items {
		n += len(it)
	}
	out := make([]byte, 0, n)
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

// seqDec decodes protocol messages. Values must outlive the call, so
// the internal arena is disabled.
var seqDecOpts = []corecbor.DecoderOption{
	corecbor.WithoutInternalArena(),
	corecbor.RejectIndefiniteLength(),
	corecbor.WithMaxNestingDepth(16),
}

// seqReader walks a CBOR sequence item by item, keeping each item's
// raw bytes.
type seqReader struct {
	dec  *corecbor.Decoder
	rest []byte
}

func newSeqReader(data []byte) *seqReader {
	return &seqReader{dec: corecbor.NewDecoder(seqDecOpts...), rest: data}
}

func (r *seqReader) more() bool { return len(r.rest) > 0 }

// next decodes the next item and returns it with its encoded bytes.
func (r *seqReader) next() (cbor.Value, []byte, error) {
	if len(r.rest) == 0 {
		return cbor.Value{}, nil, fmt.Errorf("%w: sequence ended early", ErrMessageFormat)
	}
	before := r.rest
	v, rest, err := r.dec.DecodePrefix(r.rest)
	if err != nil {
		return cbor.Value{}, nil, fmt.Errorf("%w: %w", ErrMessageFormat, err)
	}
	r.rest = rest
	return v, before[:len(before)-len(rest)], nil
}

func (r *seqReader) nextBytes(what string) ([]byte, error) {
	v, _, err := r.next()
	if err != nil {
		return nil, err
	}
	if v.Kind != cbor.KindBytes {
		return nil, fmt.Errorf("%w: %s must be a byte string", ErrMessageFormat, what)
	}
	return v.Bstr, nil
}

func (r *seqReader) nextInt(what string) (int64, error) {
	v, _, err := r.next()
	if err != nil {
		return 0, err
	}
	return valueInt(v, what)
}

func valueInt(v cbor.Value, what string) (int64, error) {
	switch v.Kind {
	case cbor.KindUint:
		if v.Num > 1<<62 {
			return 0, fmt.Errorf("%w: %s out of range", ErrMessageFormat, what)
		}
		return int64(v.Num), nil
	case cbor.KindNegInt:
		if v.Num > 1<<62 {
			return 0, fmt.Errorf("%w: %s out of range", ErrMessageFormat, what)
		}
		return -1 - int64(v.Num), nil
	}
	return 0, fmt.Errorf("%w: %s must be an integer", ErrMessageFormat, what)
}
