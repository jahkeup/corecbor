// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"fmt"
	"slices"

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

// seqDecOpts decode CBOR this party supplied or already checked
// (credentials, COSE keys). Values must outlive the call, so the
// internal arena is disabled.
var seqDecOpts = []corecbor.DecoderOption{
	corecbor.WithoutInternalArena(),
	corecbor.RejectIndefiniteLength(),
	corecbor.RejectDuplicateMapKeys(),
	corecbor.WithMaxNestingDepth(16),
}

// Received messages must be deterministically encoded (RFC 9528 §9:
// RECOMMENDED to abort otherwise), except that the labels of an
// ID_CRED map need not be sorted (§3.5.3), and a credential it carries
// by value is the sender's own encoding (§3.5.2): ID_CRED items are
// checked for preferred serialization only.
var (
	strictDecOpts = slices.Concat(seqDecOpts, []corecbor.DecoderOption{corecbor.RequireDeterministic()})
	idCredDecOpts = slices.Concat(seqDecOpts, []corecbor.DecoderOption{corecbor.RejectNonShortest()})
)

// seqReader walks a CBOR sequence item by item, keeping each item's
// raw bytes. idDec decodes ID_CRED items.
type seqReader struct {
	dec, idDec *corecbor.Decoder
	rest       []byte
}

// newSeqReader reads CBOR this package built or already checked.
func newSeqReader(data []byte) *seqReader {
	d := corecbor.NewDecoder(seqDecOpts...)
	return &seqReader{dec: d, idDec: d, rest: data}
}

// newMessageReader reads a received message: deterministic encoding
// required unless lenient.
func newMessageReader(data []byte, lenient bool) *seqReader {
	if lenient {
		return newSeqReader(data)
	}
	return &seqReader{dec: corecbor.NewDecoder(strictDecOpts...), idDec: corecbor.NewDecoder(idCredDecOpts...), rest: data}
}

// nextIDCred decodes an ID_CRED item: a header map, or a compact kid.
func (r *seqReader) nextIDCred() (cbor.Value, []byte, error) {
	d := r.dec
	r.dec = r.idDec
	defer func() { r.dec = d }()
	return r.next()
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
