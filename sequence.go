// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"unsafe"

	"github.com/jahkeup/corecbor/rfc8949"
)

// valueSize is the memory budget charge for one sequence item's slot.
const valueSize = int(unsafe.Sizeof(Value{}))

// MediaTypeCBORSeq is the IANA media type for CBOR sequences (RFC 8742).
const MediaTypeCBORSeq = "application/cbor-seq"

// Sequence is a CBOR sequence: a concatenation of zero or more CBOR data items.
// It is NOT wrapped in an outer array; each item is encoded independently.
// See RFC 8742.
type Sequence []Value

// MarshalCBOR encodes the sequence as concatenated CBOR items (no outer array).
func (s Sequence) MarshalCBOR() ([]byte, error) {
	return defaultEncoder.EncodeSequence(nil, s...)
}

// UnmarshalCBOR decodes all CBOR items from data into the sequence.
func (s *Sequence) UnmarshalCBOR(data []byte) error {
	seq, err := defaultDecoder.DecodeSequence(data)
	if err != nil {
		return err
	}
	*s = seq
	return nil
}

// EncodeSequence encodes each Value and concatenates the results (no outer array).
// It is equivalent to calling Encode for each item and appending the results.
func EncodeSequence(dst []byte, items ...Value) ([]byte, error) {
	return defaultEncoder.EncodeSequence(dst, items...)
}

// DecodeSequence decodes items one-by-one from src until exhausted.
// Unlike Decode, trailing bytes are not an error — they are the next item.
func DecodeSequence(src []byte) (Sequence, error) {
	return defaultDecoder.DecodeSequence(src)
}

// MarshalSequence reflection-marshals each item and concatenates the CBOR bytes.
func MarshalSequence(items ...any) ([]byte, error) {
	return defaultEncoder.MarshalSequence(items...)
}

// EncodeSequence encodes each Value and concatenates the results (no outer array).
func (e *Encoder) EncodeSequence(dst []byte, items ...Value) ([]byte, error) {
	var err error
	for _, item := range items {
		dst, err = e.Encode(dst, item)
		if err != nil {
			return dst, err
		}
	}
	return dst, nil
}

// DecodeSequence decodes items one-by-one from src until exhausted.
func (d *Decoder) DecodeSequence(src []byte) (Sequence, error) {
	// The memory budget covers one call, as it does for Decode.
	d.resetBudget()
	var seq Sequence
	// Error offsets are offsets in src, not in the failing item.
	for off := 0; off < len(src); {
		v, next, err := rfc8949.DecodeAt(src, off, d.cfg.opts)
		if err != nil {
			return nil, err
		}
		// The sequence's own slot for the item.
		if err := d.cfg.opts.Budget.Charge(valueSize, off); err != nil {
			return nil, err
		}
		seq = append(seq, v)
		off = next
	}
	return seq, nil
}

// MarshalSequence reflection-marshals each item and concatenates the CBOR bytes.
func (e *Encoder) MarshalSequence(items ...any) ([]byte, error) {
	var dst []byte
	for _, item := range items {
		b, err := e.Marshal(item)
		if err != nil {
			return nil, err
		}
		dst = append(dst, b...)
	}
	return dst, nil
}
