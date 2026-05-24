// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"fmt"
	"math"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/wire"
)

// DecodeUintArray decodes a CBOR array where every element is major
// type 0 (unsigned integer) directly into a []uint64. Returns
// ErrTypeMismatch if any element is not a uint.
func DecodeUintArray(src []byte, opts DecodeOpts) ([]uint64, int, error) {
	if len(src) == 0 {
		return nil, 0, fmt.Errorf("%w at offset 0", cbor.ErrTruncated)
	}
	h := wire.ParseHead(src)
	if h.N == 0 {
		return nil, 0, fmt.Errorf("%w at offset 0", cbor.ErrTruncated)
	}
	if h.Major != wire.MajorArray {
		return nil, 0, fmt.Errorf("%w at offset 0: expected array", ErrTypeMismatch)
	}
	if h.AI == wire.AIIndefinite {
		return nil, 0, fmt.Errorf("%w at offset 0: indefinite arrays not supported", ErrTypeMismatch)
	}
	count := int(h.Arg)
	if count > opts.maxArray() {
		return nil, 0, fmt.Errorf("%w at offset 0", cbor.ErrMaxArrayLength)
	}
	result := make([]uint64, count)
	pos := h.N
	for i := range count {
		if pos >= len(src) {
			return nil, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		eh := wire.ParseHead(src[pos:])
		if eh.N == 0 {
			return nil, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		if eh.Major != wire.MajorUint {
			return nil, pos, fmt.Errorf("%w at offset %d: element %d is not uint (major %d)",
				ErrTypeMismatch, pos, i, eh.Major>>5)
		}
		result[i] = eh.Arg
		pos += eh.N
	}
	return result, pos, nil
}

// DecodeFloat64Array decodes a CBOR array of floats (float16, float32,
// or float64) directly into a []float64 with promotion.
func DecodeFloat64Array(src []byte, opts DecodeOpts) ([]float64, int, error) {
	if len(src) == 0 {
		return nil, 0, fmt.Errorf("%w at offset 0", cbor.ErrTruncated)
	}
	h := wire.ParseHead(src)
	if h.N == 0 {
		return nil, 0, fmt.Errorf("%w at offset 0", cbor.ErrTruncated)
	}
	if h.Major != wire.MajorArray {
		return nil, 0, fmt.Errorf("%w at offset 0: expected array", ErrTypeMismatch)
	}
	if h.AI == wire.AIIndefinite {
		return nil, 0, fmt.Errorf("%w at offset 0: indefinite arrays not supported", ErrTypeMismatch)
	}
	count := int(h.Arg)
	if count > opts.maxArray() {
		return nil, 0, fmt.Errorf("%w at offset 0", cbor.ErrMaxArrayLength)
	}
	result := make([]float64, count)
	pos := h.N
	for i := range count {
		if pos >= len(src) {
			return nil, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		eh := wire.ParseHead(src[pos:])
		if eh.N == 0 {
			return nil, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		if eh.Major != wire.MajorOther {
			return nil, pos, fmt.Errorf("%w at offset %d: element %d is not float",
				ErrTypeMismatch, pos, i)
		}
		switch eh.AI {
		case wire.AI2Bytes:
			result[i] = wire.DecodeFloat16(uint16(eh.Arg))
		case wire.AI4Bytes:
			result[i] = float64(math.Float32frombits(uint32(eh.Arg)))
		case wire.AI8Bytes:
			result[i] = math.Float64frombits(eh.Arg)
		default:
			return nil, pos, fmt.Errorf("%w at offset %d: element %d is not float",
				ErrTypeMismatch, pos, i)
		}
		pos += eh.N
	}
	return result, pos, nil
}

// DecodeBytesArray decodes a CBOR array of byte strings into a [][]byte.
func DecodeBytesArray(src []byte, opts DecodeOpts) ([][]byte, int, error) {
	if len(src) == 0 {
		return nil, 0, fmt.Errorf("%w at offset 0", cbor.ErrTruncated)
	}
	h := wire.ParseHead(src)
	if h.N == 0 {
		return nil, 0, fmt.Errorf("%w at offset 0", cbor.ErrTruncated)
	}
	if h.Major != wire.MajorArray {
		return nil, 0, fmt.Errorf("%w at offset 0: expected array", ErrTypeMismatch)
	}
	if h.AI == wire.AIIndefinite {
		return nil, 0, fmt.Errorf("%w at offset 0: indefinite arrays not supported", ErrTypeMismatch)
	}
	count := int(h.Arg)
	if count > opts.maxArray() {
		return nil, 0, fmt.Errorf("%w at offset 0", cbor.ErrMaxArrayLength)
	}
	result := make([][]byte, count)
	pos := h.N
	for i := range count {
		if pos >= len(src) {
			return nil, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		eh := wire.ParseHead(src[pos:])
		if eh.N == 0 {
			return nil, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		if eh.Major != wire.MajorBytes || eh.AI == wire.AIIndefinite {
			return nil, pos, fmt.Errorf("%w at offset %d: element %d is not bytes",
				ErrTypeMismatch, pos, i)
		}
		length := int(eh.Arg)
		start := pos + eh.N
		end := start + length
		if end > len(src) {
			return nil, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		result[i] = make([]byte, length)
		copy(result[i], src[start:end])
		pos = end
	}
	return result, pos, nil
}

// DecodeTextArray decodes a CBOR array of text strings into a []string.
func DecodeTextArray(src []byte, opts DecodeOpts) ([]string, int, error) {
	if len(src) == 0 {
		return nil, 0, fmt.Errorf("%w at offset 0", cbor.ErrTruncated)
	}
	h := wire.ParseHead(src)
	if h.N == 0 {
		return nil, 0, fmt.Errorf("%w at offset 0", cbor.ErrTruncated)
	}
	if h.Major != wire.MajorArray {
		return nil, 0, fmt.Errorf("%w at offset 0: expected array", ErrTypeMismatch)
	}
	if h.AI == wire.AIIndefinite {
		return nil, 0, fmt.Errorf("%w at offset 0: indefinite arrays not supported", ErrTypeMismatch)
	}
	count := int(h.Arg)
	if count > opts.maxArray() {
		return nil, 0, fmt.Errorf("%w at offset 0", cbor.ErrMaxArrayLength)
	}
	result := make([]string, count)
	pos := h.N
	for i := range count {
		if pos >= len(src) {
			return nil, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		eh := wire.ParseHead(src[pos:])
		if eh.N == 0 {
			return nil, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		if eh.Major != wire.MajorText || eh.AI == wire.AIIndefinite {
			return nil, pos, fmt.Errorf("%w at offset %d: element %d is not text",
				ErrTypeMismatch, pos, i)
		}
		length := int(eh.Arg)
		start := pos + eh.N
		end := start + length
		if end > len(src) {
			return nil, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		result[i] = string(src[start:end])
		pos = end
	}
	return result, pos, nil
}
