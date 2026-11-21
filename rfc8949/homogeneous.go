// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"math"
	"unicode/utf8"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/wire"
)

// DecodeUintArray decodes a CBOR array where every element is major
// type 0 (unsigned integer) directly into a []uint64. Returns
// ErrTypeMismatch if any element is not a uint.
func DecodeUintArray(src []byte, opts DecodeOpts) ([]uint64, int, error) {
	if len(src) == 0 {
		return nil, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	h := wire.ParseHead(src)
	if h.N == 0 {
		return nil, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	if h.Major != wire.MajorArray {
		return nil, 0, decodeErrDetail(ErrTypeMismatch, 0, ": expected array")
	}
	if h.AI == wire.AIIndefinite {
		return nil, 0, decodeErrDetail(ErrTypeMismatch, 0, ": indefinite arrays not supported")
	}
	if h.Arg > uint64(opts.maxArray()) {
		return nil, 0, decodeErr(cbor.ErrMaxArrayLength, 0)
	}
	// Every element occupies at least one byte; fail before allocating.
	if h.Arg > uint64(len(src)-h.N) {
		return nil, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	count := int(h.Arg)
	result := make([]uint64, count)
	pos := h.N
	for i := range count {
		if pos >= len(src) {
			return nil, pos, decodeErr(cbor.ErrTruncated, pos)
		}
		eh := wire.ParseHead(src[pos:])
		if eh.N == 0 {
			return nil, pos, decodeErr(cbor.ErrTruncated, pos)
		}
		if eh.Major != wire.MajorUint {
			return nil, pos, decodeErrf(ErrTypeMismatch, pos, ": element %d is not uint (major %d)", i, eh.Major>>5)
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
		return nil, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	h := wire.ParseHead(src)
	if h.N == 0 {
		return nil, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	if h.Major != wire.MajorArray {
		return nil, 0, decodeErrDetail(ErrTypeMismatch, 0, ": expected array")
	}
	if h.AI == wire.AIIndefinite {
		return nil, 0, decodeErrDetail(ErrTypeMismatch, 0, ": indefinite arrays not supported")
	}
	if h.Arg > uint64(opts.maxArray()) {
		return nil, 0, decodeErr(cbor.ErrMaxArrayLength, 0)
	}
	// Every element occupies at least one byte; fail before allocating.
	if h.Arg > uint64(len(src)-h.N) {
		return nil, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	count := int(h.Arg)
	result := make([]float64, count)
	pos := h.N
	for i := range count {
		if pos >= len(src) {
			return nil, pos, decodeErr(cbor.ErrTruncated, pos)
		}
		eh := wire.ParseHead(src[pos:])
		if eh.N == 0 {
			return nil, pos, decodeErr(cbor.ErrTruncated, pos)
		}
		if eh.Major != wire.MajorOther {
			return nil, pos, decodeErrf(ErrTypeMismatch, pos, ": element %d is not float", i)
		}
		switch eh.AI {
		case wire.AI2Bytes:
			result[i] = wire.DecodeFloat16(uint16(eh.Arg))
		case wire.AI4Bytes:
			result[i] = float64(math.Float32frombits(uint32(eh.Arg)))
		case wire.AI8Bytes:
			result[i] = math.Float64frombits(eh.Arg)
		default:
			return nil, pos, decodeErrf(ErrTypeMismatch, pos, ": element %d is not float", i)
		}
		pos += eh.N
	}
	return result, pos, nil
}

// DecodeBytesArray decodes a CBOR array of byte strings into a [][]byte.
func DecodeBytesArray(src []byte, opts DecodeOpts) ([][]byte, int, error) {
	if len(src) == 0 {
		return nil, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	h := wire.ParseHead(src)
	if h.N == 0 {
		return nil, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	if h.Major != wire.MajorArray {
		return nil, 0, decodeErrDetail(ErrTypeMismatch, 0, ": expected array")
	}
	if h.AI == wire.AIIndefinite {
		return nil, 0, decodeErrDetail(ErrTypeMismatch, 0, ": indefinite arrays not supported")
	}
	if h.Arg > uint64(opts.maxArray()) {
		return nil, 0, decodeErr(cbor.ErrMaxArrayLength, 0)
	}
	// Every element occupies at least one byte; fail before allocating.
	if h.Arg > uint64(len(src)-h.N) {
		return nil, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	count := int(h.Arg)
	result := make([][]byte, count)
	pos := h.N
	for i := range count {
		if pos >= len(src) {
			return nil, pos, decodeErr(cbor.ErrTruncated, pos)
		}
		eh := wire.ParseHead(src[pos:])
		if eh.N == 0 {
			return nil, pos, decodeErr(cbor.ErrTruncated, pos)
		}
		if eh.Major != wire.MajorBytes || eh.AI == wire.AIIndefinite {
			return nil, pos, decodeErrf(ErrTypeMismatch, pos, ": element %d is not bytes", i)
		}
		length := int(eh.Arg)
		start := pos + eh.N
		end := start + length
		if end > len(src) {
			return nil, pos, decodeErr(cbor.ErrTruncated, pos)
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
		return nil, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	h := wire.ParseHead(src)
	if h.N == 0 {
		return nil, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	if h.Major != wire.MajorArray {
		return nil, 0, decodeErrDetail(ErrTypeMismatch, 0, ": expected array")
	}
	if h.AI == wire.AIIndefinite {
		return nil, 0, decodeErrDetail(ErrTypeMismatch, 0, ": indefinite arrays not supported")
	}
	if h.Arg > uint64(opts.maxArray()) {
		return nil, 0, decodeErr(cbor.ErrMaxArrayLength, 0)
	}
	// Every element occupies at least one byte; fail before allocating.
	if h.Arg > uint64(len(src)-h.N) {
		return nil, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	count := int(h.Arg)
	result := make([]string, count)
	pos := h.N
	for i := range count {
		if pos >= len(src) {
			return nil, pos, decodeErr(cbor.ErrTruncated, pos)
		}
		eh := wire.ParseHead(src[pos:])
		if eh.N == 0 {
			return nil, pos, decodeErr(cbor.ErrTruncated, pos)
		}
		if eh.Major != wire.MajorText || eh.AI == wire.AIIndefinite {
			return nil, pos, decodeErrf(ErrTypeMismatch, pos, ": element %d is not text", i)
		}
		length := int(eh.Arg)
		start := pos + eh.N
		end := start + length
		if end > len(src) {
			return nil, pos, decodeErr(cbor.ErrTruncated, pos)
		}
		if opts.RejectInvalidUTF8 && !utf8.Valid(src[start:end]) {
			return nil, pos, decodeErr(cbor.ErrInvalidUTF8, pos)
		}
		result[i] = replaceInvalidText(string(src[start:end]), &opts)
		pos = end
	}
	return result, pos, nil
}
