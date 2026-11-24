// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"math"
	"unicode/utf8"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/wire"
)

// The homogeneous array decoders apply the same well-formedness rules,
// strictness knobs, limits and memory budget as Decode (proposal 037
// C3), and the checking-decoder options (RequirePreferred and the rest)
// over the array's bytes. Indefinite-length arrays and string chunks
// are not supported (ErrTypeMismatch, or ErrIndefiniteLength under
// RejectIndefiniteLength). Interner, Arena and ZeroCopy don't apply.

// Bytes charged to the memory budget per element, besides string data.
const (
	uint64Size = 8
	sliceSize  = 24 // a []byte header
	stringSize = 16 // a string header
)

// homogeneousHead checks the array head at the start of src and returns
// the element count and the offset of the first element. It charges
// elemSize bytes per element to the budget.
func homogeneousHead(src []byte, opts *DecodeOpts, elemSize int) (int, int, error) {
	if len(src) == 0 {
		return 0, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	h := wire.ParseHead(src)
	if h.N == 0 {
		return 0, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	if h.Major != wire.MajorArray {
		return 0, 0, decodeErrDetail(ErrTypeMismatch, 0, ": expected array")
	}
	if h.AI >= 28 && h.AI <= 30 {
		return 0, 0, decodeErr(cbor.ErrReservedAI, 0)
	}
	if h.AI == wire.AIIndefinite {
		if opts.RejectIndefiniteLength {
			return 0, 0, decodeErr(cbor.ErrIndefiniteLength, 0)
		}
		return 0, 0, decodeErrDetail(ErrTypeMismatch, 0, ": indefinite arrays not supported")
	}
	if opts.RejectNonShortest && !h.IsShortest() {
		return 0, 0, decodeErr(cbor.ErrNonShortest, 0)
	}
	if h.Arg > uint64(opts.maxArray()) {
		return 0, 0, decodeErr(cbor.ErrMaxArrayLength, 0)
	}
	if opts.maxNesting() < 1 {
		return 0, 0, decodeErr(cbor.ErrMaxNestingDepth, h.N)
	}
	// Every element occupies at least one byte; fail before allocating.
	if h.Arg > uint64(len(src)-h.N) {
		return 0, 0, decodeErr(cbor.ErrTruncated, 0)
	}
	count := int(h.Arg)
	if err := opts.Budget.charge(count*elemSize, 0); err != nil {
		return 0, 0, err
	}
	return count, h.N, nil
}

// elemHead parses the head of element i at pos and checks it as Decode
// would: reserved additional information, and the argument's form.
func elemHead(src []byte, pos int, opts *DecodeOpts) (wire.HeadResult, error) {
	if pos >= len(src) {
		return wire.HeadResult{}, decodeErr(cbor.ErrTruncated, pos)
	}
	eh := wire.ParseHead(src[pos:])
	if eh.N == 0 {
		return eh, decodeErr(cbor.ErrTruncated, pos)
	}
	if eh.AI >= 28 && eh.AI <= 30 {
		return eh, decodeErr(cbor.ErrReservedAI, pos)
	}
	if eh.AI == wire.AIIndefinite {
		switch eh.Major {
		case wire.MajorUint, wire.MajorNegInt, wire.MajorTag:
			return eh, decodeErr(cbor.ErrReservedAI, pos)
		case wire.MajorOther:
			return eh, decodeErr(cbor.ErrUnexpectedBreak, pos)
		}
		if opts.RejectIndefiniteLength {
			return eh, decodeErr(cbor.ErrIndefiniteLength, pos)
		}
	}
	if opts.RejectNonShortest && eh.Major != wire.MajorOther && !eh.IsShortest() {
		return eh, decodeErr(cbor.ErrNonShortest, pos)
	}
	return eh, nil
}

// stringElem returns the bounds of the definite-length string of the
// given major type whose head eh is at pos, and charges its bytes.
func stringElem(src []byte, pos, i int, eh wire.HeadResult, major byte, what string, opts *DecodeOpts) (int, int, error) {
	if eh.Major != major || eh.AI == wire.AIIndefinite {
		return 0, 0, decodeErrf(ErrTypeMismatch, pos, ": element %d is not %s", i, what)
	}
	if eh.Arg > uint64(opts.maxBytes()) {
		return 0, 0, decodeErr(cbor.ErrMaxByteStringLength, pos)
	}
	start := pos + eh.N
	if eh.Arg > uint64(len(src)-start) {
		return 0, 0, decodeErr(cbor.ErrTruncated, pos)
	}
	length := int(eh.Arg)
	if err := opts.Budget.charge(length, pos); err != nil {
		return 0, 0, err
	}
	return start, start + length, nil
}

// checkHomogeneous runs the checking-decoder options over the array's
// bytes, as Decode does after a successful decode.
func checkHomogeneous(src []byte, opts *DecodeOpts) error {
	if opts.RequirePreferred || opts.RequireSortedMapKeys || opts.RequireCanonicalNaN {
		return checkSerialization(src, *opts)
	}
	return nil
}

// DecodeUintArray decodes a CBOR array where every element is major
// type 0 (unsigned integer) directly into a []uint64. Returns
// ErrTypeMismatch if any element is not a uint.
func DecodeUintArray(src []byte, opts DecodeOpts) ([]uint64, int, error) {
	count, pos, err := homogeneousHead(src, &opts, uint64Size)
	if err != nil {
		return nil, 0, err
	}
	result := make([]uint64, count)
	for i := range count {
		eh, err := elemHead(src, pos, &opts)
		if err != nil {
			return nil, pos, err
		}
		if eh.Major != wire.MajorUint {
			return nil, pos, decodeErrf(ErrTypeMismatch, pos, ": element %d is not uint (major %d)", i, eh.Major>>5)
		}
		result[i] = eh.Arg
		pos += eh.N
	}
	if err := checkHomogeneous(src[:pos], &opts); err != nil {
		return nil, 0, err
	}
	return result, pos, nil
}

// DecodeFloat64Array decodes a CBOR array of floats (float16, float32,
// or float64) directly into a []float64 with promotion.
func DecodeFloat64Array(src []byte, opts DecodeOpts) ([]float64, int, error) {
	count, pos, err := homogeneousHead(src, &opts, uint64Size)
	if err != nil {
		return nil, 0, err
	}
	result := make([]float64, count)
	for i := range count {
		eh, err := elemHead(src, pos, &opts)
		if err != nil {
			return nil, pos, err
		}
		if eh.Major != wire.MajorOther {
			return nil, pos, decodeErrf(ErrTypeMismatch, pos, ": element %d is not float", i)
		}
		var f float64
		switch eh.AI {
		case wire.AI2Bytes:
			f = wire.DecodeFloat16(uint16(eh.Arg))
		case wire.AI4Bytes:
			f = float64(math.Float32frombits(uint32(eh.Arg)))
		case wire.AI8Bytes:
			f = math.Float64frombits(eh.Arg)
		default:
			return nil, pos, decodeErrf(ErrTypeMismatch, pos, ": element %d is not float", i)
		}
		if opts.RejectNonFiniteFloats && (math.IsNaN(f) || math.IsInf(f, 0)) {
			return nil, pos, decodeErr(cbor.ErrNonFiniteFloat, pos)
		}
		result[i] = f
		pos += eh.N
	}
	if err := checkHomogeneous(src[:pos], &opts); err != nil {
		return nil, 0, err
	}
	return result, pos, nil
}

// DecodeBytesArray decodes a CBOR array of byte strings into a [][]byte.
func DecodeBytesArray(src []byte, opts DecodeOpts) ([][]byte, int, error) {
	count, pos, err := homogeneousHead(src, &opts, sliceSize)
	if err != nil {
		return nil, 0, err
	}
	result := make([][]byte, count)
	for i := range count {
		eh, err := elemHead(src, pos, &opts)
		if err != nil {
			return nil, pos, err
		}
		start, end, err := stringElem(src, pos, i, eh, wire.MajorBytes, "bytes", &opts)
		if err != nil {
			return nil, pos, err
		}
		result[i] = make([]byte, end-start)
		copy(result[i], src[start:end])
		pos = end
	}
	if err := checkHomogeneous(src[:pos], &opts); err != nil {
		return nil, 0, err
	}
	return result, pos, nil
}

// DecodeTextArray decodes a CBOR array of text strings into a []string.
func DecodeTextArray(src []byte, opts DecodeOpts) ([]string, int, error) {
	count, pos, err := homogeneousHead(src, &opts, stringSize)
	if err != nil {
		return nil, 0, err
	}
	result := make([]string, count)
	for i := range count {
		eh, err := elemHead(src, pos, &opts)
		if err != nil {
			return nil, pos, err
		}
		start, end, err := stringElem(src, pos, i, eh, wire.MajorText, "text", &opts)
		if err != nil {
			return nil, pos, err
		}
		if opts.RejectInvalidUTF8 && !utf8.Valid(src[start:end]) {
			return nil, pos, decodeErr(cbor.ErrInvalidUTF8, pos)
		}
		result[i] = replaceInvalidText(string(src[start:end]), &opts)
		pos = end
	}
	if err := checkHomogeneous(src[:pos], &opts); err != nil {
		return nil, 0, err
	}
	return result, pos, nil
}
