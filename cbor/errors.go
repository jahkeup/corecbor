// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"errors"

	"github.com/jahkeup/corecbor/internal/decerr"
)

// DecodeError is the concrete type of every error the decoder returns
// for malformed or rejected input: Offset is the byte offset of the
// offending item, Path (with WithErrorPath) locates it, and Err is the
// wrapped sentinel, so errors.Is matches as before. Use errors.As to
// read the offset instead of parsing the message, whose text is
// unchanged from v0.2.2.
type DecodeError = decerr.Error

// Error sentinels for the corecbor library. Every error returned by
// the encoder or decoder wraps one of these via fmt.Errorf("%w ...").
// Callers discriminate via errors.Is.
var (
	// ErrNonShortest indicates a CBOR argument was not encoded in the
	// shortest possible form (RFC 8949 §4.2.1).
	ErrNonShortest = errors.New("cbor: argument not in shortest form")

	// ErrIndefiniteLength indicates an indefinite-length item was
	// encountered where the strictness knob rejects it.
	ErrIndefiniteLength = errors.New("cbor: indefinite-length encoding")

	// ErrInvalidUTF8 indicates a text string (major type 3) contains
	// bytes that are not valid UTF-8.
	ErrInvalidUTF8 = errors.New("cbor: invalid UTF-8 in text string")

	// ErrDuplicateMapKey indicates a map contains the same key more
	// than once.
	ErrDuplicateMapKey = errors.New("cbor: duplicate map key")

	// ErrUnknownTag indicates a tag ID was encountered that is not in
	// the decoder's allowlist (when RejectUnknownTags is active).
	ErrUnknownTag = errors.New("cbor: unknown tag ID")

	// ErrNonFiniteFloat indicates a NaN or ±Infinity float was
	// encountered without the AllowNonFiniteFloats option.
	ErrNonFiniteFloat = errors.New("cbor: non-finite float (NaN or Inf)")

	// ErrNullMapKey indicates a map key is the CBOR null value.
	ErrNullMapKey = errors.New("cbor: null map key")

	// ErrTrailingBytes indicates bytes remain after the first complete
	// CBOR data item in single-value decode mode.
	ErrTrailingBytes = errors.New("cbor: trailing bytes after value")

	// ErrTruncated indicates the input ended before a complete CBOR
	// data item could be read.
	ErrTruncated = errors.New("cbor: unexpected end of input")

	// ErrMaxNestingDepth indicates the nesting depth limit was exceeded.
	ErrMaxNestingDepth = errors.New("cbor: maximum nesting depth exceeded")

	// ErrMaxArrayLength indicates an array or map declared more
	// elements than the configured limit.
	ErrMaxArrayLength = errors.New("cbor: array/map length exceeds limit")

	// ErrMaxByteStringLength indicates a byte or text string declared
	// a length exceeding the configured limit.
	ErrMaxByteStringLength = errors.New("cbor: byte/text string length exceeds limit")

	// ErrInvalidMode indicates the encoder was constructed with an
	// unrecognized mode value.
	ErrInvalidMode = errors.New("cbor: invalid encoder mode")

	// ErrNilValue indicates a nil Value was passed where a concrete
	// CBOR value is required (e.g., Tag.Inner is nil).
	ErrNilValue = errors.New("cbor: nil value in tree")

	// ErrReservedAI indicates the input contains a reserved additional
	// information value (28, 29, or 30), or indefinite length (31) on an
	// integer or tag head; neither is well-formed (RFC 8949 §3.2.4).
	ErrReservedAI = errors.New("cbor: reserved additional information value")

	// ErrMemoryBudgetExceeded indicates cumulative decode allocations
	// exceeded the configured memory budget.
	ErrMemoryBudgetExceeded = errors.New("cbor: memory budget exceeded")

	// ErrTimeRange indicates a tag 0/1 time value is outside the range
	// representable by time.Time, or a float epoch is NaN or ±Inf.
	ErrTimeRange = errors.New("cbor: time value out of range")

	// ErrNotDeterministic indicates output or input that does not follow
	// the deterministic encoding rules of the selected mode.
	ErrNotDeterministic = errors.New("cbor: not deterministically encoded")

	// ErrTypeMismatch indicates a CBOR value cannot be stored in the Go
	// target type (reflection), or a Cursor read found a different major
	// type than requested.
	ErrTypeMismatch = errors.New("cbor: type mismatch")

	// ErrInvalidKind indicates a Value whose Kind the encoder doesn't
	// support.
	ErrInvalidKind = errors.New("cbor: invalid Value kind")

	// ErrReservedSimple indicates an attempt to encode simple value 24
	// through 31, whose one-byte-argument encodings RFC 8949 §3.3 says
	// MUST NOT be used.
	ErrReservedSimple = errors.New("cbor: reserved simple value")

	// ErrUnexpectedBreak indicates a "break" stop code (0xff) where a
	// data item was expected, outside an indefinite-length item
	// (RFC 8949 §3.2.1).
	ErrUnexpectedBreak = errors.New("cbor: unexpected break stop code")

	// ErrNotPreferred indicates input that violates preferred
	// serialization (RFC 8949 §4.1, §3.4.3) in a checking decoder.
	// Where a per-knob sentinel also applies (ErrNonShortest,
	// ErrIndefiniteLength) the error wraps both.
	ErrNotPreferred = errors.New("cbor: input not in preferred serialization")

	// ErrInvalidOption indicates decoder or encoder options that
	// contradict each other (for example KeepDuplicateMapKeys together
	// with RejectDuplicateMapKeys).
	ErrInvalidOption = errors.New("cbor: conflicting options")
)

var (
	// ErrInvalidChunk indicates a chunk of an indefinite-length byte or
	// text string that is not a definite-length string of the same major
	// type (RFC 8949 §3.2.3): the input is not well-formed. It used to
	// be reported as ErrTruncated.
	ErrInvalidChunk = errors.New("cbor: invalid chunk in indefinite-length string")

	// ErrMaxItemSize indicates an item read from an io.Reader whose
	// encoded size exceeds the item size limit (DecodeFrom, Stream;
	// WithMaxItemSize in the root package).
	ErrMaxItemSize = errors.New("cbor: item size exceeds limit")
)

// ErrOverflow indicates that a CBOR integer value overflows the
// target Go type. The root package's corecbor.ErrOverflow is the
// same value.
var ErrOverflow = errors.New("cbor: integer overflow for target type")
