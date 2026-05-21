package cbor

import "errors"

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
	// information value (28, 29, or 30) which is not well-formed.
	ErrReservedAI = errors.New("cbor: reserved additional information value")
)
