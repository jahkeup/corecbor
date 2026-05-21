package rfc8949

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/wire"
)

// EncodeOpts controls encoder behavior.
type EncodeOpts struct {
	// Deterministic enables Core Deterministic Encoding (RFC 8949 §4.2.1):
	// shortest float encoding, map keys sorted by encoded bytes.
	Deterministic bool

	// AllowNonFiniteFloats permits NaN and ±Infinity. In deterministic mode,
	// NaN is normalized to the canonical half-precision 0xf97e00.
	AllowNonFiniteFloats bool

	// AllowInvalidUTF8 permits Text values containing invalid UTF-8 sequences.
	AllowInvalidUTF8 bool
}

// Encode appends the CBOR encoding of v to dst and returns the extended slice.
// It uses the options in opts; with default opts it produces preferred
// serialization (shortest argument encoding, input-width floats).
func Encode(dst []byte, v cbor.Value, opts EncodeOpts) ([]byte, error) {
	return encode(dst, v, opts)
}

// EncodeDeterministic is like Encode but forces Deterministic=true regardless
// of what opts contains.
func EncodeDeterministic(dst []byte, v cbor.Value, opts EncodeOpts) ([]byte, error) {
	opts.Deterministic = true
	return encode(dst, v, opts)
}

func encode(dst []byte, v cbor.Value, opts EncodeOpts) ([]byte, error) {
	if v == nil {
		return dst, fmt.Errorf("encode: %w", cbor.ErrNilValue)
	}
	switch val := v.(type) {
	case cbor.Uint:
		return wire.AppendHead(dst, wire.MajorUint, uint64(val)), nil
	case cbor.NegInt:
		return wire.AppendHead(dst, wire.MajorNegInt, uint64(val)), nil
	case cbor.Bytes:
		dst = wire.AppendHead(dst, wire.MajorBytes, uint64(len(val)))
		return append(dst, val...), nil
	case cbor.Text:
		if !opts.AllowInvalidUTF8 && !utf8.ValidString(string(val)) {
			return dst, fmt.Errorf("encode text: %w", cbor.ErrInvalidUTF8)
		}
		dst = wire.AppendHead(dst, wire.MajorText, uint64(len(val)))
		return append(dst, val...), nil
	case cbor.Array:
		dst = wire.AppendHead(dst, wire.MajorArray, uint64(len(val)))
		var err error
		for _, elem := range val {
			dst, err = encode(dst, elem, opts)
			if err != nil {
				return dst, err
			}
		}
		return dst, nil
	case cbor.Map:
		return encodeMap(dst, val, opts)
	case cbor.Tag:
		if val.Inner == nil {
			return dst, fmt.Errorf("encode tag %d: inner is %w", val.ID, cbor.ErrNilValue)
		}
		dst = wire.AppendHead(dst, wire.MajorTag, val.ID)
		return encode(dst, val.Inner, opts)
	case cbor.Bool:
		if val {
			return append(dst, wire.SimpleTrue), nil
		}
		return append(dst, wire.SimpleFalse), nil
	case cbor.Null:
		return append(dst, wire.SimpleNull), nil
	case cbor.Undefined:
		return append(dst, wire.SimpleUndefined), nil
	case cbor.Simple:
		if uint8(val) < 24 {
			return append(dst, wire.MajorOther|uint8(val)), nil
		}
		return append(dst, wire.SimpleOneByte, uint8(val)), nil
	case cbor.Float32:
		return encodeFloat32(dst, val, opts)
	case cbor.Float64:
		return encodeFloat64(dst, val, opts)
	default:
		return dst, fmt.Errorf("encode: unsupported Value type %T", v)
	}
}

func encodeFloat32(dst []byte, val cbor.Float32, opts EncodeOpts) ([]byte, error) {
	f := float64(val)
	if !opts.AllowNonFiniteFloats && (math.IsNaN(f) || math.IsInf(f, 0)) {
		return dst, fmt.Errorf("encode float32: %w", cbor.ErrNonFiniteFloat)
	}
	if opts.Deterministic {
		return appendShortestFloat(dst, f, opts), nil
	}
	return wire.AppendFloat32(dst, float32(val)), nil
}

func encodeFloat64(dst []byte, val cbor.Float64, opts EncodeOpts) ([]byte, error) {
	f := float64(val)
	if !opts.AllowNonFiniteFloats && (math.IsNaN(f) || math.IsInf(f, 0)) {
		return dst, fmt.Errorf("encode float64: %w", cbor.ErrNonFiniteFloat)
	}
	if opts.Deterministic {
		return appendShortestFloat(dst, f, opts), nil
	}
	return wire.AppendFloat64(dst, f), nil
}

// appendShortestFloat encodes f in the shortest lossless IEEE 754 width.
func appendShortestFloat(dst []byte, f float64, _ EncodeOpts) []byte {
	if bits, ok := wire.EncodeFloat16(f); ok {
		return wire.AppendFloat16(dst, bits)
	}
	if wire.CanFloat32Lossless(f) {
		return wire.AppendFloat32(dst, float32(f))
	}
	return wire.AppendFloat64(dst, f)
}

// encodeMap encodes a CBOR map. In deterministic mode, keys are sorted by
// bytewise-lexicographic comparison of their encoded forms without mutating
// the input slice.
func encodeMap(dst []byte, m cbor.Map, opts EncodeOpts) ([]byte, error) {
	dst = wire.AppendHead(dst, wire.MajorMap, uint64(len(m)))
	if !opts.Deterministic || len(m) <= 1 {
		var err error
		for _, entry := range m {
			dst, err = encode(dst, entry.Key, opts)
			if err != nil {
				return dst, err
			}
			dst, err = encode(dst, entry.Value, opts)
			if err != nil {
				return dst, err
			}
		}
		return dst, nil
	}

	// Phase 4 optimization: pool these buffers to reduce allocations.
	type sortEntry struct {
		encodedKey []byte
		index      int
	}
	entries := make([]sortEntry, len(m))
	for i, entry := range m {
		enc, err := encode(nil, entry.Key, opts)
		if err != nil {
			return dst, err
		}
		entries[i] = sortEntry{encodedKey: enc, index: i}
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].encodedKey, entries[j].encodedKey) < 0
	})

	var err error
	for _, se := range entries {
		dst = append(dst, se.encodedKey...)
		dst, err = encode(dst, m[se.index].Value, opts)
		if err != nil {
			return dst, err
		}
	}
	return dst, nil
}
