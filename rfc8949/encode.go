package rfc8949

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"sync"
	"unicode/utf8"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/wire"
)

// sortState holds reusable buffers for deterministic map key sorting.
// Pooled to eliminate per-encode allocations.
type sortState struct {
	entries []sortEntry
	keyBuf  []byte
}

type sortEntry struct {
	keyStart int
	keyEnd   int
	index    int
}

var sortStatePool = sync.Pool{
	New: func() any { return &sortState{} },
}

// SortMode controls how map keys are ordered in deterministic encoding.
type SortMode int

const (
	// SortBytewiseLex sorts keys by bytewise-lexicographic comparison of
	// their encoded forms (RFC 8949 §4.2.1 Core Deterministic).
	SortBytewiseLex SortMode = iota

	// SortLengthFirst sorts keys by encoded key length first, then
	// bytewise-lexicographic within same length (RFC 7049 §3.9 /
	// RFC 8949 §4.2.3 old canonical CBOR).
	SortLengthFirst
)

// FloatMode controls how floats are encoded in deterministic mode.
type FloatMode int

const (
	// FloatShortest encodes in the shortest lossless IEEE 754 width
	// (try f16→f32→f64). This is the Core Deterministic behavior.
	FloatShortest FloatMode = iota

	// FloatPreserve keeps the input width (Float32→32bit, Float64→64bit).
	// This is the Permissive mode behavior.
	FloatPreserve

	// FloatForce64 always encodes as float64 (8 bytes). This is the
	// CTAP2 requirement.
	FloatForce64
)

// EncodeOpts controls encoder behavior.
type EncodeOpts struct {
	// Deterministic enables deterministic encoding: map keys are sorted
	// according to SortMode.
	Deterministic bool

	// SortMode selects the key sort algorithm in deterministic mode.
	// Zero value (SortBytewiseLex) is RFC 8949 §4.2.1.
	SortMode SortMode

	// FloatMode selects the float encoding strategy. Zero value
	// (FloatShortest) uses shortest lossless width in deterministic mode.
	FloatMode FloatMode

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
	switch opts.FloatMode {
	case FloatForce64:
		return wire.AppendFloat64(dst, f), nil
	case FloatShortest:
		if opts.Deterministic {
			return appendShortestFloat(dst, f, opts), nil
		}
		return wire.AppendFloat32(dst, float32(val)), nil
	default:
		return wire.AppendFloat32(dst, float32(val)), nil
	}
}

func encodeFloat64(dst []byte, val cbor.Float64, opts EncodeOpts) ([]byte, error) {
	f := float64(val)
	if !opts.AllowNonFiniteFloats && (math.IsNaN(f) || math.IsInf(f, 0)) {
		return dst, fmt.Errorf("encode float64: %w", cbor.ErrNonFiniteFloat)
	}
	switch opts.FloatMode {
	case FloatForce64:
		return wire.AppendFloat64(dst, f), nil
	case FloatShortest:
		if opts.Deterministic {
			return appendShortestFloat(dst, f, opts), nil
		}
		return wire.AppendFloat64(dst, f), nil
	default:
		return wire.AppendFloat64(dst, f), nil
	}
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

	ss := sortStatePool.Get().(*sortState)
	ss.keyBuf = ss.keyBuf[:0]
	if cap(ss.entries) >= len(m) {
		ss.entries = ss.entries[:len(m)]
	} else {
		ss.entries = make([]sortEntry, len(m))
	}

	for i, entry := range m {
		start := len(ss.keyBuf)
		var err error
		ss.keyBuf, err = encode(ss.keyBuf, entry.Key, opts)
		if err != nil {
			sortStatePool.Put(ss)
			return dst, err
		}
		ss.entries[i] = sortEntry{keyStart: start, keyEnd: len(ss.keyBuf), index: i}
	}

	keyBuf := ss.keyBuf
	entries := ss.entries
	sort.Slice(entries, func(i, j int) bool {
		ei := keyBuf[entries[i].keyStart:entries[i].keyEnd]
		ej := keyBuf[entries[j].keyStart:entries[j].keyEnd]
		if opts.SortMode == SortLengthFirst {
			if len(ei) != len(ej) {
				return len(ei) < len(ej)
			}
		}
		return bytes.Compare(ei, ej) < 0
	})

	var err error
	for _, se := range entries {
		dst = append(dst, keyBuf[se.keyStart:se.keyEnd]...)
		dst, err = encode(dst, m[se.index].Value, opts)
		if err != nil {
			sortStatePool.Put(ss)
			return dst, err
		}
	}
	sortStatePool.Put(ss)
	return dst, nil
}
