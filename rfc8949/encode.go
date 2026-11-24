// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"bytes"
	"cmp"
	"fmt"
	"math"
	"slices"
	"sync"
	"unicode/utf8"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/internal/rawvalue"
	"github.com/jahkeup/corecbor/wire"
)

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

// SortStateCache is an encoder-local sort state for single-goroutine hot paths.
type SortStateCache struct {
	ss   sortState
	used bool
}

func (c *SortStateCache) get() *sortState {
	if c.used {
		return nil
	}
	c.used = true
	c.ss.keyBuf = c.ss.keyBuf[:0]
	return &c.ss
}

func (c *SortStateCache) put() {
	c.used = false
}

type SortMode int

const (
	SortBytewiseLex SortMode = iota
	SortLengthFirst
	// SortNone keeps map entries in insertion order while the other
	// deterministic rules (shortest floats, bignum normalization) still
	// apply. Used by the Experimental ModePreferredPlus.
	SortNone
)

type FloatMode int

const (
	FloatShortest FloatMode = iota
	FloatPreserve
	FloatForce64
)

type EncodeOpts struct {
	Deterministic        bool
	SortMode             SortMode
	FloatMode            FloatMode
	AllowNonFiniteFloats bool
	AllowInvalidUTF8     bool
	SkipUTF8Validation   bool
	// InvalidUTF8 selects how text that is not valid UTF-8 is written
	// (proposal 035). It applies when neither AllowInvalidUTF8 nor
	// SkipUTF8Validation is set; the zero value rejects.
	InvalidUTF8 InvalidUTF8
	// LegacyBignumPassthrough emits tag 2/3 contents as supplied in
	// deterministic modes, as v0.2.2 did, instead of stripping leading
	// zeros and reducing values that fit major type 0/1 (RFC 8949
	// §3.4.3).
	//
	// Deprecated: v0.2 compatibility only; removed no earlier than v0.32.0.
	LegacyBignumPassthrough bool
	// RejectInvalidTagContent returns an error wrapping
	// cbor.ErrMalformedTag for a tag whose content is not valid for it,
	// under the rules DecodeOpts.RejectInvalidTagContent applies
	// (proposal 037 C10).
	RejectInvalidTagContent bool
	// RejectDuplicateMapKeys returns an error wrapping
	// cbor.ErrDuplicateMapKey for a map whose keys repeat in the CBOR
	// data model, in modes that don't sort (the sorting modes always
	// reject repeats) (proposal 037 C11). The bools sit together so the struct,
	// copied per call, doesn't grow.
	RejectDuplicateMapKeys bool
	SortCache              *SortStateCache
}

func Encode(dst []byte, v cbor.Value, opts EncodeOpts) ([]byte, error) {
	return encode(dst, &v, &opts)
}

func EncodeDeterministic(dst []byte, v cbor.Value, opts EncodeOpts) ([]byte, error) {
	opts.Deterministic = true
	return encode(dst, &v, &opts)
}

func encode(dst []byte, v *cbor.Value, opts *EncodeOpts) ([]byte, error) {
	if v.Kind == cbor.KindInvalid {
		return dst, fmt.Errorf("encode: %w", cbor.ErrNilValue)
	}
	if v.Kind == rawvalue.Kind {
		return encodeOther(dst, v)
	}
	switch v.Kind {
	case cbor.KindUint:
		return wire.AppendHead(dst, wire.MajorUint, v.Num), nil
	case cbor.KindNegInt:
		return wire.AppendHead(dst, wire.MajorNegInt, v.Num), nil
	case cbor.KindBytes:
		dst = wire.AppendHead(dst, wire.MajorBytes, uint64(len(v.Bstr)))
		return append(dst, v.Bstr...), nil
	case cbor.KindText:
		s := v.Str
		if !opts.AllowInvalidUTF8 && !opts.SkipUTF8Validation && !utf8.ValidString(s) {
			return encodeInvalidText(dst, s, opts)
		}
		dst = wire.AppendHead(dst, wire.MajorText, uint64(len(s)))
		return append(dst, s...), nil
	case cbor.KindArray:
		items := v.Items
		dst = wire.AppendHead(dst, wire.MajorArray, uint64(len(items)))
		var err error
		for i := range items {
			elem := &items[i]
			switch elem.Kind {
			case cbor.KindUint:
				dst = wire.AppendHead(dst, wire.MajorUint, elem.Num)
			case cbor.KindNegInt:
				dst = wire.AppendHead(dst, wire.MajorNegInt, elem.Num)
			case cbor.KindBool:
				if elem.Num != 0 {
					dst = append(dst, wire.SimpleTrue)
				} else {
					dst = append(dst, wire.SimpleFalse)
				}
			case cbor.KindNull:
				dst = append(dst, wire.SimpleNull)
			case cbor.KindBytes:
				dst = wire.AppendHead(dst, wire.MajorBytes, uint64(len(elem.Bstr)))
				dst = append(dst, elem.Bstr...)
			case cbor.KindText:
				if textNeedsPolicy(elem.Str, opts) {
					if dst, err = encodeInvalidText(dst, elem.Str, opts); err != nil {
						return dst, err
					}
					continue
				}
				dst = wire.AppendHead(dst, wire.MajorText, uint64(len(elem.Str)))
				dst = append(dst, elem.Str...)
			default:
				dst, err = encode(dst, elem, opts)
				if err != nil {
					return dst, err
				}
			}
		}
		return dst, nil
	case cbor.KindMap:
		return encodeMap(dst, v.Pairs, opts)
	case cbor.KindTag:
		return encodeTag(dst, v, opts)
	case cbor.KindBool:
		if v.Num != 0 {
			return append(dst, wire.SimpleTrue), nil
		}
		return append(dst, wire.SimpleFalse), nil
	case cbor.KindNull:
		return append(dst, wire.SimpleNull), nil
	case cbor.KindUndefined:
		return append(dst, wire.SimpleUndefined), nil
	case cbor.KindSimple:
		sv := uint8(v.Num)
		if sv < 24 {
			return append(dst, wire.MajorOther|sv), nil
		}
		if sv < 32 {
			return dst, fmt.Errorf("encode simple(%d): %w", sv, cbor.ErrReservedSimple)
		}
		return append(dst, wire.SimpleOneByte, sv), nil
	case cbor.KindFloat32:
		return encodeFloat32(dst, math.Float32frombits(uint32(v.Num)), opts)
	case cbor.KindFloat64:
		return encodeFloat64(dst, math.Float64frombits(v.Num), opts)
	default:
		return dst, unsupportedKind(v.Kind)
	}
}

// encodeOther splices a raw Value made by rawvalue.Make: a pre-encoded,
// validated item from Permissive-mode RawMessage/RawTag. A Value that
// merely carries the raw kind gets the same error as any other
// unsupported kind. It is kept out of line, marker check included:
// handling the raw kind inside encode's switch, or inlining the check,
// cost ~20% on scalar encoding (code generation of that recursive hot
// function, not extra work).
//
//go:noinline
func encodeOther(dst []byte, v *cbor.Value) ([]byte, error) {
	if !rawvalue.Is(v) {
		return dst, unsupportedKind(v.Kind)
	}
	return append(dst, v.Bstr...), nil
}

// encodeTag writes a tag Value. It is out of line so encode's hot switch
// stays small: carrying the tag 2/3 preferred-bignum branch (proposal
// 024) inside encode cost ~27% on scalar-array encoding through code
// generation alone, as raw values did for encodeOther.
//
//go:noinline
func encodeTag(dst []byte, v *cbor.Value, opts *EncodeOpts) ([]byte, error) {
	if len(v.Items) == 0 {
		return dst, fmt.Errorf("encode tag %d: inner is %w", v.Num, cbor.ErrNilValue)
	}
	inner := &v.Items[0]
	if inner.Kind == cbor.KindInvalid {
		return dst, fmt.Errorf("encode tag %d: inner is %w", v.Num, cbor.ErrNilValue)
	}
	if opts.RejectInvalidTagContent {
		if p := tagContentProblem(v.Num, *inner); p != "" {
			return dst, fmt.Errorf("encode tag %d: %w: %s", v.Num, cbor.ErrMalformedTag, p)
		}
	}
	if v.Num-cbor.TagUnsignedBignum < 2 && opts.Deterministic &&
		inner.Kind == cbor.KindBytes && !opts.LegacyBignumPassthrough {
		return appendPreferredBignum(dst, v.Num, inner.Bstr), nil
	}
	dst = wire.AppendHead(dst, wire.MajorTag, v.Num)
	return encode(dst, inner, opts)
}

// appendPreferredBignum writes tag 2/3 content in RFC 8949 §3.4.3
// preferred serialization: leading zero bytes dropped, and a value that
// fits 64 bits written as major type 0 (tag 2) or 1 (tag 3).
func appendPreferredBignum(dst []byte, tag uint64, b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) <= 8 {
		var n uint64
		for _, c := range b {
			n = n<<8 | uint64(c)
		}
		if tag == cbor.TagUnsignedBignum {
			return wire.AppendHead(dst, wire.MajorUint, n)
		}
		return wire.AppendHead(dst, wire.MajorNegInt, n)
	}
	dst = wire.AppendHead(dst, wire.MajorTag, tag)
	dst = wire.AppendHead(dst, wire.MajorBytes, uint64(len(b)))
	return append(dst, b...)
}

// canonicalNaN64 is the binary64 quiet NaN CTAP2 (FloatForce64) emits
// for every NaN, the double-width form of f97e00 (spec §2.2).
const canonicalNaN64 = 0x7ff8000000000000

func encodeFloat32(dst []byte, val float32, opts *EncodeOpts) ([]byte, error) {
	f := float64(val)
	if !opts.AllowNonFiniteFloats && (math.IsNaN(f) || math.IsInf(f, 0)) {
		return dst, fmt.Errorf("encode float32: %w", cbor.ErrNonFiniteFloat)
	}
	switch opts.FloatMode {
	case FloatForce64:
		if math.IsNaN(f) {
			return wire.AppendFloat64(dst, math.Float64frombits(canonicalNaN64)), nil
		}
		return wire.AppendFloat64(dst, f), nil
	case FloatShortest:
		if opts.Deterministic {
			return appendShortestFloat(dst, f), nil
		}
		return wire.AppendFloat32(dst, val), nil
	default:
		return wire.AppendFloat32(dst, val), nil
	}
}

func encodeFloat64(dst []byte, val float64, opts *EncodeOpts) ([]byte, error) {
	f := val
	if !opts.AllowNonFiniteFloats && (math.IsNaN(f) || math.IsInf(f, 0)) {
		return dst, fmt.Errorf("encode float64: %w", cbor.ErrNonFiniteFloat)
	}
	switch opts.FloatMode {
	case FloatForce64:
		if math.IsNaN(f) {
			return wire.AppendFloat64(dst, math.Float64frombits(canonicalNaN64)), nil
		}
		return wire.AppendFloat64(dst, f), nil
	case FloatShortest:
		if opts.Deterministic {
			return appendShortestFloat(dst, f), nil
		}
		return wire.AppendFloat64(dst, f), nil
	default:
		return wire.AppendFloat64(dst, f), nil
	}
}

func appendShortestFloat(dst []byte, f float64) []byte {
	if bits, ok := wire.EncodeFloat16(f); ok {
		return wire.AppendFloat16(dst, bits)
	}
	if wire.CanFloat32Lossless(f) {
		return wire.AppendFloat32(dst, float32(f))
	}
	return wire.AppendFloat64(dst, f)
}

func encodeMap(dst []byte, m []cbor.MapEntry, opts *EncodeOpts) ([]byte, error) {
	if opts.RejectDuplicateMapKeys {
		if err := duplicateKeyErr(m); err != nil {
			return dst, err
		}
	}
	dst = wire.AppendHead(dst, wire.MajorMap, uint64(len(m)))
	if !opts.Deterministic || len(m) <= 1 || opts.SortMode == SortNone {
		var err error
		for i := range m {
			key := &m[i].Key
			switch key.Kind {
			case cbor.KindText:
				if textNeedsPolicy(key.Str, opts) {
					if dst, err = encodeInvalidText(dst, key.Str, opts); err != nil {
						return dst, err
					}
					break
				}
				dst = wire.AppendHead(dst, wire.MajorText, uint64(len(key.Str)))
				dst = append(dst, key.Str...)
			case cbor.KindUint:
				dst = wire.AppendHead(dst, wire.MajorUint, key.Num)
			default:
				dst, err = encode(dst, key, opts)
				if err != nil {
					return dst, err
				}
			}
			val := &m[i].Value
			switch val.Kind {
			case cbor.KindUint:
				dst = wire.AppendHead(dst, wire.MajorUint, val.Num)
			case cbor.KindText:
				if textNeedsPolicy(val.Str, opts) {
					if dst, err = encodeInvalidText(dst, val.Str, opts); err != nil {
						return dst, err
					}
					break
				}
				dst = wire.AppendHead(dst, wire.MajorText, uint64(len(val.Str)))
				dst = append(dst, val.Str...)
			case cbor.KindBytes:
				dst = wire.AppendHead(dst, wire.MajorBytes, uint64(len(val.Bstr)))
				dst = append(dst, val.Bstr...)
			case cbor.KindBool:
				if val.Num != 0 {
					dst = append(dst, wire.SimpleTrue)
				} else {
					dst = append(dst, wire.SimpleFalse)
				}
			case cbor.KindNull:
				dst = append(dst, wire.SimpleNull)
			default:
				dst, err = encode(dst, val, opts)
				if err != nil {
					return dst, err
				}
			}
		}
		return dst, nil
	}

	var ss *sortState
	var pooled bool
	if opts.SortCache != nil {
		ss = opts.SortCache.get()
	}
	if ss == nil {
		ss = sortStatePool.Get().(*sortState)
		ss.keyBuf = ss.keyBuf[:0]
		pooled = true
	}
	if cap(ss.entries) >= len(m) {
		ss.entries = ss.entries[:len(m)]
	} else {
		ss.entries = make([]sortEntry, len(m))
	}

	for i := range m {
		start := len(ss.keyBuf)
		var err error
		ss.keyBuf, err = encode(ss.keyBuf, &m[i].Key, opts)
		if err != nil {
			if pooled {
				sortStatePool.Put(ss)
			} else {
				opts.SortCache.put()
			}
			return dst, err
		}
		ss.entries[i] = sortEntry{keyStart: start, keyEnd: len(ss.keyBuf), index: i}
	}

	keyBuf := ss.keyBuf
	entries := ss.entries
	// RFC 8949 §5.6: a map with duplicate keys is not valid CBOR, and the
	// §4.2.1 ordering is undefined for it. A comparison sort must compare
	// every pair that ends up adjacent, so equal encodings always reach
	// the comparator; noting them there costs no extra pass.
	dup := false
	slices.SortFunc(entries, func(a, b sortEntry) int {
		ea := keyBuf[a.keyStart:a.keyEnd]
		eb := keyBuf[b.keyStart:b.keyEnd]
		if opts.SortMode == SortLengthFirst {
			if c := cmp.Compare(len(ea), len(eb)); c != 0 {
				return c
			}
		}
		if len(ea) > 0 && len(eb) > 0 && ea[0] != eb[0] {
			return int(ea[0]) - int(eb[0])
		}
		c := bytes.Compare(ea, eb)
		if c == 0 && a.index != b.index {
			dup = true
		}
		return c
	})
	if dup {
		if pooled {
			sortStatePool.Put(ss)
		} else {
			opts.SortCache.put()
		}
		return dst, fmt.Errorf("encode map: %w", cbor.ErrDuplicateMapKey)
	}

	var err error
	for _, se := range entries {
		dst = append(dst, keyBuf[se.keyStart:se.keyEnd]...)
		dst, err = encode(dst, &m[se.index].Value, opts)
		if err != nil {
			if pooled {
				sortStatePool.Put(ss)
			} else {
				opts.SortCache.put()
			}
			return dst, err
		}
	}
	if pooled {
		sortStatePool.Put(ss)
	} else {
		opts.SortCache.put()
	}
	return dst, nil
}

// duplicateKeyErr returns the duplicate-key error for m, or nil. It is
// out of line so encodeMap's common path keeps its code generation.
//
//go:noinline
func duplicateKeyErr(m []cbor.MapEntry) error {
	if len(m) > 1 && hasDuplicateKeys(m) {
		return fmt.Errorf("encode map: %w", cbor.ErrDuplicateMapKey)
	}
	return nil
}

// hasDuplicateKeys reports whether two keys of m are the same key in
// the CBOR data model (RFC 8949 §5.6.1, the decoder's default key
// identity). Small maps compare pairwise; larger ones hash.
func hasDuplicateKeys(m []cbor.MapEntry) bool {
	if len(m) <= dedupThreshold {
		for i := 1; i < len(m); i++ {
			for j := range i {
				if keysEqual(m[i].Key, m[j].Key, false) {
					return true
				}
			}
		}
		return false
	}
	seen := make(map[uint64][]int32, len(m))
	for i := range m {
		h := keyHash(m[i].Key)
		for _, j := range seen[h] {
			if keysEqual(m[i].Key, m[j].Key, false) {
				return true
			}
		}
		seen[h] = append(seen[h], int32(i))
	}
	return false
}

// kindError is the encoder's unsupported-kind error. It wraps
// ErrInvalidKind while keeping the v0.2.2 message text.
type kindError cbor.Kind

func (k kindError) Error() string {
	return fmt.Sprintf("encode: unsupported Value kind %d", cbor.Kind(k))
}

func (k kindError) Unwrap() error { return cbor.ErrInvalidKind }

// unsupportedKind builds the error out of line: constructing it inside
// encode's switch changed that hot recursive function's code generation
// enough to cost ~20% on scalar encoding.
//
//go:noinline
func unsupportedKind(k cbor.Kind) error { return kindError(k) }
