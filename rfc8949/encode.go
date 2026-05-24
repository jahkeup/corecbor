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
	SortCache            *SortStateCache
}

func Encode(dst []byte, v cbor.Value, opts EncodeOpts) ([]byte, error) {
	return encode(dst, v, opts)
}

func EncodeDeterministic(dst []byte, v cbor.Value, opts EncodeOpts) ([]byte, error) {
	opts.Deterministic = true
	return encode(dst, v, opts)
}

func encode(dst []byte, v cbor.Value, opts EncodeOpts) ([]byte, error) {
	if v.IsZero() {
		return dst, fmt.Errorf("encode: %w", cbor.ErrNilValue)
	}
	switch v.Kind() {
	case cbor.KindUint:
		return wire.AppendHead(dst, wire.MajorUint, v.UintVal()), nil
	case cbor.KindNegInt:
		return wire.AppendHead(dst, wire.MajorNegInt, v.NegIntVal()), nil
	case cbor.KindBytes:
		b := v.BytesVal()
		dst = wire.AppendHead(dst, wire.MajorBytes, uint64(len(b)))
		return append(dst, b...), nil
	case cbor.KindText:
		s := v.TextVal()
		if !opts.AllowInvalidUTF8 && !opts.SkipUTF8Validation && !utf8.ValidString(s) {
			return dst, fmt.Errorf("encode text: %w", cbor.ErrInvalidUTF8)
		}
		dst = wire.AppendHead(dst, wire.MajorText, uint64(len(s)))
		return append(dst, s...), nil
	case cbor.KindArray:
		items := v.Array()
		dst = wire.AppendHead(dst, wire.MajorArray, uint64(len(items)))
		var err error
		for _, elem := range items {
			dst, err = encode(dst, elem, opts)
			if err != nil {
				return dst, err
			}
		}
		return dst, nil
	case cbor.KindMap:
		return encodeMap(dst, v.Map(), opts)
	case cbor.KindTag:
		inner := v.TagInner()
		if inner.IsZero() {
			return dst, fmt.Errorf("encode tag %d: inner is %w", v.TagID(), cbor.ErrNilValue)
		}
		dst = wire.AppendHead(dst, wire.MajorTag, v.TagID())
		return encode(dst, inner, opts)
	case cbor.KindBool:
		if v.BoolVal() {
			return append(dst, wire.SimpleTrue), nil
		}
		return append(dst, wire.SimpleFalse), nil
	case cbor.KindNull:
		return append(dst, wire.SimpleNull), nil
	case cbor.KindUndefined:
		return append(dst, wire.SimpleUndefined), nil
	case cbor.KindSimple:
		sv := v.SimpleVal()
		if sv < 24 {
			return append(dst, wire.MajorOther|sv), nil
		}
		return append(dst, wire.SimpleOneByte, sv), nil
	case cbor.KindFloat32:
		return encodeFloat32(dst, v.Float32Val(), opts)
	case cbor.KindFloat64:
		return encodeFloat64(dst, v.Float64Val(), opts)
	default:
		return dst, fmt.Errorf("encode: unsupported Value kind %d", v.Kind())
	}
}

func encodeFloat32(dst []byte, val float32, opts EncodeOpts) ([]byte, error) {
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
		return wire.AppendFloat32(dst, val), nil
	default:
		return wire.AppendFloat32(dst, val), nil
	}
}

func encodeFloat64(dst []byte, val float64, opts EncodeOpts) ([]byte, error) {
	f := val
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

func appendShortestFloat(dst []byte, f float64, _ EncodeOpts) []byte {
	if bits, ok := wire.EncodeFloat16(f); ok {
		return wire.AppendFloat16(dst, bits)
	}
	if wire.CanFloat32Lossless(f) {
		return wire.AppendFloat32(dst, float32(f))
	}
	return wire.AppendFloat64(dst, f)
}

func encodeMap(dst []byte, m []cbor.MapEntry, opts EncodeOpts) ([]byte, error) {
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

	for i, entry := range m {
		start := len(ss.keyBuf)
		var err error
		ss.keyBuf, err = encode(ss.keyBuf, entry.Key, opts)
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
		return bytes.Compare(ea, eb)
	})

	var err error
	for _, se := range entries {
		dst = append(dst, keyBuf[se.keyStart:se.keyEnd]...)
		dst, err = encode(dst, m[se.index].Value, opts)
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
