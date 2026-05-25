// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"fmt"
	"math"
	"sync"
	"unicode/utf8"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/wire"
)

const dedupThreshold = 16

type keyDedup struct {
	seen map[uint64][]int
}

var keyDedupPool = sync.Pool{
	New: func() any { return &keyDedup{seen: make(map[uint64][]int, 32)} },
}

func (kd *keyDedup) reset() {
	clear(kd.seen)
}

func fnv1a(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

type DecodeOpts struct {
	RejectIndefiniteLength bool
	RejectNonShortest      bool
	RejectInvalidUTF8      bool
	RejectDuplicateMapKeys bool
	RejectUnknownTags      bool
	RejectNonFiniteFloats  bool
	RejectNullMapKeys      bool

	MaxNestingDepth     int
	MaxArrayLength      int
	MaxByteStringLength int

	Budget   *BudgetState
	Interner *StringInterner
	Arena    *Arena
	ZeroCopy bool
}

type BudgetState struct {
	Allocated int
	Limit     int
}

func NewBudget(limit int) *BudgetState {
	return &BudgetState{Limit: limit}
}

func (bs *BudgetState) charge(n int) error {
	if bs == nil {
		return nil
	}
	bs.Allocated += n
	if bs.Allocated > bs.Limit {
		return fmt.Errorf("%w: used %d, limit %d", cbor.ErrMemoryBudgetExceeded, bs.Allocated, bs.Limit)
	}
	return nil
}

func StrictOpts() DecodeOpts {
	return DecodeOpts{
		RejectIndefiniteLength: true,
		RejectNonShortest:      true,
		RejectInvalidUTF8:      true,
		RejectDuplicateMapKeys: true,
		RejectUnknownTags:      true,
		RejectNonFiniteFloats:  true,
		RejectNullMapKeys:      true,
	}
}

func (o DecodeOpts) maxNesting() int {
	if o.MaxNestingDepth > 0 {
		return o.MaxNestingDepth
	}
	return 256
}

func (o DecodeOpts) maxArray() int {
	if o.MaxArrayLength > 0 {
		return o.MaxArrayLength
	}
	return 1 << 20
}

func (o DecodeOpts) maxBytes() int {
	if o.MaxByteStringLength > 0 {
		return o.MaxByteStringLength
	}
	return 16 << 20
}

func Decode(src []byte, opts DecodeOpts) (cbor.Value, int, error) {
	return decodeValue(src, 0, 0, opts, true)
}

var knownTags = map[uint64]bool{
	55799: true,
}

func decodeValue(src []byte, off, depth int, opts DecodeOpts, stripSelfDescribe bool) (cbor.Value, int, error) {
	if off >= len(src) {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
	}

	h := wire.ParseHead(src[off:])
	if h.N == 0 {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
	}

	if h.AI >= 28 && h.AI <= 30 {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrReservedAI, off)
	}

	if opts.RejectNonShortest && h.AI >= wire.AI1Byte && h.AI <= wire.AI8Bytes && !h.IsShortest() {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrNonShortest, off)
	}

	switch h.Major {
	case wire.MajorUint:
		return cbor.Uint(h.Arg), off + h.N, nil
	case wire.MajorNegInt:
		return cbor.NegInt(h.Arg), off + h.N, nil
	case wire.MajorBytes:
		return decodeBytes(src, off, h, opts)
	case wire.MajorText:
		return decodeText(src, off, h, opts)
	case wire.MajorArray:
		return decodeArray(src, off, h, depth, opts)
	case wire.MajorMap:
		return decodeMap(src, off, h, depth, opts)
	case wire.MajorTag:
		return decodeTag(src, off, h, depth, opts, stripSelfDescribe)
	case wire.MajorOther:
		return decodeOther(src, off, h, opts)
	default:
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
	}
}

func decodeBytes(src []byte, off int, h wire.HeadResult, opts DecodeOpts) (cbor.Value, int, error) {
	if h.AI == wire.AIIndefinite {
		if opts.RejectIndefiniteLength {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrIndefiniteLength, off)
		}
		return decodeIndefiniteBytes(src, off+h.N, opts)
	}
	if h.Arg > uint64(opts.maxBytes()) {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrMaxByteStringLength, off)
	}
	length := int(h.Arg)
	start := off + h.N
	end := start + length
	if end > len(src) {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
	}
	if err := opts.Budget.charge(length); err != nil {
		return cbor.Value{}, off, err
	}
	if opts.ZeroCopy {
		return cbor.Bytes(src[start:end]), end, nil
	}
	buf := make([]byte, length)
	copy(buf, src[start:end])
	return cbor.Bytes(buf), end, nil
}

func decodeIndefiniteBytes(src []byte, off int, opts DecodeOpts) (cbor.Value, int, error) {
	var buf []byte
	for {
		if off >= len(src) {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
		}
		if src[off] == wire.BreakCode {
			return cbor.Bytes(buf), off + 1, nil
		}
		h := wire.ParseHead(src[off:])
		if h.N == 0 {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
		}
		if h.Major != wire.MajorBytes || h.AI == wire.AIIndefinite {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
		}
		if h.AI >= 28 && h.AI <= 30 {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrReservedAI, off)
		}
		if opts.RejectNonShortest && h.AI >= wire.AI1Byte && h.AI <= wire.AI8Bytes && !h.IsShortest() {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrNonShortest, off)
		}
		if h.Arg > uint64(opts.maxBytes()) {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrMaxByteStringLength, off)
		}
		length := int(h.Arg)
		if int64(len(buf))+int64(length) > int64(opts.maxBytes()) {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrMaxByteStringLength, off)
		}
		start := off + h.N
		end := start + length
		if end > len(src) {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
		}
		buf = append(buf, src[start:end]...)
		off = end
	}
}

func decodeText(src []byte, off int, h wire.HeadResult, opts DecodeOpts) (cbor.Value, int, error) {
	if h.AI == wire.AIIndefinite {
		if opts.RejectIndefiniteLength {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrIndefiniteLength, off)
		}
		return decodeIndefiniteText(src, off+h.N, opts)
	}
	if h.Arg > uint64(opts.maxBytes()) {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrMaxByteStringLength, off)
	}
	length := int(h.Arg)
	start := off + h.N
	end := start + length
	if end > len(src) {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
	}
	if opts.RejectInvalidUTF8 && !utf8.Valid(src[start:end]) {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrInvalidUTF8, off)
	}
	if err := opts.Budget.charge(length); err != nil {
		return cbor.Value{}, off, err
	}
	var s string
	if opts.ZeroCopy {
		s = zeroCopyString(src, start, end)
	} else if opts.Interner != nil {
		s = opts.Interner.Intern(src[start:end])
	} else {
		s = string(src[start:end])
	}
	return cbor.Text(s), end, nil
}

func decodeIndefiniteText(src []byte, off int, opts DecodeOpts) (cbor.Value, int, error) {
	var buf []byte
	for {
		if off >= len(src) {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
		}
		if src[off] == wire.BreakCode {
			s := string(buf)
			if opts.RejectInvalidUTF8 && !utf8.ValidString(s) {
				return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrInvalidUTF8, off)
			}
			return cbor.Text(s), off + 1, nil
		}
		h := wire.ParseHead(src[off:])
		if h.N == 0 {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
		}
		if h.Major != wire.MajorText || h.AI == wire.AIIndefinite {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
		}
		if h.AI >= 28 && h.AI <= 30 {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrReservedAI, off)
		}
		if opts.RejectNonShortest && h.AI >= wire.AI1Byte && h.AI <= wire.AI8Bytes && !h.IsShortest() {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrNonShortest, off)
		}
		if h.Arg > uint64(opts.maxBytes()) {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrMaxByteStringLength, off)
		}
		length := int(h.Arg)
		if int64(len(buf))+int64(length) > int64(opts.maxBytes()) {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrMaxByteStringLength, off)
		}
		start := off + h.N
		end := start + length
		if end > len(src) {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
		}
		buf = append(buf, src[start:end]...)
		off = end
	}
}

func decodeArray(src []byte, off int, h wire.HeadResult, depth int, opts DecodeOpts) (cbor.Value, int, error) {
	if h.AI == wire.AIIndefinite {
		if opts.RejectIndefiniteLength {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrIndefiniteLength, off)
		}
		return decodeIndefiniteArray(src, off+h.N, depth, opts)
	}
	count := int(h.Arg)
	if h.Arg > uint64(opts.maxArray()) || count < 0 {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrMaxArrayLength, off)
	}
	if err := opts.Budget.charge(count * 16); err != nil {
		return cbor.Value{}, off, err
	}
	var arr []cbor.Value
	if opts.Arena != nil {
		arr = opts.Arena.AllocValues(count)
	} else {
		arr = make([]cbor.Value, count)
	}
	pos := off + h.N
	childDepth := depth + 1
	if childDepth > opts.maxNesting() {
		return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrMaxNestingDepth, pos)
	}
	if count == 0 {
		return cbor.MakeArrayFromSlice(arr), pos, nil
	}
	srcLen := len(src)
	_ = arr[count-1]
	for i := range count {
		if pos >= srcLen {
			return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		ib := src[pos]

		if ib < 0x40 {
			var arg uint64
			var n int
			ai := ib & 0x1f
			switch {
			case ai < 24:
				arg = uint64(ai)
				n = 1
			case ai == 24:
				if pos+1 >= srcLen {
					return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
				}
				arg = uint64(src[pos+1])
				n = 2
				if opts.RejectNonShortest && arg < 24 {
					return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrNonShortest, pos)
				}
			case ai == 25:
				if pos+2 >= srcLen {
					return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
				}
				arg = uint64(src[pos+1])<<8 | uint64(src[pos+2])
				n = 3
				if opts.RejectNonShortest && arg <= 0xff {
					return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrNonShortest, pos)
				}
			case ai == 26:
				if pos+4 >= srcLen {
					return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
				}
				arg = uint64(src[pos+1])<<24 | uint64(src[pos+2])<<16 | uint64(src[pos+3])<<8 | uint64(src[pos+4])
				n = 5
				if opts.RejectNonShortest && arg <= 0xffff {
					return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrNonShortest, pos)
				}
			case ai == 27:
				if pos+8 >= srcLen {
					return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
				}
				arg = uint64(src[pos+1])<<56 | uint64(src[pos+2])<<48 | uint64(src[pos+3])<<40 | uint64(src[pos+4])<<32 |
					uint64(src[pos+5])<<24 | uint64(src[pos+6])<<16 | uint64(src[pos+7])<<8 | uint64(src[pos+8])
				n = 9
				if opts.RejectNonShortest && arg <= 0xffffffff {
					return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrNonShortest, pos)
				}
			default:
				if ai >= 28 && ai <= 30 {
					return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrReservedAI, pos)
				}
				v, next, err := decodeValue(src, pos, childDepth, opts, false)
				if err != nil {
					return cbor.Value{}, next, err
				}
				arr[i] = v
				pos = next
				continue
			}
			if ib < 0x20 {
				arr[i] = cbor.Uint(arg)
			} else {
				arr[i] = cbor.NegInt(arg)
			}
			pos += n
			continue
		}

		// Inline fast-path: short text (major 3, AI < 24)
		if ib&0xe0 == 0x60 && ib&0x1f < 24 {
			length := int(ib & 0x1f)
			end := pos + 1 + length
			if end <= srcLen {
				if opts.RejectInvalidUTF8 && !utf8.Valid(src[pos+1:end]) {
					return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrInvalidUTF8, pos)
				}
				var s string
				if opts.Interner != nil {
					s = opts.Interner.Intern(src[pos+1 : end])
				} else if opts.ZeroCopy {
					s = zeroCopyString(src, pos+1, end)
				} else {
					s = string(src[pos+1 : end])
				}
				arr[i] = cbor.Text(s)
				pos = end
				continue
			}
		}

		// Inline fast-path: short bytes (major 2, AI < 24)
		if ib&0xe0 == 0x40 && ib&0x1f < 24 {
			length := int(ib & 0x1f)
			end := pos + 1 + length
			if end <= srcLen {
				if opts.ZeroCopy {
					arr[i] = cbor.Bytes(src[pos+1 : end])
				} else {
					buf := make([]byte, length)
					copy(buf, src[pos+1:end])
					arr[i] = cbor.Bytes(buf)
				}
				pos = end
				continue
			}
		}

		// Inline fast-path: simple values (bool, null, undefined)
		if ib == wire.SimpleTrue {
			arr[i] = cbor.Bool(true)
			pos++
			continue
		}
		if ib == wire.SimpleFalse {
			arr[i] = cbor.Bool(false)
			pos++
			continue
		}
		if ib == wire.SimpleNull {
			arr[i] = cbor.Null()
			pos++
			continue
		}
		if ib == wire.SimpleUndefined {
			arr[i] = cbor.Undefined()
			pos++
			continue
		}

		v, next, err := decodeValue(src, pos, childDepth, opts, false)
		if err != nil {
			return cbor.Value{}, next, err
		}
		arr[i] = v
		pos = next
	}
	return cbor.MakeArrayFromSlice(arr), pos, nil
}

func decodeIndefiniteArray(src []byte, off, depth int, opts DecodeOpts) (cbor.Value, int, error) {
	if depth+1 > opts.maxNesting() {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrMaxNestingDepth, off)
	}
	var arr []cbor.Value
	pos := off
	for {
		if pos >= len(src) {
			return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		if src[pos] == wire.BreakCode {
			if arr == nil {
				arr = []cbor.Value{}
			}
			return cbor.MakeArrayFromSlice(arr), pos + 1, nil
		}
		if len(arr) >= opts.maxArray() {
			return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrMaxArrayLength, pos)
		}
		v, next, err := decodeValue(src, pos, depth+1, opts, false)
		if err != nil {
			return cbor.Value{}, next, err
		}
		arr = append(arr, v)
		pos = next
	}
}

func decodeMap(src []byte, off int, h wire.HeadResult, depth int, opts DecodeOpts) (cbor.Value, int, error) {
	if h.AI == wire.AIIndefinite {
		if opts.RejectIndefiniteLength {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrIndefiniteLength, off)
		}
		return decodeIndefiniteMap(src, off+h.N, depth, opts)
	}
	count := int(h.Arg)
	if h.Arg > uint64(opts.maxArray()) || count < 0 {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrMaxArrayLength, off)
	}
	if depth+1 > opts.maxNesting() {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrMaxNestingDepth, off)
	}

	var dedup *keyDedup
	if count > dedupThreshold {
		dedup = keyDedupPool.Get().(*keyDedup)
		dedup.reset()
		defer keyDedupPool.Put(dedup)
	}

	if err := opts.Budget.charge(count * 32); err != nil {
		return cbor.Value{}, off, err
	}
	var m []cbor.MapEntry
	if opts.Arena != nil {
		m = opts.Arena.AllocPairs(count)[:0]
	} else {
		m = make([]cbor.MapEntry, 0, count)
	}
	pos := off + h.N
	for range count {
		keyOff := pos

		// Inline fast-path: short definite-length text key (covers >90% of real map keys)
		var k cbor.Value
		var encodedKey []byte
		if pos < len(src) && src[pos]&0xe0 == 0x60 && src[pos]&0x1f < 24 {
			length := int(src[pos] & 0x1f)
			end := pos + 1 + length
			if end <= len(src) {
				raw := src[pos:end]
				var s string
				if opts.RejectInvalidUTF8 && !utf8.Valid(src[pos+1:end]) {
					return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrInvalidUTF8, pos)
				}
				if opts.RejectNonShortest {
					// AI < 24 is always shortest for text
				}
				if opts.Interner != nil {
					s = opts.Interner.Intern(src[pos+1 : end])
				} else if opts.ZeroCopy {
					s = zeroCopyString(src, pos+1, end)
				} else {
					s = string(src[pos+1 : end])
				}
				k = cbor.Text(s)
				encodedKey = raw
				pos = end
				goto keyDone
			}
		}
		{
			var next int
			var err error
			k, next, err = decodeValue(src, pos, depth+1, opts, false)
			if err != nil {
				return cbor.Value{}, next, err
			}
			encodedKey = src[keyOff:next]
			pos = next
		}
	keyDone:
		if opts.RejectNullMapKeys {
			if k.Kind == cbor.KindNull {
				return cbor.Value{}, keyOff, fmt.Errorf("%w at offset %d", cbor.ErrNullMapKey, keyOff)
			}
		}
		v, next, err := decodeValue(src, pos, depth+1, opts, false)
		if err != nil {
			return cbor.Value{}, next, err
		}
		pos = next
		m, err = mapInsert(m, k, v, keyOff, encodedKey, dedup, opts)
		if err != nil {
			return cbor.Value{}, keyOff, err
		}
	}
	return cbor.MakeMapFromSlice(m), pos, nil
}

func decodeIndefiniteMap(src []byte, off, depth int, opts DecodeOpts) (cbor.Value, int, error) {
	if depth+1 > opts.maxNesting() {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrMaxNestingDepth, off)
	}
	var m []cbor.MapEntry
	pos := off
	for {
		if pos >= len(src) {
			return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		if src[pos] == wire.BreakCode {
			if m == nil {
				m = []cbor.MapEntry{}
			}
			return cbor.MakeMapFromSlice(m), pos + 1, nil
		}
		if len(m) >= opts.maxArray() {
			return cbor.Value{}, pos, fmt.Errorf("%w at offset %d", cbor.ErrMaxArrayLength, pos)
		}
		keyOff := pos
		k, next, err := decodeValue(src, pos, depth+1, opts, false)
		if err != nil {
			return cbor.Value{}, next, err
		}
		encodedKey := src[keyOff:next]
		pos = next
		if opts.RejectNullMapKeys {
			if k.Kind == cbor.KindNull {
				return cbor.Value{}, keyOff, fmt.Errorf("%w at offset %d", cbor.ErrNullMapKey, keyOff)
			}
		}
		v, next, err := decodeValue(src, pos, depth+1, opts, false)
		if err != nil {
			return cbor.Value{}, next, err
		}
		pos = next
		m, err = mapInsert(m, k, v, keyOff, encodedKey, nil, opts)
		if err != nil {
			return cbor.Value{}, keyOff, err
		}
	}
}

func mapInsert(m []cbor.MapEntry, key, val cbor.Value, keyOff int, encodedKey []byte, dedup *keyDedup, opts DecodeOpts) ([]cbor.MapEntry, error) {
	if opts.RejectDuplicateMapKeys {
		if dedup != nil {
			h := fnv1a(encodedKey)
			for _, idx := range dedup.seen[h] {
				if valuesEqual(m[idx].Key, key) {
					return m, fmt.Errorf("%w at offset %d", cbor.ErrDuplicateMapKey, keyOff)
				}
			}
			dedup.seen[h] = append(dedup.seen[h], len(m))
		} else {
			for _, entry := range m {
				if valuesEqual(entry.Key, key) {
					return m, fmt.Errorf("%w at offset %d", cbor.ErrDuplicateMapKey, keyOff)
				}
			}
		}
		m = append(m, cbor.MapEntry{Key: key, Value: val})
		return m, nil
	}
	if dedup != nil {
		h := fnv1a(encodedKey)
		for _, idx := range dedup.seen[h] {
			if valuesEqual(m[idx].Key, key) {
				m[idx].Value = val
				return m, nil
			}
		}
		dedup.seen[h] = append(dedup.seen[h], len(m))
	} else {
		for i, entry := range m {
			if valuesEqual(entry.Key, key) {
				m[i].Value = val
				return m, nil
			}
		}
	}
	m = append(m, cbor.MapEntry{Key: key, Value: val})
	return m, nil
}

func valuesEqual(a, b cbor.Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case cbor.KindUint:
		return a.UintVal() == b.UintVal()
	case cbor.KindNegInt:
		return a.NegIntVal() == b.NegIntVal()
	case cbor.KindBytes:
		ab, bb := a.BytesVal(), b.BytesVal()
		if len(ab) != len(bb) {
			return false
		}
		for i := range ab {
			if ab[i] != bb[i] {
				return false
			}
		}
		return true
	case cbor.KindText:
		return a.TextVal() == b.TextVal()
	case cbor.KindBool:
		return a.BoolVal() == b.BoolVal()
	case cbor.KindNull:
		return true
	case cbor.KindUndefined:
		return true
	case cbor.KindSimple:
		return a.SimpleVal() == b.SimpleVal()
	case cbor.KindFloat32:
		return a.Float32Val() == b.Float32Val()
	case cbor.KindFloat64:
		return a.Float64Val() == b.Float64Val()
	default:
		return false
	}
}

func decodeTag(src []byte, off int, h wire.HeadResult, depth int, opts DecodeOpts, stripSelfDescribe bool) (cbor.Value, int, error) {
	tagID := h.Arg
	pos := off + h.N

	if opts.RejectUnknownTags && !knownTags[tagID] {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrUnknownTag, off)
	}

	if tagID == 55799 && stripSelfDescribe {
		return decodeValue(src, pos, depth, opts, true)
	}

	if depth+1 > opts.maxNesting() {
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrMaxNestingDepth, off)
	}
	inner, next, err := decodeValue(src, pos, depth+1, opts, false)
	if err != nil {
		return cbor.Value{}, next, err
	}
	return cbor.MakeTag(tagID, inner), next, nil
}

func decodeOther(src []byte, off int, h wire.HeadResult, opts DecodeOpts) (cbor.Value, int, error) {
	ai := h.AI
	switch {
	case ai < 20:
		return cbor.Simple(ai), off + h.N, nil
	case ai == 20:
		return cbor.Bool(false), off + h.N, nil
	case ai == 21:
		return cbor.Bool(true), off + h.N, nil
	case ai == 22:
		return cbor.Null(), off + h.N, nil
	case ai == 23:
		return cbor.Undefined(), off + h.N, nil
	case ai == wire.AI1Byte:
		sv := uint8(h.Arg)
		if sv < 32 {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrNonShortest, off)
		}
		return cbor.Simple(sv), off + h.N, nil
	case ai == wire.AI2Bytes:
		bits := uint16(h.Arg)
		f := wire.DecodeFloat16(bits)
		if opts.RejectNonFiniteFloats && (math.IsNaN(f) || math.IsInf(f, 0)) {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrNonFiniteFloat, off)
		}
		return cbor.Float64(f), off + h.N, nil
	case ai == wire.AI4Bytes:
		bits := uint32(h.Arg)
		f := math.Float32frombits(bits)
		if opts.RejectNonFiniteFloats && (math.IsNaN(float64(f)) || math.IsInf(float64(f), 0)) {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrNonFiniteFloat, off)
		}
		return cbor.Float32(f), off + h.N, nil
	case ai == wire.AI8Bytes:
		f := math.Float64frombits(h.Arg)
		if opts.RejectNonFiniteFloats && (math.IsNaN(f) || math.IsInf(f, 0)) {
			return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrNonFiniteFloat, off)
		}
		return cbor.Float64(f), off + h.N, nil
	case ai == wire.AIIndefinite:
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
	default:
		return cbor.Value{}, off, fmt.Errorf("%w at offset %d", cbor.ErrReservedAI, off)
	}
}
