// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"fmt"
	"math"
	"slices"
	"unicode/utf8"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/internal/decerr"
	"github.com/jahkeup/corecbor/wire"
)

const dedupThreshold = 16

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
	// ReplaceInvalidUTF8 substitutes U+FFFD per invalid byte in decoded
	// text strings (InvalidUTF8Replace, proposal 035). Ignored when
	// RejectInvalidUTF8 is set.
	ReplaceInvalidUTF8 bool

	MaxNestingDepth     int
	MaxArrayLength      int
	MaxByteStringLength int

	// AllowedTags, when non-nil, is the set of tag numbers accepted
	// under RejectUnknownTags; tag 55799 (self-describe) is always
	// accepted. Nil means the tags the library models
	// (encoder-decoder-spec.md §4.3).
	AllowedTags *TagSet

	// ErrorPath makes every DecodeError carry Path, the location of the
	// offending item ("$[2].foo"). It costs nothing on the success path.
	ErrorPath bool

	Budget   *BudgetState
	Interner *StringInterner
	Arena    *Arena
	ZeroCopy bool

	// KeyIdentity selects when two map keys are the same key for
	// duplicate handling (proposal 024). The zero value is
	// KeyIdentityValue (RFC 8949 §5.6.1 data model).
	KeyIdentity KeyIdentity
	// KeepDuplicateMapKeys keeps every map entry in input order instead
	// of resolving repeats last-write-wins. It conflicts with
	// RejectDuplicateMapKeys (ErrInvalidOption).
	KeepDuplicateMapKeys bool
	// LegacyFloatKeyEquality compares float map keys as v0.2.2 did
	// (same Kind and ==) instead of per RFC 8949 erratum 8589.
	//
	// Deprecated: v0.2 compatibility only; removed no earlier than v0.32.0.
	LegacyFloatKeyEquality bool

	// Checking decoder (proposal 024). These run after a successful
	// decode, over the item's bytes.
	//
	// RequirePreferred rejects input not in RFC 8949 §4.1 preferred
	// serialization: non-shortest arguments, floats not in the shortest
	// width that preserves the value (NaN payload included), indefinite
	// lengths, and tag 2/3 bignums with leading zeros or that fit major
	// type 0/1 (§3.4.3). Errors wrap ErrNotPreferred.
	RequirePreferred bool
	// RequireSortedMapKeys rejects maps whose keys are not in strictly
	// increasing bytewise-lexicographic order of their encodings (RFC
	// 8949 §4.2.1), which also rejects duplicates. Errors wrap
	// ErrNotDeterministic.
	RequireSortedMapKeys bool
	// RequireCanonicalNaN rejects any NaN other than f97e00
	// (draft-ietf-cbor-serialization-13 §4; Experimental). Errors wrap
	// ErrNotPreferred.
	RequireCanonicalNaN bool

	// spans, when non-nil, receives the entry spans of the next map
	// decoded (MapEntrySpans). Maps clear it before decoding children.
	spans *[]EntrySpan

	// reserve is the number of input bytes that enclosing containers
	// still need for their own pending items. A nested container may
	// only claim the bytes beyond it, which bounds total preallocation
	// across the whole nesting stack by the input length.
	reserve int
}

// avail returns the input bytes available to the item starting at pos
// after setting aside what enclosing containers still need.
func (o DecodeOpts) avail(src []byte, pos int) int {
	return len(src) - pos - o.reserve
}

type BudgetState struct {
	Allocated int
	Limit     int
}

func NewBudget(limit int) *BudgetState {
	return &BudgetState{Limit: limit}
}

// charge records n bytes of allocation for the item at off. The
// message keeps its v0.2.2 text (no offset); the offset is available
// through the DecodeError.
func (bs *BudgetState) charge(n, off int) error {
	if bs == nil {
		return nil
	}
	bs.Allocated += n
	if bs.Allocated > bs.Limit {
		return decerr.Text(cbor.ErrMemoryBudgetExceeded, off,
			fmt.Sprintf("%s: used %d, limit %d", cbor.ErrMemoryBudgetExceeded, bs.Allocated, bs.Limit))
	}
	return nil
}

func StrictOpts() DecodeOpts {
	return DecodeOpts{
		RejectIndefiniteLength: true,
		RejectNonShortest:      true,
		RejectInvalidUTF8:      true,
		RejectDuplicateMapKeys: true,
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
	if opts.KeepDuplicateMapKeys && opts.RejectDuplicateMapKeys {
		return cbor.Value{}, 0, decodeErrDetail(cbor.ErrInvalidOption, 0, ": KeepDuplicateMapKeys with RejectDuplicateMapKeys")
	}
	v, n, err := decodeValue(src, 0, 0, opts, true)
	if err != nil && opts.ErrorPath {
		err = withPath(err, "$")
	}
	if err == nil && (opts.RequirePreferred || opts.RequireSortedMapKeys || opts.RequireCanonicalNaN) {
		if err := checkSerialization(src[:n], opts); err != nil {
			return cbor.Value{}, 0, err
		}
	}
	return v, n, err
}

// DecodeNested decodes one item from the start of src the way Decode
// decodes it when nested inside a larger item: leading self-describe
// tags (55799) are kept as tags instead of stripped. Use it to decode a
// sub-item's source bytes and get the same Value Decode produced for it
// inside its parent.
func DecodeNested(src []byte, opts DecodeOpts) (cbor.Value, int, error) {
	return decodeValue(src, 0, 0, opts, false)
}

// modeledTags are the tags encoder-decoder-spec.md §4.3 says the library
// models; RejectUnknownTags with no AllowedTags accepts exactly these.
var modeledTags = map[uint64]struct{}{
	0: {}, 1: {}, 2: {}, 3: {}, 21: {}, 22: {}, 23: {}, 24: {},
	32: {}, 35: {}, 258: {}, cbor.TagSelfDescribe: {},
}

// TagSet is an immutable set of tag numbers, used as
// DecodeOpts.AllowedTags. It is a pointer type so DecodeOpts stays
// comparable.
type TagSet struct {
	m map[uint64]struct{}
}

// NewTagSet returns a set holding ids.
func NewTagSet(ids ...uint64) *TagSet {
	s := &TagSet{m: make(map[uint64]struct{}, len(ids))}
	for _, id := range ids {
		s.m[id] = struct{}{}
	}
	return s
}

// Contains reports whether id is in the set. A nil set is empty.
func (s *TagSet) Contains(id uint64) bool {
	if s == nil {
		return false
	}
	_, ok := s.m[id]
	return ok
}

// IDs returns the set's tag numbers in ascending order.
func (s *TagSet) IDs() []uint64 {
	if s == nil {
		return nil
	}
	ids := make([]uint64, 0, len(s.m))
	for id := range s.m {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// tagAllowed reports whether tag id passes the RejectUnknownTags policy.
func (o *DecodeOpts) tagAllowed(id uint64) bool {
	if !o.RejectUnknownTags || id == cbor.TagSelfDescribe {
		return true
	}
	if o.AllowedTags != nil {
		return o.AllowedTags.Contains(id)
	}
	_, ok := modeledTags[id]
	return ok
}

func decodeValue(src []byte, off, depth int, opts DecodeOpts, stripSelfDescribe bool) (cbor.Value, int, error) {
	if off >= len(src) {
		return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
	}

	h := wire.ParseHead(src[off:])
	if h.N == 0 {
		return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
	}

	if h.AI >= 28 && h.AI <= 30 {
		return cbor.Value{}, off, decodeErr(cbor.ErrReservedAI, off)
	}
	// Indefinite length (AI 31) is not well-formed for integers and tags
	// (RFC 8949 §3.2.4); ParseHead reports it with Arg 0.
	if h.AI == wire.AIIndefinite && (h.Major == wire.MajorUint || h.Major == wire.MajorNegInt || h.Major == wire.MajorTag) {
		return cbor.Value{}, off, decerr.Text(cbor.ErrReservedAI, off, fmt.Sprintf("%s (indefinite length for major type %d) at offset %d", cbor.ErrReservedAI, h.Major>>5, off))
	}

	if opts.RejectNonShortest && h.AI >= wire.AI1Byte && h.AI <= wire.AI8Bytes && !h.IsShortest() {
		return cbor.Value{}, off, decodeErr(cbor.ErrNonShortest, off)
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
		return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
	}
}

func decodeBytes(src []byte, off int, h wire.HeadResult, opts DecodeOpts) (cbor.Value, int, error) {
	if h.AI == wire.AIIndefinite {
		if opts.RejectIndefiniteLength {
			return cbor.Value{}, off, decodeErr(cbor.ErrIndefiniteLength, off)
		}
		return decodeIndefiniteBytes(src, off+h.N, opts)
	}
	if h.Arg > uint64(opts.maxBytes()) {
		return cbor.Value{}, off, decodeErr(cbor.ErrMaxByteStringLength, off)
	}
	length := int(h.Arg)
	start := off + h.N
	end := start + length
	if end > len(src) {
		return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
	}
	if err := opts.Budget.charge(length, off); err != nil {
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
			return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
		}
		if src[off] == wire.BreakCode {
			return cbor.Bytes(buf), off + 1, nil
		}
		h := wire.ParseHead(src[off:])
		if h.N == 0 {
			return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
		}
		if h.Major != wire.MajorBytes || h.AI == wire.AIIndefinite {
			return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
		}
		if h.AI >= 28 && h.AI <= 30 {
			return cbor.Value{}, off, decodeErr(cbor.ErrReservedAI, off)
		}
		if opts.RejectNonShortest && h.AI >= wire.AI1Byte && h.AI <= wire.AI8Bytes && !h.IsShortest() {
			return cbor.Value{}, off, decodeErr(cbor.ErrNonShortest, off)
		}
		if h.Arg > uint64(opts.maxBytes()) {
			return cbor.Value{}, off, decodeErr(cbor.ErrMaxByteStringLength, off)
		}
		length := int(h.Arg)
		if int64(len(buf))+int64(length) > int64(opts.maxBytes()) {
			return cbor.Value{}, off, decodeErr(cbor.ErrMaxByteStringLength, off)
		}
		start := off + h.N
		end := start + length
		if end > len(src) {
			return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
		}
		buf = append(buf, src[start:end]...)
		off = end
	}
}

func decodeText(src []byte, off int, h wire.HeadResult, opts DecodeOpts) (cbor.Value, int, error) {
	if h.AI == wire.AIIndefinite {
		if opts.RejectIndefiniteLength {
			return cbor.Value{}, off, decodeErr(cbor.ErrIndefiniteLength, off)
		}
		return decodeIndefiniteText(src, off+h.N, opts)
	}
	if h.Arg > uint64(opts.maxBytes()) {
		return cbor.Value{}, off, decodeErr(cbor.ErrMaxByteStringLength, off)
	}
	length := int(h.Arg)
	start := off + h.N
	end := start + length
	if end > len(src) {
		return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
	}
	if opts.RejectInvalidUTF8 && !utf8.Valid(src[start:end]) {
		return cbor.Value{}, off, decodeErr(cbor.ErrInvalidUTF8, off)
	}
	if err := opts.Budget.charge(length, off); err != nil {
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
	return cbor.Text(replaceInvalidText(s, &opts)), end, nil
}

func decodeIndefiniteText(src []byte, off int, opts DecodeOpts) (cbor.Value, int, error) {
	var buf []byte
	for {
		if off >= len(src) {
			return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
		}
		if src[off] == wire.BreakCode {
			s := string(buf)
			if opts.RejectInvalidUTF8 && !utf8.ValidString(s) {
				return cbor.Value{}, off, decodeErr(cbor.ErrInvalidUTF8, off)
			}
			return cbor.Text(replaceInvalidText(s, &opts)), off + 1, nil
		}
		h := wire.ParseHead(src[off:])
		if h.N == 0 {
			return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
		}
		if h.Major != wire.MajorText || h.AI == wire.AIIndefinite {
			return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
		}
		if h.AI >= 28 && h.AI <= 30 {
			return cbor.Value{}, off, decodeErr(cbor.ErrReservedAI, off)
		}
		if opts.RejectNonShortest && h.AI >= wire.AI1Byte && h.AI <= wire.AI8Bytes && !h.IsShortest() {
			return cbor.Value{}, off, decodeErr(cbor.ErrNonShortest, off)
		}
		if h.Arg > uint64(opts.maxBytes()) {
			return cbor.Value{}, off, decodeErr(cbor.ErrMaxByteStringLength, off)
		}
		length := int(h.Arg)
		if int64(len(buf))+int64(length) > int64(opts.maxBytes()) {
			return cbor.Value{}, off, decodeErr(cbor.ErrMaxByteStringLength, off)
		}
		start := off + h.N
		end := start + length
		if end > len(src) {
			return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
		}
		buf = append(buf, src[start:end]...)
		off = end
	}
}

func decodeArray(src []byte, off int, h wire.HeadResult, depth int, opts DecodeOpts) (cbor.Value, int, error) {
	if h.AI == wire.AIIndefinite {
		if opts.RejectIndefiniteLength {
			return cbor.Value{}, off, decodeErr(cbor.ErrIndefiniteLength, off)
		}
		return decodeIndefiniteArray(src, off+h.N, depth, opts)
	}
	count := int(h.Arg)
	if h.Arg > uint64(opts.maxArray()) || count < 0 {
		return cbor.Value{}, off, decodeErr(cbor.ErrMaxArrayLength, off)
	}
	pos := off + h.N
	childDepth := depth + 1
	if childDepth > opts.maxNesting() {
		return cbor.Value{}, pos, decodeErr(cbor.ErrMaxNestingDepth, pos)
	}
	// Every element occupies at least one byte, so a count larger than
	// the available input cannot be satisfied. Fail before allocating.
	if count > opts.avail(src, pos) {
		return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
	}
	if err := opts.Budget.charge(count*16, off); err != nil {
		return cbor.Value{}, off, err
	}
	var arr []cbor.Value
	if opts.Arena != nil {
		arr = opts.Arena.AllocValues(count)
	} else {
		arr = make([]cbor.Value, count)
	}
	if count == 0 {
		return cbor.MakeArrayFromSlice(arr), pos, nil
	}
	srcLen := len(src)
	_ = arr[count-1]
	for i := range count {
		if pos >= srcLen {
			return cbor.Value{}, pos, indexPath(decodeErr(cbor.ErrTruncated, pos), opts, i)
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
					return cbor.Value{}, pos, indexPath(decodeErr(cbor.ErrTruncated, pos), opts, i)
				}
				arg = uint64(src[pos+1])
				n = 2
				if opts.RejectNonShortest && arg < 24 {
					return cbor.Value{}, pos, indexPath(decodeErr(cbor.ErrNonShortest, pos), opts, i)
				}
			case ai == 25:
				if pos+2 >= srcLen {
					return cbor.Value{}, pos, indexPath(decodeErr(cbor.ErrTruncated, pos), opts, i)
				}
				arg = uint64(src[pos+1])<<8 | uint64(src[pos+2])
				n = 3
				if opts.RejectNonShortest && arg <= 0xff {
					return cbor.Value{}, pos, indexPath(decodeErr(cbor.ErrNonShortest, pos), opts, i)
				}
			case ai == 26:
				if pos+4 >= srcLen {
					return cbor.Value{}, pos, indexPath(decodeErr(cbor.ErrTruncated, pos), opts, i)
				}
				arg = uint64(src[pos+1])<<24 | uint64(src[pos+2])<<16 | uint64(src[pos+3])<<8 | uint64(src[pos+4])
				n = 5
				if opts.RejectNonShortest && arg <= 0xffff {
					return cbor.Value{}, pos, indexPath(decodeErr(cbor.ErrNonShortest, pos), opts, i)
				}
			case ai == 27:
				if pos+8 >= srcLen {
					return cbor.Value{}, pos, indexPath(decodeErr(cbor.ErrTruncated, pos), opts, i)
				}
				arg = uint64(src[pos+1])<<56 | uint64(src[pos+2])<<48 | uint64(src[pos+3])<<40 | uint64(src[pos+4])<<32 |
					uint64(src[pos+5])<<24 | uint64(src[pos+6])<<16 | uint64(src[pos+7])<<8 | uint64(src[pos+8])
				n = 9
				if opts.RejectNonShortest && arg <= 0xffffffff {
					return cbor.Value{}, pos, indexPath(decodeErr(cbor.ErrNonShortest, pos), opts, i)
				}
			default:
				if ai >= 28 && ai <= 30 {
					return cbor.Value{}, pos, indexPath(decodeErr(cbor.ErrReservedAI, pos), opts, i)
				}
				co := opts
				co.reserve += count - i - 1
				v, next, err := decodeValue(src, pos, childDepth, co, false)
				if err != nil {
					return cbor.Value{}, next, indexPath(err, opts, i)
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
					return cbor.Value{}, pos, indexPath(decodeErr(cbor.ErrInvalidUTF8, pos), opts, i)
				}
				var s string
				if opts.Interner != nil {
					s = opts.Interner.Intern(src[pos+1 : end])
				} else if opts.ZeroCopy {
					s = zeroCopyString(src, pos+1, end)
				} else {
					s = string(src[pos+1 : end])
				}
				if opts.ReplaceInvalidUTF8 {
					s = replaceInvalidText(s, &opts)
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

		co := opts
		co.reserve += count - i - 1
		v, next, err := decodeValue(src, pos, childDepth, co, false)
		if err != nil {
			return cbor.Value{}, next, indexPath(err, opts, i)
		}
		arr[i] = v
		pos = next
	}
	return cbor.MakeArrayFromSlice(arr), pos, nil
}

func decodeIndefiniteArray(src []byte, off, depth int, opts DecodeOpts) (cbor.Value, int, error) {
	if depth+1 > opts.maxNesting() {
		return cbor.Value{}, off, decodeErr(cbor.ErrMaxNestingDepth, off)
	}
	var arr []cbor.Value
	pos := off
	for {
		if pos >= len(src) {
			return cbor.Value{}, pos, decodeErr(cbor.ErrTruncated, pos)
		}
		if src[pos] == wire.BreakCode {
			if arr == nil {
				arr = []cbor.Value{}
			}
			return cbor.MakeArrayFromSlice(arr), pos + 1, nil
		}
		if len(arr) >= opts.maxArray() {
			return cbor.Value{}, pos, decodeErr(cbor.ErrMaxArrayLength, pos)
		}
		co := opts
		co.reserve++ // break code
		v, next, err := decodeValue(src, pos, depth+1, co, false)
		if err != nil {
			return cbor.Value{}, next, indexPath(err, opts, len(arr))
		}
		arr = append(arr, v)
		pos = next
	}
}

func decodeMap(src []byte, off int, h wire.HeadResult, depth int, opts DecodeOpts) (cbor.Value, int, error) {
	if h.AI == wire.AIIndefinite {
		if opts.RejectIndefiniteLength {
			return cbor.Value{}, off, decodeErr(cbor.ErrIndefiniteLength, off)
		}
		return decodeIndefiniteMap(src, off+h.N, depth, opts)
	}
	count := int(h.Arg)
	if h.Arg > uint64(opts.maxArray()) || count < 0 {
		return cbor.Value{}, off, decodeErr(cbor.ErrMaxArrayLength, off)
	}
	if depth+1 > opts.maxNesting() {
		return cbor.Value{}, off, decodeErr(cbor.ErrMaxNestingDepth, off)
	}
	// Every pair occupies at least two bytes. Fail before allocating.
	if count > opts.avail(src, off+h.N)/2 {
		return cbor.Value{}, off, decodeErr(cbor.ErrTruncated, off)
	}

	// Span recording (MapEntrySpans) applies to this map only.
	rec := opts.spans
	opts.spans = nil

	ks := getKeySet(count, &opts)
	defer putKeySet(ks)

	if err := opts.Budget.charge(count*32, off); err != nil {
		return cbor.Value{}, off, err
	}
	var m []cbor.MapEntry
	if opts.Arena != nil {
		m = opts.Arena.AllocPairs(count)[:0]
	} else {
		m = make([]cbor.MapEntry, 0, count)
	}
	pos := off + h.N
	for i := range count {
		keyOff := pos
		// Bytes the remaining pairs of this map still need.
		rest := (count - i - 1) * 2

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
					return cbor.Value{}, pos, decodeErr(cbor.ErrInvalidUTF8, pos)
				}
				if opts.Interner != nil {
					s = opts.Interner.Intern(src[pos+1 : end])
				} else if opts.ZeroCopy {
					s = zeroCopyString(src, pos+1, end)
				} else {
					s = string(src[pos+1 : end])
				}
				if opts.ReplaceInvalidUTF8 {
					s = replaceInvalidText(s, &opts)
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
			co := opts
			co.reserve += rest + 1 // this pair's value
			k, next, err = decodeValue(src, pos, depth+1, co, false)
			if err != nil {
				return cbor.Value{}, next, err
			}
			encodedKey = src[keyOff:next]
			pos = next
		}
	keyDone:
		if opts.RejectNullMapKeys {
			if k.Kind == cbor.KindNull {
				return cbor.Value{}, keyOff, decodeErr(cbor.ErrNullMapKey, keyOff)
			}
		}
		valOff := pos
		co := opts
		co.reserve += rest
		v, next, err := decodeValue(src, pos, depth+1, co, false)
		if err != nil {
			return cbor.Value{}, next, keyPath(err, opts, k)
		}
		pos = next
		var idx int
		m, idx, err = mapInsert(m, k, v, keyOff, encodedKey, ks, &opts)
		if err != nil {
			return cbor.Value{}, keyOff, err
		}
		if rec != nil {
			recordSpan(rec, idx, keyOff, valOff, pos)
		}
	}
	return cbor.MakeMapFromSlice(m), pos, nil
}

func decodeIndefiniteMap(src []byte, off, depth int, opts DecodeOpts) (cbor.Value, int, error) {
	if depth+1 > opts.maxNesting() {
		return cbor.Value{}, off, decodeErr(cbor.ErrMaxNestingDepth, off)
	}
	var m []cbor.MapEntry
	rec := opts.spans
	opts.spans = nil
	// Indefinite maps keep the v0.2 linear scan for value identity.
	ks := getKeySet(0, &opts)
	defer putKeySet(ks)
	pos := off
	for {
		if pos >= len(src) {
			return cbor.Value{}, pos, decodeErr(cbor.ErrTruncated, pos)
		}
		if src[pos] == wire.BreakCode {
			if m == nil {
				m = []cbor.MapEntry{}
			}
			return cbor.MakeMapFromSlice(m), pos + 1, nil
		}
		if len(m) >= opts.maxArray() {
			return cbor.Value{}, pos, decodeErr(cbor.ErrMaxArrayLength, pos)
		}
		keyOff := pos
		kOpts := opts
		kOpts.reserve += 2 // this pair's value + break code
		k, next, err := decodeValue(src, pos, depth+1, kOpts, false)
		if err != nil {
			return cbor.Value{}, next, err
		}
		encodedKey := src[keyOff:next]
		pos = next
		if opts.RejectNullMapKeys {
			if k.Kind == cbor.KindNull {
				return cbor.Value{}, keyOff, decodeErr(cbor.ErrNullMapKey, keyOff)
			}
		}
		valOff := pos
		vOpts := opts
		vOpts.reserve++ // break code
		v, next, err := decodeValue(src, pos, depth+1, vOpts, false)
		if err != nil {
			return cbor.Value{}, next, keyPath(err, opts, k)
		}
		pos = next
		var idx int
		m, idx, err = mapInsert(m, k, v, keyOff, encodedKey, ks, &opts)
		if err != nil {
			return cbor.Value{}, keyOff, err
		}
		if rec != nil {
			recordSpan(rec, idx, keyOff, valOff, pos)
		}
	}
}

func decodeTag(src []byte, off int, h wire.HeadResult, depth int, opts DecodeOpts, stripSelfDescribe bool) (cbor.Value, int, error) {
	tagID := h.Arg
	pos := off + h.N

	if !opts.tagAllowed(tagID) {
		return cbor.Value{}, off, decodeErr(cbor.ErrUnknownTag, off)
	}

	if tagID == 55799 && stripSelfDescribe {
		return decodeValue(src, pos, depth, opts, true)
	}

	if depth+1 > opts.maxNesting() {
		return cbor.Value{}, off, decodeErr(cbor.ErrMaxNestingDepth, off)
	}
	inner, next, err := decodeValue(src, pos, depth+1, opts, false)
	if err != nil {
		return cbor.Value{}, next, err
	}
	if opts.Arena != nil {
		// Same layout as MakeTag; the one-item slice is capped so an
		// append can't overwrite the arena slot that follows it.
		items := opts.Arena.AllocValues(1)[:1:1]
		items[0] = inner
		return cbor.Value{Kind: cbor.KindTag, Num: tagID, Items: items}, next, nil
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
			return cbor.Value{}, off, decodeErr(cbor.ErrNonShortest, off)
		}
		return cbor.Simple(sv), off + h.N, nil
	case ai == wire.AI2Bytes:
		bits := uint16(h.Arg)
		f := wire.DecodeFloat16(bits)
		if opts.RejectNonFiniteFloats && (math.IsNaN(f) || math.IsInf(f, 0)) {
			return cbor.Value{}, off, decodeErr(cbor.ErrNonFiniteFloat, off)
		}
		return cbor.Float64(f), off + h.N, nil
	case ai == wire.AI4Bytes:
		bits := uint32(h.Arg)
		f := math.Float32frombits(bits)
		if opts.RejectNonFiniteFloats && (math.IsNaN(float64(f)) || math.IsInf(float64(f), 0)) {
			return cbor.Value{}, off, decodeErr(cbor.ErrNonFiniteFloat, off)
		}
		return cbor.Float32(f), off + h.N, nil
	case ai == wire.AI8Bytes:
		f := math.Float64frombits(h.Arg)
		if opts.RejectNonFiniteFloats && (math.IsNaN(f) || math.IsInf(f, 0)) {
			return cbor.Value{}, off, decodeErr(cbor.ErrNonFiniteFloat, off)
		}
		return cbor.Float64(f), off + h.N, nil
	case ai == wire.AIIndefinite:
		// A break is only valid as the terminator of an indefinite-length
		// item, which the container decoders consume themselves.
		return cbor.Value{}, off, decodeErr(cbor.ErrUnexpectedBreak, off)
	default:
		return cbor.Value{}, off, decodeErr(cbor.ErrReservedAI, off)
	}
}
