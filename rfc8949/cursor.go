// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"errors"
	"fmt"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/wire"
)

var (
	ErrNotInContainer = errors.New("cbor: cursor not inside a container")
	ErrKeyNotFound    = errors.New("cbor: map key not found")
	ErrNotScalar      = errors.New("cbor: current item is not a scalar")
	ErrTypeMismatch   = errors.New("cbor: type mismatch")
)

type cursorFrame struct {
	remaining int  // items left (-1 for indefinite)
	isMap     bool // true if map (items are key-value pairs)
}

// Cursor provides forward-only, lazy traversal of CBOR data. It reads
// only wire headers to determine structure, skipping payloads until
// the caller requests a value. Zero allocations for Skip and RawBytes.
type Cursor struct {
	src   []byte
	pos   int
	stack []cursorFrame
	opts  DecodeOpts
}

// NewCursor creates a cursor over src.
func NewCursor(src []byte, opts DecodeOpts) *Cursor {
	return &Cursor{src: src, opts: opts}
}

// Offset returns the current byte position in the source buffer.
func (c *Cursor) Offset() int { return c.pos }

// AtEnd reports whether the cursor has consumed all bytes at the
// current level.
func (c *Cursor) AtEnd() bool {
	if len(c.stack) > 0 {
		top := &c.stack[len(c.stack)-1]
		return top.remaining == 0
	}
	return c.pos >= len(c.src)
}

// AtBreak reports whether the cursor is at a break code (0xff),
// indicating the end of an indefinite-length container.
func (c *Cursor) AtBreak() bool {
	if c.pos >= len(c.src) {
		return false
	}
	return c.src[c.pos] == wire.BreakCode
}

// Kind returns the CBOR major type of the current item without
// advancing the cursor.
func (c *Cursor) Kind() (byte, error) {
	if c.pos >= len(c.src) {
		return 0, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
	}
	return c.src[c.pos] & 0xe0, nil
}

// Skip advances past the current item (and all children if it's a
// container) without decoding. Returns the number of bytes skipped.
func (c *Cursor) Skip() (int, error) {
	start := c.pos
	if err := c.skipItem(); err != nil {
		return 0, err
	}
	c.consumeFromFrame()
	return c.pos - start, nil
}

// RawBytes returns the raw CBOR bytes of the current item without
// decoding. Advances the cursor past the item.
func (c *Cursor) RawBytes() ([]byte, error) {
	start := c.pos
	if err := c.skipItem(); err != nil {
		return nil, err
	}
	c.consumeFromFrame()
	return c.src[start:c.pos], nil
}

// Raw returns the source bytes of the item the cursor is positioned
// at, without advancing. The slice aliases the cursor's source.
func (c *Cursor) Raw() ([]byte, error) {
	next, err := c.skipAt(c.pos, len(c.stack), 0, len(c.stack) == 0)
	if err != nil {
		return nil, err
	}
	return c.src[c.pos:next], nil
}

// DecodeRaw decodes the current item, returning its Value and its
// source bytes (aliasing the cursor's source), and advances past it.
func (c *Cursor) DecodeRaw() (cbor.Value, []byte, error) {
	start := c.pos
	v, err := c.Decode()
	if err != nil {
		return cbor.Value{}, nil, err
	}
	return v, c.src[start:c.pos], nil
}

// Bytes returns the contents of the current byte-string item without
// copying (aliasing the cursor's source), and advances. It returns
// ErrTypeMismatch if the item is not a byte string (major type 2), and
// ErrIndefiniteLength for an indefinite-length byte string, which has
// no single contiguous span.
func (c *Cursor) Bytes() ([]byte, error) {
	if c.pos >= len(c.src) {
		return nil, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
	}
	h := wire.ParseHead(c.src[c.pos:])
	if h.N == 0 {
		return nil, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
	}
	if h.Major != wire.MajorBytes {
		return nil, fmt.Errorf("%w at offset %d: expected byte string, got major %d",
			ErrTypeMismatch, c.pos, h.Major>>5)
	}
	if h.AI == wire.AIIndefinite {
		return nil, fmt.Errorf("%w at offset %d", cbor.ErrIndefiniteLength, c.pos)
	}
	if h.AI >= 28 && h.AI <= 30 {
		return nil, fmt.Errorf("%w at offset %d", cbor.ErrReservedAI, c.pos)
	}
	if c.opts.RejectNonShortest && h.AI >= wire.AI1Byte && h.AI <= wire.AI8Bytes && !h.IsShortest() {
		return nil, fmt.Errorf("%w at offset %d", cbor.ErrNonShortest, c.pos)
	}
	if h.Arg > uint64(c.opts.maxBytes()) {
		return nil, fmt.Errorf("%w at offset %d", cbor.ErrMaxByteStringLength, c.pos)
	}
	start := c.pos + h.N
	if h.Arg > uint64(len(c.src)-start) {
		return nil, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
	}
	end := start + int(h.Arg)
	c.pos = end
	c.consumeFromFrame()
	return c.src[start:end], nil
}

// Decode fully decodes the current item using the cursor's DecodeOpts.
// Advances the cursor past the item.
func (c *Cursor) Decode() (cbor.Value, error) {
	v, next, err := Decode(c.src[c.pos:], c.opts)
	if err != nil {
		return cbor.Value{}, err
	}
	c.pos += next
	c.consumeFromFrame()
	return v, nil
}

func (c *Cursor) consumeFromFrame() {
	if len(c.stack) == 0 {
		return
	}
	top := &c.stack[len(c.stack)-1]
	if top.remaining > 0 {
		top.remaining--
	}
}

// EnterArray positions the cursor at the first element of the current
// array. Returns the element count (-1 for indefinite-length).
func (c *Cursor) EnterArray() (int, error) {
	if c.pos >= len(c.src) {
		return 0, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
	}
	h := wire.ParseHead(c.src[c.pos:])
	if h.N == 0 {
		return 0, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
	}
	if h.Major != wire.MajorArray {
		return 0, fmt.Errorf("%w at offset %d: expected array, got major %d",
			ErrTypeMismatch, c.pos, h.Major>>5)
	}
	c.pos += h.N
	count := -1
	if h.AI != wire.AIIndefinite {
		count = int(h.Arg)
	}
	c.stack = append(c.stack, cursorFrame{remaining: count, isMap: false})
	return count, nil
}

// EnterMap positions the cursor at the first key of the current map.
// Returns the pair count (-1 for indefinite-length). Keys and values
// alternate: key, value, key, value, ...
func (c *Cursor) EnterMap() (int, error) {
	if c.pos >= len(c.src) {
		return 0, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
	}
	h := wire.ParseHead(c.src[c.pos:])
	if h.N == 0 {
		return 0, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
	}
	if h.Major != wire.MajorMap {
		return 0, fmt.Errorf("%w at offset %d: expected map, got major %d",
			ErrTypeMismatch, c.pos, h.Major>>5)
	}
	c.pos += h.N
	count := -1
	if h.AI != wire.AIIndefinite {
		count = int(h.Arg) * 2
	}
	c.stack = append(c.stack, cursorFrame{remaining: count, isMap: true})
	if h.AI != wire.AIIndefinite {
		return int(h.Arg), nil
	}
	return -1, nil
}

// ExitArray skips any remaining items in the current array and returns
// the cursor to the enclosing container. Returns ErrNotInContainer if
// not inside an array.
func (c *Cursor) ExitArray() error {
	if len(c.stack) == 0 {
		return ErrNotInContainer
	}
	top := &c.stack[len(c.stack)-1]
	if top.isMap {
		return fmt.Errorf("%w: currently in a map, not an array", ErrNotInContainer)
	}
	if err := c.skipRemaining(top); err != nil {
		return err
	}
	c.stack = c.stack[:len(c.stack)-1]
	return nil
}

// ExitMap skips any remaining key-value pairs in the current map and
// returns the cursor to the enclosing container.
func (c *Cursor) ExitMap() error {
	if len(c.stack) == 0 {
		return ErrNotInContainer
	}
	top := &c.stack[len(c.stack)-1]
	if !top.isMap {
		return fmt.Errorf("%w: currently in an array, not a map", ErrNotInContainer)
	}
	if err := c.skipRemaining(top); err != nil {
		return err
	}
	c.stack = c.stack[:len(c.stack)-1]
	return nil
}

// FindMapKey scans forward in the current map for a text key matching
// key. On success, the cursor is positioned at the value for that key.
// Returns ErrKeyNotFound if the key is not found before the map ends.
// Only scans forward — cannot find keys already passed.
func (c *Cursor) FindMapKey(key string) error {
	if len(c.stack) == 0 {
		return ErrNotInContainer
	}
	top := &c.stack[len(c.stack)-1]
	if !top.isMap {
		return fmt.Errorf("%w: not in a map", ErrNotInContainer)
	}

	for {
		if top.remaining == 0 {
			return ErrKeyNotFound
		}
		if top.remaining < 0 && c.AtBreak() {
			return ErrKeyNotFound
		}
		if c.pos >= len(c.src) {
			return fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
		}

		keyStart := c.pos
		h := wire.ParseHead(c.src[c.pos:])
		if h.N == 0 {
			return fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
		}

		if h.Major == wire.MajorText && h.AI != wire.AIIndefinite {
			length := int(h.Arg)
			start := c.pos + h.N
			end := start + length
			if end <= len(c.src) {
				candidate := c.src[start:end]
				if len(candidate) == len(key) && string(candidate) == key {
					c.pos = end
					if top.remaining > 0 {
						top.remaining--
					}
					return nil
				}
			}
		}

		c.pos = keyStart
		if err := c.skipItem(); err != nil {
			return err
		}
		if err := c.skipItem(); err != nil {
			return err
		}
		if top.remaining > 0 {
			top.remaining -= 2
		}
	}
}

func (c *Cursor) skipRemaining(frame *cursorFrame) error {
	if frame.remaining < 0 {
		for !c.AtBreak() {
			if c.pos >= len(c.src) {
				return fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
			}
			if err := c.skipItem(); err != nil {
				return err
			}
			if frame.isMap {
				if err := c.skipItem(); err != nil {
					return err
				}
			}
		}
		c.pos++
		return nil
	}

	for range frame.remaining {
		if err := c.skipItem(); err != nil {
			return err
		}
	}
	return nil
}

// skipItem advances past one complete data item at the current
// position. It checks the same structural rules as Decode (reserved
// additional information, indefinite length where it isn't allowed,
// stray break codes, two-byte simple values below 32, nesting depth,
// length limits, and declared lengths the input can't hold) but none
// of the content knobs (UTF-8, duplicates, tags, floats), which only
// Decode applies.
func (c *Cursor) skipItem() error {
	next, err := c.skipAt(c.pos, len(c.stack), 0, len(c.stack) == 0)
	if err != nil {
		return err
	}
	c.pos = next
	return nil
}

// skipAt returns the offset just past the item at off. depth counts
// enclosing containers and tags; reserve is the number of bytes that
// enclosing containers still need for their pending items (see
// DecodeOpts.reserve). strip mirrors Decode dropping leading
// self-describe tags without counting them as nesting.
func (c *Cursor) skipAt(off, depth, reserve int, strip bool) (int, error) {
	src, o := c.src, c.opts
	if off >= len(src) {
		return off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
	}
	h := wire.ParseHead(src[off:])
	if h.N == 0 {
		return off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
	}
	if h.AI >= 28 && h.AI <= 30 {
		return off, fmt.Errorf("%w at offset %d", cbor.ErrReservedAI, off)
	}
	if h.AI == wire.AIIndefinite && (h.Major == wire.MajorUint || h.Major == wire.MajorNegInt || h.Major == wire.MajorTag) {
		return off, fmt.Errorf("%w (indefinite length for major type %d) at offset %d", cbor.ErrReservedAI, h.Major>>5, off)
	}
	pos := off + h.N
	avail := len(src) - pos - reserve

	switch h.Major {
	case wire.MajorUint, wire.MajorNegInt:
		return pos, nil

	case wire.MajorBytes, wire.MajorText:
		if h.AI == wire.AIIndefinite {
			return c.skipChunks(pos, h.Major)
		}
		if h.Arg > uint64(o.maxBytes()) {
			return off, fmt.Errorf("%w at offset %d", cbor.ErrMaxByteStringLength, off)
		}
		if h.Arg > uint64(len(src)-pos) {
			return off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
		}
		return pos + int(h.Arg), nil

	case wire.MajorArray, wire.MajorMap:
		isMap := h.Major == wire.MajorMap
		if depth+1 > o.maxNesting() {
			return off, fmt.Errorf("%w at offset %d", cbor.ErrMaxNestingDepth, off)
		}
		per := 1
		if isMap {
			per = 2
		}
		if h.AI == wire.AIIndefinite {
			for n := 0; ; n++ {
				if pos >= len(src) {
					return pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
				}
				if src[pos] == wire.BreakCode {
					return pos + 1, nil
				}
				if n >= o.maxArray() {
					return pos, fmt.Errorf("%w at offset %d", cbor.ErrMaxArrayLength, pos)
				}
				for k := range per {
					// Pending: the rest of this pair, plus the break code.
					next, err := c.skipAt(pos, depth+1, reserve+per-k, false)
					if err != nil {
						return next, err
					}
					pos = next
				}
			}
		}
		if h.Arg > uint64(o.maxArray()) {
			return off, fmt.Errorf("%w at offset %d", cbor.ErrMaxArrayLength, off)
		}
		count := int(h.Arg)
		if count > avail/per {
			return off, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, off)
		}
		for i := range count * per {
			next, err := c.skipAt(pos, depth+1, reserve+count*per-i-1, false)
			if err != nil {
				return next, err
			}
			pos = next
		}
		return pos, nil

	case wire.MajorTag:
		if !o.tagAllowed(h.Arg) {
			return off, fmt.Errorf("%w at offset %d", cbor.ErrUnknownTag, off)
		}
		if strip && h.Arg == cbor.TagSelfDescribe {
			return c.skipAt(pos, depth, reserve, true)
		}
		if depth+1 > o.maxNesting() {
			return off, fmt.Errorf("%w at offset %d", cbor.ErrMaxNestingDepth, off)
		}
		return c.skipAt(pos, depth+1, reserve, false)

	default: // major type 7
		switch {
		case h.AI == wire.AIIndefinite:
			return off, fmt.Errorf("%w at offset %d", cbor.ErrUnexpectedBreak, off)
		case h.AI == wire.AI1Byte && h.Arg < 32:
			return off, fmt.Errorf("%w at offset %d", cbor.ErrNonShortest, off)
		}
		return pos, nil
	}
}

// skipChunks skips the chunks of an indefinite-length byte or text
// string starting at pos, through the break code.
func (c *Cursor) skipChunks(pos int, major byte) (int, error) {
	src, o := c.src, c.opts
	total := uint64(0)
	for {
		if pos >= len(src) {
			return pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		if src[pos] == wire.BreakCode {
			return pos + 1, nil
		}
		h := wire.ParseHead(src[pos:])
		if h.N == 0 || h.Major != major || h.AI == wire.AIIndefinite {
			return pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		if h.AI >= 28 && h.AI <= 30 {
			return pos, fmt.Errorf("%w at offset %d", cbor.ErrReservedAI, pos)
		}
		if h.Arg > uint64(o.maxBytes()) || total+h.Arg > uint64(o.maxBytes()) {
			return pos, fmt.Errorf("%w at offset %d", cbor.ErrMaxByteStringLength, pos)
		}
		if h.Arg > uint64(len(src)-pos-h.N) {
			return pos, fmt.Errorf("%w at offset %d", cbor.ErrTruncated, pos)
		}
		total += h.Arg
		pos += h.N + int(h.Arg)
	}
}
