// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"errors"
	"fmt"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/internal/decerr"
	"github.com/jahkeup/corecbor/wire"
)

var (
	ErrNotInContainer = errors.New("cbor: cursor not inside a container")
	ErrKeyNotFound    = errors.New("cbor: map key not found")
	ErrNotScalar      = errors.New("cbor: current item is not a scalar")
	ErrTypeMismatch   = cbor.ErrTypeMismatch
)

type cursorFrame struct {
	remaining int  // items left (-1 for indefinite)
	isMap     bool // true if map (items are key-value pairs)
}

// Cursor provides forward-only, lazy traversal of CBOR data. It reads
// only wire headers to determine structure, skipping payloads until
// the caller requests a value. Zero allocations for Skip and RawBytes.
type Cursor struct {
	src  []byte
	pos  int
	opts DecodeOpts
	// Open containers: the first len(frames) levels live inline so that
	// entering a container doesn't allocate in the common shallow case;
	// deeper levels spill into extra.
	frames [4]cursorFrame
	extra  []cursorFrame
	nopen  int
}

// depth returns the number of open containers.
func (c *Cursor) depth() int { return c.nopen }

// top returns the innermost open container; c.depth() must be > 0.
func (c *Cursor) top() *cursorFrame {
	i := c.nopen - 1
	if i < len(c.frames) {
		return &c.frames[i]
	}
	return &c.extra[i-len(c.frames)]
}

func (c *Cursor) push(f cursorFrame) {
	if c.nopen < len(c.frames) {
		c.frames[c.nopen] = f
	} else {
		c.extra = append(c.extra[:c.nopen-len(c.frames)], f)
	}
	c.nopen++
}

func (c *Cursor) pop() { c.nopen-- }

// NewCursor creates a cursor over src.
func NewCursor(src []byte, opts DecodeOpts) *Cursor {
	return &Cursor{src: src, opts: opts}
}

// Offset returns the current byte position in the source buffer.
func (c *Cursor) Offset() int { return c.pos }

// AtEnd reports whether the cursor has consumed all bytes at the
// current level.
func (c *Cursor) AtEnd() bool {
	if c.depth() > 0 {
		top := c.top()
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
		return 0, decodeErr(cbor.ErrTruncated, c.pos)
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
	next, err := c.skipAt(c.pos, c.depth(), 0, c.depth() == 0)
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
		return nil, decodeErr(cbor.ErrTruncated, c.pos)
	}
	h := wire.ParseHead(c.src[c.pos:])
	if h.N == 0 {
		return nil, decodeErr(cbor.ErrTruncated, c.pos)
	}
	if h.Major != wire.MajorBytes {
		return nil, decodeErrf(ErrTypeMismatch, c.pos, ": expected byte string, got major %d", h.Major>>5)
	}
	if h.AI == wire.AIIndefinite {
		return nil, decodeErr(cbor.ErrIndefiniteLength, c.pos)
	}
	if h.AI >= 28 && h.AI <= 30 {
		return nil, decodeErr(cbor.ErrReservedAI, c.pos)
	}
	if c.opts.RejectNonShortest && h.AI >= wire.AI1Byte && h.AI <= wire.AI8Bytes && !h.IsShortest() {
		return nil, decodeErr(cbor.ErrNonShortest, c.pos)
	}
	if h.Arg > uint64(c.opts.maxBytes()) {
		return nil, decodeErr(cbor.ErrMaxByteStringLength, c.pos)
	}
	start := c.pos + h.N
	if h.Arg > uint64(len(c.src)-start) {
		return nil, decodeErr(cbor.ErrTruncated, c.pos)
	}
	end := start + int(h.Arg)
	c.pos = end
	c.consumeFromFrame()
	return c.src[start:end], nil
}

// Decode fully decodes the current item using the cursor's DecodeOpts.
// Advances the cursor past the item.
func (c *Cursor) Decode() (cbor.Value, error) {
	// Nesting depth continues from the containers the cursor is in.
	v, next, err := decodeFrom(c.src[c.pos:], c.depth(), c.opts)
	if err != nil {
		return cbor.Value{}, err
	}
	c.pos += next
	c.consumeFromFrame()
	return v, nil
}

func (c *Cursor) consumeFromFrame() {
	if c.depth() == 0 {
		return
	}
	top := c.top()
	if top.remaining > 0 {
		top.remaining--
	}
}

// EnterArray positions the cursor at the first element of the current
// array. Returns the element count (-1 for indefinite-length).
//
// It applies the same structural rules and limits as Decode and Skip
// to the array's head (reserved additional information, indefinite or
// non-shortest lengths when the options reject them, MaxArrayLength,
// MaxNestingDepth, and a count the input can't hold); on error the
// cursor doesn't move.
func (c *Cursor) EnterArray() (int, error) {
	return c.enter(wire.MajorArray)
}

// EnterMap positions the cursor at the first key of the current map.
// Returns the pair count (-1 for indefinite-length). Keys and values
// alternate: key, value, key, value, ... It checks the map's head as
// EnterArray does.
func (c *Cursor) EnterMap() (int, error) {
	return c.enter(wire.MajorMap)
}

func (c *Cursor) enter(major byte) (int, error) {
	off, o := c.pos, c.opts
	if off >= len(c.src) {
		return 0, decodeErr(cbor.ErrTruncated, off)
	}
	h := wire.ParseHead(c.src[off:])
	if h.N == 0 {
		return 0, decodeErr(cbor.ErrTruncated, off)
	}
	isMap := major == wire.MajorMap
	if h.Major != major {
		want := "array"
		if isMap {
			want = "map"
		}
		return 0, decodeErrf(ErrTypeMismatch, off, ": expected %s, got major %d", want, h.Major>>5)
	}
	if h.AI >= 28 && h.AI <= 30 {
		return 0, decodeErr(cbor.ErrReservedAI, off)
	}
	indefinite := h.AI == wire.AIIndefinite
	if indefinite && o.RejectIndefiniteLength {
		return 0, decodeErr(cbor.ErrIndefiniteLength, off)
	}
	if o.RejectNonShortest && h.AI >= wire.AI1Byte && h.AI <= wire.AI8Bytes && !h.IsShortest() {
		return 0, decodeErr(cbor.ErrNonShortest, off)
	}
	// Same order as Decode: length limit, then nesting depth.
	if !indefinite && h.Arg > uint64(o.maxArray()) {
		return 0, decodeErr(cbor.ErrMaxArrayLength, off)
	}
	if c.depth()+1 > o.maxNesting() {
		return 0, decodeErr(cbor.ErrMaxNestingDepth, off)
	}
	count, items := -1, -1
	if !indefinite {
		// h.Arg <= maxArray, an int, so the conversion can't wrap.
		// Every item takes at least a byte: fail now on a count the
		// input can't hold, which also bounds the doubling for a map.
		per := 1
		if isMap {
			per = 2
		}
		count = int(h.Arg)
		if count > (len(c.src)-off-h.N)/per {
			return 0, decodeErr(cbor.ErrTruncated, off)
		}
		items = count * per
	}
	c.pos += h.N
	// The nested container is one item of its parent.
	c.consumeFromFrame()
	c.push(cursorFrame{remaining: items, isMap: isMap})
	return count, nil
}

// ExitArray skips any remaining items in the current array and returns
// the cursor to the enclosing container. Returns ErrNotInContainer if
// not inside an array.
func (c *Cursor) ExitArray() error {
	if c.depth() == 0 {
		return ErrNotInContainer
	}
	top := c.top()
	if top.isMap {
		return fmt.Errorf("%w: currently in a map, not an array", ErrNotInContainer)
	}
	if err := c.skipRemaining(top); err != nil {
		return err
	}
	c.pop()
	return nil
}

// ExitMap skips any remaining key-value pairs in the current map and
// returns the cursor to the enclosing container.
func (c *Cursor) ExitMap() error {
	if c.depth() == 0 {
		return ErrNotInContainer
	}
	top := c.top()
	if !top.isMap {
		return fmt.Errorf("%w: currently in an array, not a map", ErrNotInContainer)
	}
	if err := c.skipRemaining(top); err != nil {
		return err
	}
	c.pop()
	return nil
}

// FindMapKey scans forward in the current map for a text key matching
// key. On success, the cursor is positioned at the value for that key.
// Returns ErrKeyNotFound if the key is not found before the map ends.
// Only scans forward — cannot find keys already passed.
func (c *Cursor) FindMapKey(key string) error {
	if c.depth() == 0 {
		return ErrNotInContainer
	}
	top := c.top()
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
			return decodeErr(cbor.ErrTruncated, c.pos)
		}

		keyStart := c.pos
		h := wire.ParseHead(c.src[c.pos:])
		if h.N == 0 {
			return decodeErr(cbor.ErrTruncated, c.pos)
		}

		if h.Major == wire.MajorText && h.AI != wire.AIIndefinite {
			start := c.pos + h.N
			// Compare in uint64: a huge length would wrap as an int.
			if h.Arg <= uint64(len(c.src)-start) {
				end := start + int(h.Arg)
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
				return decodeErr(cbor.ErrTruncated, c.pos)
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
	next, err := c.skipAt(c.pos, c.depth(), 0, c.depth() == 0)
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
		return off, decodeErr(cbor.ErrTruncated, off)
	}
	h := wire.ParseHead(src[off:])
	if h.N == 0 {
		return off, decodeErr(cbor.ErrTruncated, off)
	}
	if h.AI >= 28 && h.AI <= 30 {
		return off, decodeErr(cbor.ErrReservedAI, off)
	}
	if h.AI == wire.AIIndefinite && (h.Major == wire.MajorUint || h.Major == wire.MajorNegInt || h.Major == wire.MajorTag) {
		return off, decerr.Text(cbor.ErrReservedAI, off, fmt.Sprintf("%s (indefinite length for major type %d) at offset %d", cbor.ErrReservedAI, h.Major>>5, off))
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
			return off, decodeErr(cbor.ErrMaxByteStringLength, off)
		}
		if h.Arg > uint64(len(src)-pos) {
			return off, decodeErr(cbor.ErrTruncated, off)
		}
		return pos + int(h.Arg), nil

	case wire.MajorArray, wire.MajorMap:
		isMap := h.Major == wire.MajorMap
		// Same order as Decode and the stream reader: a definite length
		// over the limit is reported before the nesting depth.
		if h.AI != wire.AIIndefinite && h.Arg > uint64(o.maxArray()) {
			return off, decodeErr(cbor.ErrMaxArrayLength, off)
		}
		if depth+1 > o.maxNesting() {
			return off, decodeErr(cbor.ErrMaxNestingDepth, off)
		}
		per := 1
		if isMap {
			per = 2
		}
		if h.AI == wire.AIIndefinite {
			for n := 0; ; n++ {
				if pos >= len(src) {
					return pos, decodeErr(cbor.ErrTruncated, pos)
				}
				if src[pos] == wire.BreakCode {
					return pos + 1, nil
				}
				if n >= o.maxArray() {
					return pos, decodeErr(cbor.ErrMaxArrayLength, pos)
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
		count := int(h.Arg)
		if count > avail/per {
			return off, decodeErr(cbor.ErrTruncated, off)
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
			return off, decodeErr(cbor.ErrUnknownTag, off)
		}
		if strip && h.Arg == cbor.TagSelfDescribe {
			// Strip the whole chain in a loop, as Decode does (037 C1).
			return c.skipAt(skipSelfDescribe(src, pos, &o), depth, reserve, true)
		}
		if depth+1 > o.maxNesting() {
			return off, decodeErr(cbor.ErrMaxNestingDepth, off)
		}
		return c.skipAt(pos, depth+1, reserve, false)

	default: // major type 7
		switch {
		case h.AI == wire.AIIndefinite:
			return off, decodeErr(cbor.ErrUnexpectedBreak, off)
		case h.AI == wire.AI1Byte && h.Arg < 32:
			return off, decodeErr(cbor.ErrNonShortest, off)
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
			return pos, decodeErr(cbor.ErrTruncated, pos)
		}
		if src[pos] == wire.BreakCode {
			return pos + 1, nil
		}
		h := wire.ParseHead(src[pos:])
		if h.N == 0 || h.Major != major || h.AI == wire.AIIndefinite {
			return pos, decodeErr(cbor.ErrTruncated, pos)
		}
		if h.AI >= 28 && h.AI <= 30 {
			return pos, decodeErr(cbor.ErrReservedAI, pos)
		}
		if h.Arg > uint64(o.maxBytes()) || total+h.Arg > uint64(o.maxBytes()) {
			return pos, decodeErr(cbor.ErrMaxByteStringLength, pos)
		}
		if h.Arg > uint64(len(src)-pos-h.N) {
			return pos, decodeErr(cbor.ErrTruncated, pos)
		}
		total += h.Arg
		pos += h.N + int(h.Arg)
	}
}
