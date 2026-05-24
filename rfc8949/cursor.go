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

// Decode fully decodes the current item using the cursor's DecodeOpts.
// Advances the cursor past the item.
func (c *Cursor) Decode() (cbor.Value, error) {
	v, next, err := Decode(c.src[c.pos:], c.opts)
	if err != nil {
		return nil, err
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

func (c *Cursor) skipItem() error {
	if c.pos >= len(c.src) {
		return fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
	}

	h := wire.ParseHead(c.src[c.pos:])
	if h.N == 0 {
		return fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
	}

	switch h.Major {
	case wire.MajorUint, wire.MajorNegInt:
		c.pos += h.N
		return nil

	case wire.MajorBytes, wire.MajorText:
		if h.AI == wire.AIIndefinite {
			c.pos += h.N
			return c.skipIndefiniteString()
		}
		end := c.pos + h.N + int(h.Arg)
		if end > len(c.src) {
			return fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
		}
		c.pos = end
		return nil

	case wire.MajorArray:
		c.pos += h.N
		if h.AI == wire.AIIndefinite {
			return c.skipIndefiniteItems(false)
		}
		count := int(h.Arg)
		for range count {
			if err := c.skipItem(); err != nil {
				return err
			}
		}
		return nil

	case wire.MajorMap:
		c.pos += h.N
		if h.AI == wire.AIIndefinite {
			return c.skipIndefiniteItems(true)
		}
		count := int(h.Arg) * 2
		for range count {
			if err := c.skipItem(); err != nil {
				return err
			}
		}
		return nil

	case wire.MajorTag:
		c.pos += h.N
		return c.skipItem()

	case wire.MajorOther:
		c.pos += h.N
		return nil

	default:
		return fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
	}
}

func (c *Cursor) skipIndefiniteString() error {
	for {
		if c.pos >= len(c.src) {
			return fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
		}
		if c.src[c.pos] == wire.BreakCode {
			c.pos++
			return nil
		}
		h := wire.ParseHead(c.src[c.pos:])
		if h.N == 0 {
			return fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
		}
		end := c.pos + h.N + int(h.Arg)
		if end > len(c.src) {
			return fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
		}
		c.pos = end
	}
}

func (c *Cursor) skipIndefiniteItems(isMap bool) error {
	for {
		if c.pos >= len(c.src) {
			return fmt.Errorf("%w at offset %d", cbor.ErrTruncated, c.pos)
		}
		if c.src[c.pos] == wire.BreakCode {
			c.pos++
			return nil
		}
		if err := c.skipItem(); err != nil {
			return err
		}
		if isMap {
			if err := c.skipItem(); err != nil {
				return err
			}
		}
	}
}
