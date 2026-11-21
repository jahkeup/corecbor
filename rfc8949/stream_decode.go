// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"errors"
	"fmt"
	"io"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/internal/decerr"
	"github.com/jahkeup/corecbor/wire"
)

// DecodeFrom reads exactly one CBOR data item from r and decodes it. It
// consumes the item's bytes and nothing after them, so consecutive calls
// on one reader return consecutive items. Cost is linear in the item
// size.
//
// When r implements io.ByteReader (bytes.Reader, bufio.Reader,
// BufferedReader), item heads are read a byte at a time through it;
// otherwise each head is read with its own Read call, so wrap slow
// readers in a bufio.Reader (whose buffering is then the caller's).
//
// An empty reader returns io.EOF. A reader that ends mid-item returns an
// error wrapping both cbor.ErrTruncated and io.ErrUnexpectedEOF. The
// decoder's nesting, length and well-formedness limits are applied while
// reading, before the item's bytes are buffered, so a limit violation is
// reported as soon as its head is read.
func DecodeFrom(r io.Reader, opts DecodeOpts) (cbor.Value, error) {
	ir := itemReader{r: r, opts: opts}
	if br, ok := r.(io.ByteReader); ok {
		ir.br = br
	}
	return ir.decode()
}

// BufferedReader wraps an io.Reader with an internal read buffer for use
// with DecodeFromBuffered. Bytes it reads ahead stay buffered for
// subsequent reads, so a sequence of items can be read efficiently from
// a reader that doesn't buffer.
type BufferedReader struct {
	r   io.Reader
	buf []byte
	off int
}

// Read implements io.Reader, returning buffered bytes first.
func (br *BufferedReader) Read(p []byte) (int, error) {
	if br.off < len(br.buf) {
		n := copy(p, br.buf[br.off:])
		br.off += n
		return n, nil
	}
	return br.r.Read(p)
}

// ReadByte implements io.ByteReader.
func (br *BufferedReader) ReadByte() (byte, error) {
	if br.off >= len(br.buf) {
		if cap(br.buf) == 0 {
			br.buf = make([]byte, 0, 4096)
		}
		var n int
		var err error
		for range 100 {
			n, err = br.r.Read(br.buf[:cap(br.buf)])
			if n > 0 || err != nil {
				break
			}
		}
		br.buf = br.buf[:n]
		br.off = 0
		if n == 0 {
			if err == nil {
				err = io.ErrNoProgress
			}
			return 0, err
		}
	}
	b := br.buf[br.off]
	br.off++
	return b, nil
}

// DecodeFromBuffered reads one CBOR value from br, keeping any bytes read
// ahead buffered for subsequent reads.
func DecodeFromBuffered(br *BufferedReader, opts DecodeOpts) (cbor.Value, error) {
	return DecodeFrom(br, opts)
}

// NewBufferedReader wraps an io.Reader for use with DecodeFromBuffered.
func NewBufferedReader(r io.Reader) *BufferedReader {
	return &BufferedReader{r: r}
}

// errItemEOF reports that the reader ended inside an item.
var errItemEOF = errors.New("rfc8949: reader ended mid-item")

// errInternal marks a broken internal invariant (a bug, not bad input).
var errInternal = errors.New("rfc8949: internal")

// itemReader reads the bytes of exactly one data item. It walks heads
// with an explicit stack (no recursion), enforcing the same nesting,
// length and well-formedness rules Decode applies to the item's
// structure, and buffers only bytes it has actually read.
type itemReader struct {
	r    io.Reader
	br   io.ByteReader
	opts DecodeOpts
	buf  []byte
}

type itemFrame struct {
	remaining    uint64 // definite: items left (a map counts keys and values)
	indef        bool
	isMap        bool
	items        int   // indefinite container: items read so far
	str          byte  // indefinite string: its major type (0 if not a string)
	strLen       int64 // indefinite string: bytes so far
	selfDescribe bool  // stripped tag 55799: adds no nesting depth
}

func (ir *itemReader) decode() (cbor.Value, error) {
	err := ir.read()
	switch {
	case err == nil:
	case errors.Is(err, errItemEOF):
		// The reader is exhausted, so the buffered bytes are the whole
		// input: Decode reports exactly what it would for them.
		_, _, derr := Decode(ir.buf, ir.opts)
		if derr == nil || errors.Is(derr, cbor.ErrTruncated) {
			return cbor.Value{}, decerr.Text(fmt.Errorf("%w: %w", cbor.ErrTruncated, io.ErrUnexpectedEOF), len(ir.buf),
				fmt.Sprintf("%s at offset %d: %s", cbor.ErrTruncated, len(ir.buf), io.ErrUnexpectedEOF))
		}
		return cbor.Value{}, derr
	default:
		return cbor.Value{}, err
	}
	v, n, err := Decode(ir.buf, ir.opts)
	if err != nil {
		return cbor.Value{}, err
	}
	if n != len(ir.buf) {
		return cbor.Value{}, fmt.Errorf("%w: read %d bytes for an item that decoded from %d", errInternal, len(ir.buf), n)
	}
	return v, nil
}

func (ir *itemReader) readByte() (byte, error) {
	if ir.br != nil {
		return ir.br.ReadByte()
	}
	var b [1]byte
	_, err := io.ReadFull(ir.r, b[:])
	return b[0], err
}

// readN appends exactly n more bytes from the reader to buf, growing it
// in bounded chunks so a declared length never allocates ahead of data.
func (ir *itemReader) readN(n uint64) error {
	const maxChunk = 64 << 10
	for n > 0 {
		chunk := uint64(maxChunk)
		if n < chunk {
			chunk = n
		}
		start := len(ir.buf)
		if cap(ir.buf)-start < int(chunk) {
			grown := make([]byte, start, max(2*cap(ir.buf), start+int(chunk)))
			copy(grown, ir.buf)
			ir.buf = grown
		}
		ir.buf = ir.buf[:start+int(chunk)]
		m, err := io.ReadFull(ir.r, ir.buf[start:])
		ir.buf = ir.buf[:start+m]
		if err != nil {
			return ir.readErr(err)
		}
		n -= chunk
	}
	return nil
}

// readErr maps a reader error: EOF of any kind inside an item becomes
// errItemEOF; other reader errors pass through.
func (ir *itemReader) readErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errItemEOF
	}
	return err
}

// readHead appends the rest of a head whose initial byte ib is already
// in buf at off, and parses it.
func (ir *itemReader) readHead(off int, ib byte) (wire.HeadResult, error) {
	var extra uint64
	switch ib & 0x1f {
	case wire.AI1Byte:
		extra = 1
	case wire.AI2Bytes:
		extra = 2
	case wire.AI4Bytes:
		extra = 4
	case wire.AI8Bytes:
		extra = 8
	}
	if err := ir.readN(extra); err != nil {
		return wire.HeadResult{}, err
	}
	return wire.ParseHead(ir.buf[off:]), nil
}

func errAt(sentinel error, off int) error {
	return decodeErr(sentinel, off)
}

func (ir *itemReader) read() error {
	opts := ir.opts
	var stack []itemFrame
	depth := 0
	for {
		off := len(ir.buf)
		var top *itemFrame
		if len(stack) > 0 {
			top = &stack[len(stack)-1]
		}
		ib, err := ir.readByte()
		if err != nil {
			if off == 0 && errors.Is(err, io.EOF) {
				return io.EOF // clean end: no item started
			}
			return ir.readErr(err)
		}
		ir.buf = append(ir.buf, ib)

		// Chunks of an indefinite-length string (decodeIndefiniteBytes,
		// decodeIndefiniteText).
		if top != nil && top.str != 0 {
			if ib == wire.BreakCode {
				stack = stack[:len(stack)-1]
				if ir.complete(&stack, &depth) {
					return nil
				}
				continue
			}
			h, err := ir.readHead(off, ib)
			if err != nil {
				return err
			}
			if h.Major != top.str || h.AI == wire.AIIndefinite {
				return errAt(cbor.ErrTruncated, off)
			}
			if h.AI >= 28 && h.AI <= 30 {
				return errAt(cbor.ErrReservedAI, off)
			}
			if h.Arg > uint64(opts.maxBytes()) || top.strLen+int64(h.Arg) > int64(opts.maxBytes()) {
				return errAt(cbor.ErrMaxByteStringLength, off)
			}
			top.strLen += int64(h.Arg)
			if err := ir.readN(h.Arg); err != nil {
				return err
			}
			continue
		}

		if ib == wire.BreakCode {
			if top != nil && top.indef && (!top.isMap || top.items%2 == 0) {
				stack = stack[:len(stack)-1]
				depth--
				if ir.complete(&stack, &depth) {
					return nil
				}
				continue
			}
			return errAt(cbor.ErrUnexpectedBreak, off)
		}
		if top != nil && top.indef {
			if (!top.isMap && top.items >= opts.maxArray()) || (top.isMap && top.items%2 == 0 && top.items/2 >= opts.maxArray()) {
				return errAt(cbor.ErrMaxArrayLength, off)
			}
		}

		h, err := ir.readHead(off, ib)
		if err != nil {
			return err
		}
		if h.AI >= 28 && h.AI <= 30 {
			return errAt(cbor.ErrReservedAI, off)
		}
		indefinite := h.AI == wire.AIIndefinite
		switch h.Major {
		case wire.MajorUint, wire.MajorNegInt:
			if indefinite {
				return errAt(cbor.ErrReservedAI, off)
			}
		case wire.MajorOther:
		case wire.MajorBytes, wire.MajorText:
			if indefinite {
				stack = append(stack, itemFrame{str: h.Major})
				continue
			}
			if h.Arg > uint64(opts.maxBytes()) {
				return errAt(cbor.ErrMaxByteStringLength, off)
			}
			if err := ir.readN(h.Arg); err != nil {
				return err
			}
		case wire.MajorArray, wire.MajorMap:
			isMap := h.Major == wire.MajorMap
			if !indefinite && h.Arg > uint64(opts.maxArray()) {
				return errAt(cbor.ErrMaxArrayLength, off)
			}
			if depth+1 > opts.maxNesting() {
				return errAt(cbor.ErrMaxNestingDepth, off)
			}
			if indefinite {
				stack = append(stack, itemFrame{indef: true, isMap: isMap})
				depth++
				continue
			}
			if h.Arg > 0 {
				n := h.Arg
				if isMap {
					n *= 2 // h.Arg <= maxArray <= MaxInt64, so this can't overflow
				}
				stack = append(stack, itemFrame{remaining: n, isMap: isMap})
				depth++
				continue
			}
		case wire.MajorTag:
			if indefinite {
				return errAt(cbor.ErrReservedAI, off)
			}
			sd := h.Arg == 55799 && (top == nil || top.selfDescribe)
			if !sd {
				if depth+1 > opts.maxNesting() {
					return errAt(cbor.ErrMaxNestingDepth, off)
				}
				depth++
			}
			stack = append(stack, itemFrame{remaining: 1, selfDescribe: sd})
			continue
		}
		if ir.complete(&stack, &depth) {
			return nil
		}
	}
}

// complete records that an item finished at the innermost open frame,
// closing every definite frame that this fills. It reports whether the
// top-level item is complete.
func (ir *itemReader) complete(stack *[]itemFrame, depth *int) bool {
	for len(*stack) > 0 {
		top := &(*stack)[len(*stack)-1]
		if top.indef {
			top.items++
			return false
		}
		top.remaining--
		if top.remaining > 0 {
			return false
		}
		if !top.selfDescribe {
			*depth--
		}
		*stack = (*stack)[:len(*stack)-1]
	}
	return true
}
