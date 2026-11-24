// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"unicode/utf8"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/rfc8949"
	"github.com/jahkeup/corecbor/wire"
)

// ErrIndefiniteNotPermitted is returned when indefinite-length encoding is
// attempted in a deterministic mode.
var ErrIndefiniteNotPermitted = errors.New("corecbor: indefinite-length not permitted in deterministic mode")

// StreamEncoder errors.
var (
	// ErrContainerOverflow is returned when more items are written to a
	// definite-length container than it declared.
	ErrContainerOverflow = errors.New("corecbor: container overflow")

	// ErrContainerUnderflow is returned by EndContainer when a container
	// holds fewer items than it declared, or ends mid-item (after a tag
	// head, or after a map key without its value).
	ErrContainerUnderflow = errors.New("corecbor: container underflow")

	// ErrNoOpenContainer is returned by EndContainer with no open container.
	ErrNoOpenContainer = errors.New("corecbor: no open container")

	// ErrStreamMapOrder is returned in deterministic modes when a map key
	// does not sort strictly after the previous key under the mode's key
	// order. It wraps ErrNotDeterministic, and also ErrDuplicateMapKey
	// when the key repeats the previous one.
	ErrStreamMapOrder = fmt.Errorf("corecbor: stream map keys out of deterministic order: %w", cbor.ErrNotDeterministic)
)

// EncodeTo writes the CBOR encoding of v to w.
func (e *Encoder) EncodeTo(w io.Writer, v Value) error {
	return rfc8949.EncodeTo(w, v, e.encodeOpts())
}

// StreamEncoder allows imperative stream writing of CBOR data.
//
// In deterministic modes the stream does not buffer or reorder map
// entries: callers write keys in the mode's order, and the stream
// verifies it, returning ErrStreamMapOrder for a key that is out of
// order or repeated. Callers that can't pre-sort keys should build a
// Value and use EncodeTo.
type StreamEncoder struct {
	w       io.Writer // out, or &tee while a map key is being captured
	out     io.Writer
	tee     keyTee
	enc     *Encoder
	stack   []containerState
	scratch [9]byte

	deterministic bool
	sortMode      rfc8949.SortMode
	capturing     int // frames currently capturing a map key's bytes
}

type containerState struct {
	remaining int // items declared; -1 for indefinite
	written   int // items started (a map counts keys and values)
	isMap     bool

	// started is set when tag heads for the next item have been written
	// but the tagged item itself hasn't been counted yet.
	started bool

	// Deterministic map key verification.
	capturing bool
	key       []byte // bytes of the key being written
	prevKey   []byte
	hasPrev   bool
}

// startItem prepares the innermost container for the next item: it
// checks for overflow and, in deterministic maps, starts capturing a key
// or verifies the key that just completed. count is false for a tag
// head, which belongs to the item that follows it.
func (s *StreamEncoder) startItem(count bool) error {
	if len(s.stack) == 0 {
		return nil
	}
	top := &s.stack[len(s.stack)-1]
	if !top.started {
		if top.remaining >= 0 && top.written >= top.remaining {
			return ErrContainerOverflow
		}
		if top.isMap && s.deterministic {
			if top.written%2 == 0 {
				top.capturing = true
				top.key = top.key[:0]
				s.beginCapture()
			} else if err := s.finishKey(top); err != nil {
				return err
			}
		}
	}
	if count {
		top.written++
		top.started = false
	} else {
		top.started = true
	}
	return nil
}

// trackWrite starts and counts one item in the innermost container. The
// common cases (top level, arrays, permissive maps) stay inlinable.
func (s *StreamEncoder) trackWrite() error {
	if len(s.stack) == 0 {
		return nil
	}
	return s.trackNested()
}

func (s *StreamEncoder) trackNested() error {
	top := &s.stack[len(s.stack)-1]
	if top.started || (top.isMap && s.deterministic) {
		return s.startItem(true)
	}
	if top.remaining >= 0 && top.written >= top.remaining {
		return ErrContainerOverflow
	}
	top.written++
	return nil
}

// finishKey verifies that the key just written in top sorts strictly
// after the previous key of the same map.
func (s *StreamEncoder) finishKey(top *containerState) error {
	top.capturing = false
	s.endCapture()
	if top.hasPrev {
		switch compareStreamKeys(s.sortMode, top.prevKey, top.key) {
		case 0:
			return fmt.Errorf("%w: %w", ErrStreamMapOrder, cbor.ErrDuplicateMapKey)
		case 1:
			return ErrStreamMapOrder
		}
	}
	top.prevKey = append(top.prevKey[:0], top.key...)
	top.hasPrev = true
	return nil
}

func compareStreamKeys(mode rfc8949.SortMode, a, b []byte) int {
	if mode == rfc8949.SortLengthFirst && len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return bytes.Compare(a, b)
}

// write sends b to the output, copying it into any map key being captured.
func (s *StreamEncoder) write(b []byte) error {
	_, err := s.w.Write(b)
	return err
}

func (s *StreamEncoder) writeString(t string) error {
	_, err := io.WriteString(s.w, t)
	return err
}

// keyTee forwards writes to the output and copies them into every map
// key being captured. The encoder writes through it only while a key is
// open, so the common path has no capture check.
type keyTee struct{ s *StreamEncoder }

func (t *keyTee) Write(b []byte) (int, error) {
	for i := range t.s.stack {
		if t.s.stack[i].capturing {
			t.s.stack[i].key = append(t.s.stack[i].key, b...)
		}
	}
	return t.s.out.Write(b)
}

func (t *keyTee) WriteString(str string) (int, error) {
	for i := range t.s.stack {
		if t.s.stack[i].capturing {
			t.s.stack[i].key = append(t.s.stack[i].key, str...)
		}
	}
	return io.WriteString(t.s.out, str)
}

func (s *StreamEncoder) beginCapture() {
	if s.capturing == 0 {
		s.tee.s = s
		s.w = &s.tee
	}
	s.capturing++
}

func (s *StreamEncoder) endCapture() {
	s.capturing--
	if s.capturing == 0 {
		s.w = s.out
	}
}

// Stream returns a new StreamEncoder that writes to w.
func (e *Encoder) Stream(w io.Writer) *StreamEncoder {
	opts := e.encodeOpts()
	// Key order is verified only for modes that sort map keys.
	sorted := opts.Deterministic && opts.SortMode != rfc8949.SortNone
	return &StreamEncoder{w: w, out: w, enc: e, deterministic: sorted, sortMode: opts.SortMode}
}

// BeginArray starts a CBOR array. Pass n >= 0 for a definite-length array,
// or n = -1 for indefinite-length (Permissive mode only). The array counts
// as one item of the enclosing container.
func (s *StreamEncoder) BeginArray(n int) error {
	if n < 0 && s.enc.mode != ModePermissive {
		return ErrIndefiniteNotPermitted
	}
	if err := s.trackWrite(); err != nil {
		return err
	}
	if n < 0 {
		s.scratch[0] = wire.MajorArray | wire.AIIndefinite
		if err := s.write(s.scratch[:1]); err != nil {
			return err
		}
		s.stack = append(s.stack, containerState{remaining: -1})
		return nil
	}
	if err := s.write(wire.AppendHead(s.scratch[:0], wire.MajorArray, uint64(n))); err != nil {
		return err
	}
	s.stack = append(s.stack, containerState{remaining: n})
	return nil
}

// BeginMap starts a CBOR map. Pass n >= 0 for a definite-length map,
// or n = -1 for indefinite-length (Permissive mode only). The map counts
// as one item of the enclosing container.
func (s *StreamEncoder) BeginMap(n int) error {
	if n < 0 && s.enc.mode != ModePermissive {
		return ErrIndefiniteNotPermitted
	}
	if n > math.MaxInt/2 {
		return fmt.Errorf("%w: map of %d pairs", cbor.ErrMaxArrayLength, n)
	}
	if err := s.trackWrite(); err != nil {
		return err
	}
	if n < 0 {
		s.scratch[0] = wire.MajorMap | wire.AIIndefinite
		if err := s.write(s.scratch[:1]); err != nil {
			return err
		}
		s.stack = append(s.stack, containerState{remaining: -1, isMap: true})
		return nil
	}
	if err := s.write(wire.AppendHead(s.scratch[:0], wire.MajorMap, uint64(n))); err != nil {
		return err
	}
	// Maps count keys and values, so items needed = n*2.
	s.stack = append(s.stack, containerState{remaining: n * 2, isMap: true})
	return nil
}

// WriteValue writes a single CBOR value to the stream. For scalar kinds,
// dispatches directly to zero-alloc write methods.
func (s *StreamEncoder) WriteValue(v Value) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	switch v.Kind {
	case cbor.KindUint:
		return s.writeHead(wire.MajorUint, v.Num)
	case cbor.KindNegInt:
		return s.writeHead(wire.MajorNegInt, v.Num)
	case cbor.KindBool:
		if v.Num != 0 {
			s.scratch[0] = wire.SimpleTrue
		} else {
			s.scratch[0] = wire.SimpleFalse
		}
		return s.write(s.scratch[:1])
	case cbor.KindNull:
		s.scratch[0] = wire.SimpleNull
		return s.write(s.scratch[:1])
	case cbor.KindUndefined:
		s.scratch[0] = wire.SimpleUndefined
		return s.write(s.scratch[:1])
	case cbor.KindText:
		if !s.enc.cfg.allowInvalidUTF8 && !utf8.ValidString(v.Str) {
			return s.writeInvalidText(v.Str)
		}
		if err := s.writeHead(wire.MajorText, uint64(len(v.Str))); err != nil {
			return err
		}
		return s.writeString(v.Str)
	case cbor.KindBytes:
		if err := s.writeHead(wire.MajorBytes, uint64(len(v.Bstr))); err != nil {
			return err
		}
		return s.write(v.Bstr)
	case cbor.KindFloat32, cbor.KindFloat64:
		// Same float rules as Encode for this mode (width, NaN
		// canonicalization, non-finite rejection).
		return s.writeModeFloat(v)
	case cbor.KindSimple:
		if v.Num < 24 {
			s.scratch[0] = wire.MajorOther | byte(v.Num)
			return s.write(s.scratch[:1])
		}
		if v.Num < 32 {
			return fmt.Errorf("stream simple(%d): %w", v.Num, cbor.ErrReservedSimple)
		}
		s.scratch[0] = wire.SimpleOneByte
		s.scratch[1] = byte(v.Num)
		return s.write(s.scratch[:2])
	default:
		buf, err := rfc8949.Encode(nil, v, s.enc.encodeOpts())
		if err != nil {
			return err
		}
		return s.write(buf)
	}
}

// EndContainer closes the current container. For indefinite-length containers,
// it writes the break code. For definite-length containers, it verifies the
// correct number of items were written.
func (s *StreamEncoder) EndContainer() error {
	if len(s.stack) == 0 {
		return ErrNoOpenContainer
	}
	top := s.stack[len(s.stack)-1]
	s.stack = s.stack[:len(s.stack)-1]
	if top.capturing {
		s.endCapture()
	}
	if top.started || (top.isMap && top.written%2 == 1) {
		return ErrContainerUnderflow
	}
	if top.remaining < 0 {
		s.scratch[0] = wire.BreakCode
		return s.write(s.scratch[:1])
	}
	if top.written != top.remaining {
		return ErrContainerUnderflow
	}
	return nil
}

// Flush is a no-op for Phase 2. If w implements io.Flusher, it flushes.
func (s *StreamEncoder) Flush() error {
	if f, ok := s.out.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

func (s *StreamEncoder) writeHead(major byte, arg uint64) error {
	buf := wire.AppendHead(s.scratch[:0], major, arg)
	_, err := s.w.Write(buf)
	return err
}

// WriteUint writes a CBOR unsigned integer directly without Value construction.
func (s *StreamEncoder) WriteUint(v uint64) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	return s.writeHead(wire.MajorUint, v)
}

// WriteNegInt writes a CBOR negative integer directly. The wire value
// represents -1 - v.
func (s *StreamEncoder) WriteNegInt(v uint64) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	return s.writeHead(wire.MajorNegInt, v)
}

// WriteBytes writes a CBOR byte string directly without Value construction.
func (s *StreamEncoder) WriteBytes(b []byte) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	if err := s.writeHead(wire.MajorBytes, uint64(len(b))); err != nil {
		return err
	}
	_, err := s.w.Write(b)
	return err
}

// writeInvalidText writes t, which is not valid UTF-8, under the
// encoder's invalid-UTF-8 policy. The item has already been counted.
// Kept out of line so WriteValue's scalar paths don't grow.
//
//go:noinline
func (s *StreamEncoder) writeInvalidText(t string) error {
	if s.enc.cfg.invalidUTF8 == InvalidUTF8Reject {
		return cbor.ErrInvalidUTF8
	}
	buf, err := rfc8949.Encode(nil, cbor.Text(t), s.enc.encodeOpts())
	if err != nil {
		return err
	}
	return s.write(buf)
}

// WriteText writes a CBOR text string directly. Text that is not valid
// UTF-8 is handled by the encoder's WithInvalidUTF8 policy (rejected by
// default).
func (s *StreamEncoder) WriteText(t string) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	if !s.enc.cfg.allowInvalidUTF8 && !utf8.ValidString(t) {
		return s.writeInvalidText(t)
	}
	if err := s.writeHead(wire.MajorText, uint64(len(t))); err != nil {
		return err
	}
	_, err := io.WriteString(s.w, t)
	return err
}

// WriteBool writes a CBOR boolean directly.
func (s *StreamEncoder) WriteBool(v bool) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	b := wire.SimpleFalse
	if v {
		b = wire.SimpleTrue
	}
	s.scratch[0] = b
	return s.write(s.scratch[:1])
}

// WriteNull writes the CBOR null value directly.
func (s *StreamEncoder) WriteNull() error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	s.scratch[0] = wire.SimpleNull
	return s.write(s.scratch[:1])
}

// WriteUndefined writes the CBOR undefined value directly.
func (s *StreamEncoder) WriteUndefined() error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	s.scratch[0] = wire.SimpleUndefined
	return s.write(s.scratch[:1])
}

// WriteFloat32 writes a CBOR float. It writes what Encode writes for
// Float32(v) in the encoder's mode: a single-precision float in
// Permissive, the shortest exact width in the deterministic modes, and
// a double in CTAP2 (proposal 037 C13). Rejects NaN/Inf unless the
// encoder was constructed with AllowNonFiniteFloats.
func (s *StreamEncoder) WriteFloat32(v float32) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	f := float64(v)
	if !s.enc.cfg.allowNonFiniteFloats && (math.IsNaN(f) || math.IsInf(f, 0)) {
		return cbor.ErrNonFiniteFloat
	}
	if s.enc.mode != ModePermissive {
		return s.writeModeFloat(cbor.Float32(v))
	}
	return s.write(wire.AppendFloat32(s.scratch[:0], v))
}

// WriteFloat64 writes a CBOR float. It writes what Encode writes for
// Float64(v) in the encoder's mode: a double in Permissive and CTAP2,
// the shortest exact width in the other deterministic modes (proposal
// 037 C13). Rejects NaN/Inf unless the encoder was constructed with
// AllowNonFiniteFloats.
func (s *StreamEncoder) WriteFloat64(v float64) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	if !s.enc.cfg.allowNonFiniteFloats && (math.IsNaN(v) || math.IsInf(v, 0)) {
		return cbor.ErrNonFiniteFloat
	}
	if s.enc.mode != ModePermissive {
		return s.writeModeFloat(cbor.Float64(v))
	}
	return s.write(wire.AppendFloat64(s.scratch[:0], v))
}

// writeModeFloat writes the float v under the mode's float rules (width,
// NaN canonicalization). A float is at most 9 bytes, so this appends
// into scratch without allocating.
func (s *StreamEncoder) writeModeFloat(v Value) error {
	buf, err := rfc8949.Encode(s.scratch[:0], v, s.enc.encodeOpts())
	if err != nil {
		return err
	}
	return s.write(buf)
}

// WriteSimple writes a CBOR simple value (0-19 or 32-255) directly.
// Values 24-31 return ErrReservedSimple (RFC 8949 §3.3).
func (s *StreamEncoder) WriteSimple(v uint8) error {
	if v >= 24 && v < 32 {
		return fmt.Errorf("stream simple(%d): %w", v, cbor.ErrReservedSimple)
	}
	if err := s.trackWrite(); err != nil {
		return err
	}
	if v < 24 {
		s.scratch[0] = wire.MajorOther | v
		return s.write(s.scratch[:1])
	}
	s.scratch[0] = wire.SimpleOneByte
	s.scratch[1] = v
	return s.write(s.scratch[:2])
}

// WriteTag writes a CBOR tag header. The next write becomes the tag's
// content — caller must write exactly one item after WriteTag. The tag
// and its content count as one item of the enclosing container.
//
// The head is written immediately, so a tag 2/3 bignum written as
// WriteTag + WriteBytes keeps its content as supplied. In deterministic
// modes, pass the whole Value to WriteValue to get the RFC 8949 §3.4.3
// preferred form Encode writes (proposal 024).
func (s *StreamEncoder) WriteTag(id uint64) error {
	if err := s.startItem(false); err != nil {
		return err
	}
	return s.writeHead(wire.MajorTag, id)
}

// WriteRawCBOR writes pre-encoded CBOR bytes directly to the output
// without validation or re-encoding. The caller is responsible for
// ensuring the bytes are well-formed CBOR. Counts as one item in the
// enclosing container.
func (s *StreamEncoder) WriteRawCBOR(raw []byte) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	return s.write(raw)
}

// DecodeFrom reads exactly one CBOR value from r. A memory budget
// (WithMemoryBudget) covers the call: the bytes buffered for the item
// as well as what decoding it allocates.
func (d *Decoder) DecodeFrom(r io.Reader) (Value, error) {
	d.resetBudget()
	return rfc8949.DecodeFrom(r, d.cfg.opts)
}

// resetBudget starts a new decode operation's memory budget.
func (d *Decoder) resetBudget() {
	if d.cfg.opts.Budget != nil {
		d.cfg.opts.Budget.Allocated = 0
	}
}

// Stream returns a streaming iterator that reads CBOR values from r.
type Stream struct {
	br  *rfc8949.BufferedReader
	dec *Decoder
	val cbor.Value
	err error
}

// NewStream returns a Stream that reads CBOR values from r using d's options.
func (d *Decoder) Stream(r io.Reader) *Stream {
	return &Stream{br: rfc8949.NewBufferedReader(r), dec: d}
}

// Next advances to the next CBOR value. Returns false when no more values
// are available or an error occurred.
func (s *Stream) Next() bool {
	s.dec.resetBudget() // the budget covers one item
	v, err := rfc8949.DecodeFromBuffered(s.br, s.dec.cfg.opts)
	if err != nil {
		// Only a reader that ends between items ends the stream cleanly
		// (RFC 8742 §2): a partial last item is an error (037 C6).
		if err != io.EOF {
			s.err = err
		}
		return false
	}
	s.val = v
	return true
}

// Value returns the most recently decoded CBOR value.
func (s *Stream) Value() Value {
	return s.val
}

// Err returns the error that stopped iteration, if any. A reader that
// ends between items (io.EOF before an item starts) is the end of the
// stream, not an error. A reader that ends inside an item is: the error
// wraps ErrTruncated and io.ErrUnexpectedEOF. A DecodeError's Offset
// counts from the start of the failing item, since a reader has no
// position of its own (proposal 037 C19).
func (s *Stream) Err() error {
	return s.err
}
