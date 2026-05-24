// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"errors"
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

// EncodeTo writes the CBOR encoding of v to w.
func (e *Encoder) EncodeTo(w io.Writer, v Value) error {
	return rfc8949.EncodeTo(w, v, e.encodeOpts())
}

// StreamEncoder allows imperative stream writing of CBOR data.
type StreamEncoder struct {
	w       io.Writer
	enc     *Encoder
	stack   []containerState
	scratch [9]byte
}

type containerState struct {
	remaining int // -1 for indefinite
	written   int
}

func (s *StreamEncoder) trackWrite() error {
	if len(s.stack) == 0 {
		return nil
	}
	top := &s.stack[len(s.stack)-1]
	if top.remaining >= 0 && top.written >= top.remaining {
		return errors.New("corecbor: container overflow")
	}
	top.written++
	return nil
}

// Stream returns a new StreamEncoder that writes to w.
func (e *Encoder) Stream(w io.Writer) *StreamEncoder {
	return &StreamEncoder{w: w, enc: e}
}

// BeginArray starts a CBOR array. Pass n >= 0 for a definite-length array,
// or n = -1 for indefinite-length (Permissive mode only).
func (s *StreamEncoder) BeginArray(n int) error {
	if n < 0 {
		if s.enc.mode != ModePermissive {
			return ErrIndefiniteNotPermitted
		}
		_, err := s.w.Write([]byte{wire.MajorArray | wire.AIIndefinite})
		if err != nil {
			return err
		}
		s.stack = append(s.stack, containerState{remaining: -1})
		return nil
	}
	head := wire.AppendHead(nil, wire.MajorArray, uint64(n))
	_, err := s.w.Write(head)
	if err != nil {
		return err
	}
	s.stack = append(s.stack, containerState{remaining: n})
	return nil
}

// BeginMap starts a CBOR map. Pass n >= 0 for a definite-length map,
// or n = -1 for indefinite-length (Permissive mode only).
func (s *StreamEncoder) BeginMap(n int) error {
	if n < 0 {
		if s.enc.mode != ModePermissive {
			return ErrIndefiniteNotPermitted
		}
		_, err := s.w.Write([]byte{wire.MajorMap | wire.AIIndefinite})
		if err != nil {
			return err
		}
		s.stack = append(s.stack, containerState{remaining: -1})
		return nil
	}
	head := wire.AppendHead(nil, wire.MajorMap, uint64(n))
	_, err := s.w.Write(head)
	if err != nil {
		return err
	}
	// Maps count key-value pairs, so items needed = n*2
	s.stack = append(s.stack, containerState{remaining: n * 2})
	return nil
}

// WriteValue writes a single CBOR value to the stream.
func (s *StreamEncoder) WriteValue(v Value) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	return rfc8949.EncodeTo(s.w, v, s.enc.encodeOpts())
}

// EndContainer closes the current container. For indefinite-length containers,
// it writes the break code. For definite-length containers, it verifies the
// correct number of items were written.
func (s *StreamEncoder) EndContainer() error {
	if len(s.stack) == 0 {
		return errors.New("corecbor: no open container")
	}
	top := s.stack[len(s.stack)-1]
	s.stack = s.stack[:len(s.stack)-1]
	if top.remaining < 0 {
		_, err := s.w.Write([]byte{wire.BreakCode})
		return err
	}
	if top.written != top.remaining {
		return errors.New("corecbor: container underflow")
	}
	return nil
}

// Flush is a no-op for Phase 2. If w implements io.Flusher, it flushes.
func (s *StreamEncoder) Flush() error {
	if f, ok := s.w.(interface{ Flush() error }); ok {
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

// WriteText writes a CBOR text string directly. Validates UTF-8 unless
// the encoder was constructed with AllowInvalidUTF8.
func (s *StreamEncoder) WriteText(t string) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	if !s.enc.cfg.allowInvalidUTF8 && !utf8.ValidString(t) {
		return cbor.ErrInvalidUTF8
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
	_, err := s.w.Write(s.scratch[:1])
	return err
}

// WriteNull writes the CBOR null value directly.
func (s *StreamEncoder) WriteNull() error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	s.scratch[0] = wire.SimpleNull
	_, err := s.w.Write(s.scratch[:1])
	return err
}

// WriteUndefined writes the CBOR undefined value directly.
func (s *StreamEncoder) WriteUndefined() error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	s.scratch[0] = wire.SimpleUndefined
	_, err := s.w.Write(s.scratch[:1])
	return err
}

// WriteFloat32 writes a CBOR float32 directly. Rejects NaN/Inf unless
// the encoder was constructed with AllowNonFiniteFloats.
func (s *StreamEncoder) WriteFloat32(v float32) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	f := float64(v)
	if !s.enc.cfg.allowNonFiniteFloats && (math.IsNaN(f) || math.IsInf(f, 0)) {
		return cbor.ErrNonFiniteFloat
	}
	buf := wire.AppendFloat32(s.scratch[:0], v)
	_, err := s.w.Write(buf)
	return err
}

// WriteFloat64 writes a CBOR float64 directly. Rejects NaN/Inf unless
// the encoder was constructed with AllowNonFiniteFloats.
func (s *StreamEncoder) WriteFloat64(v float64) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	if !s.enc.cfg.allowNonFiniteFloats && (math.IsNaN(v) || math.IsInf(v, 0)) {
		return cbor.ErrNonFiniteFloat
	}
	buf := wire.AppendFloat64(s.scratch[:0], v)
	_, err := s.w.Write(buf)
	return err
}

// WriteSimple writes a CBOR simple value (0-19 or 32-255) directly.
func (s *StreamEncoder) WriteSimple(v uint8) error {
	if err := s.trackWrite(); err != nil {
		return err
	}
	if v < 24 {
		s.scratch[0] = wire.MajorOther | v
		_, err := s.w.Write(s.scratch[:1])
		return err
	}
	s.scratch[0] = wire.SimpleOneByte
	s.scratch[1] = v
	_, err := s.w.Write(s.scratch[:2])
	return err
}

// WriteTag writes a CBOR tag header. The next write becomes the tag's
// content — caller must write exactly one item after WriteTag.
func (s *StreamEncoder) WriteTag(id uint64) error {
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
	_, err := s.w.Write(raw)
	return err
}

// DecodeFrom reads exactly one CBOR value from r.
func (d *Decoder) DecodeFrom(r io.Reader) (Value, error) {
	return rfc8949.DecodeFrom(r, d.cfg.opts)
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
	v, err := rfc8949.DecodeFromBuffered(s.br, s.dec.cfg.opts)
	if err != nil {
		if !errors.Is(err, cbor.ErrTruncated) && err != io.EOF {
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

// Err returns the error that stopped iteration, if any. io.EOF and
// truncation at the boundary are not errors (they indicate end of stream).
func (s *Stream) Err() error {
	return s.err
}
