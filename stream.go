package corecbor

import (
	"errors"
	"io"

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
	w     io.Writer
	enc   *Encoder
	stack []containerState
}

type containerState struct {
	remaining int // -1 for indefinite
	written   int
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
	if len(s.stack) > 0 {
		top := &s.stack[len(s.stack)-1]
		if top.remaining >= 0 && top.written >= top.remaining {
			return errors.New("corecbor: container overflow")
		}
		top.written++
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
