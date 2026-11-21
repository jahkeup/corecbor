// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"errors"
	"reflect"
	"sync"

	"github.com/jahkeup/corecbor/cbor"
)

// Marshaler is the interface implemented by types that can marshal
// themselves into a valid CBOR encoding.
type Marshaler interface {
	MarshalCBOR() ([]byte, error)
}

// Unmarshaler is the interface implemented by types that can unmarshal
// a CBOR encoding of themselves.
type Unmarshaler interface {
	UnmarshalCBOR([]byte) error
}

// ErrOverflow indicates that a CBOR integer value overflows the target
// Go type (e.g., uint64 max into int64, or negint into uint).
var ErrOverflow = cbor.ErrOverflow

// ErrNotPointer indicates Unmarshal was called with a non-pointer target.
var ErrNotPointer = errors.New("cbor: unmarshal requires a pointer argument")

// ErrUnsupportedType indicates a Go type that cannot be marshaled to CBOR.
var ErrUnsupportedType = errors.New("cbor: unsupported type")

// defaultEncoder is the package-level encoder for Marshal
// (CoreDeterministic). It is shared across goroutines, so it must come
// from NewShared.
var defaultEncoder = NewShared(ModeCoreDeterministic)

// defaultDecoder serves package-level helpers that don't use the
// internal arena (DecodeSequence). It has no per-call mutable state.
var defaultDecoder = NewDecoder(WithoutInternalArena())

// decoderPool hands each package-level Unmarshal call its own
// arena-backed Decoder, so concurrent calls never share an arena.
var decoderPool = sync.Pool{New: func() any { return NewDecoder() }}

// Marshal encodes v into CBOR using CoreDeterministic mode.
// It builds a Value tree from v via reflection, then encodes it.
// Marshal is safe for concurrent use.
func Marshal(v any) ([]byte, error) {
	return defaultEncoder.Marshal(v)
}

// Unmarshal decodes CBOR data into v, which must be a non-nil pointer.
// It uses a forgiving decoder (accepts all well-formed CBOR).
// Unmarshal is safe for concurrent use, and everything it stores in v
// is independent of data and of any decoder storage.
func Unmarshal(data []byte, v any) error {
	d := decoderPool.Get().(*Decoder)
	defer decoderPool.Put(d)
	return d.Unmarshal(data, v)
}

// Marshal encodes v into CBOR using the encoder's mode settings.
func (e *Encoder) Marshal(v any) ([]byte, error) {
	val, err := goToValue(v, &marshalOpts{EncodeOpts: e.encodeOpts(), goNames: e.cfg.goNames})
	if err != nil {
		return nil, err
	}
	return e.Encode(nil, val)
}

// Unmarshal decodes CBOR data into v using the decoder's strictness settings.
// v must be a non-nil pointer.
//
// Every Unmarshaler reached during decoding (including RawMessage and
// RawTag) receives its item's bytes exactly as they appear in data,
// after data has passed the decoder's strictness checks.
func (d *Decoder) Unmarshal(data []byte, v any) error {
	val, err := d.Decode(data)
	if err != nil {
		return err
	}
	u := unmarshalState{
		clone:              d.arena != nil || d.cfg.opts.Arena != nil || d.cfg.opts.ZeroCopy,
		lossless:           d.cfg.textLossless,
		disallowUnknown:    d.cfg.disallowUnknown,
		caseInsensitive:    d.cfg.caseInsensitive,
		legacyNoTextBinary: d.cfg.legacyNoTextBinary,
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer && !rv.IsNil() && needsRaw(rv.Elem().Type()) {
		r := rawState{unmarshalState: u, opts: d.cfg.opts}
		r.opts.Arena, r.opts.Budget = nil, nil // already validated and charged
		return r.rawToGo(stripSelfDescribe(data), val, rv.Elem())
	}
	return unmarshalValue(val, v, u)
}
