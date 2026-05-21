// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import "errors"

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
var ErrOverflow = errors.New("cbor: integer overflow for target type")

// ErrNotPointer indicates Unmarshal was called with a non-pointer target.
var ErrNotPointer = errors.New("cbor: unmarshal requires a pointer argument")

// ErrUnsupportedType indicates a Go type that cannot be marshaled to CBOR.
var ErrUnsupportedType = errors.New("cbor: unsupported type")

// defaultEncoder is the package-level encoder for Marshal (CoreDeterministic).
var defaultEncoder = New(ModeCoreDeterministic)

// defaultDecoder is the package-level decoder for Unmarshal (forgiving).
var defaultDecoder = NewDecoder()

// Marshal encodes v into CBOR using CoreDeterministic mode.
// It builds a Value tree from v via reflection, then encodes it.
func Marshal(v any) ([]byte, error) {
	return defaultEncoder.Marshal(v)
}

// Unmarshal decodes CBOR data into v, which must be a non-nil pointer.
// It uses a forgiving decoder (accepts all well-formed CBOR).
func Unmarshal(data []byte, v any) error {
	return defaultDecoder.Unmarshal(data, v)
}

// Marshal encodes v into CBOR using the encoder's mode settings.
func (e *Encoder) Marshal(v any) ([]byte, error) {
	val, err := goToValue(v, e.encodeOpts())
	if err != nil {
		return nil, err
	}
	return e.Encode(nil, val)
}

// Unmarshal decodes CBOR data into v using the decoder's strictness settings.
// v must be a non-nil pointer.
func (d *Decoder) Unmarshal(data []byte, v any) error {
	val, err := d.Decode(data)
	if err != nil {
		return err
	}
	return unmarshalValue(val, v)
}
