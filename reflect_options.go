// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import "errors"

// Reflection options and sentinels (proposal 025).

// ErrUnknownField indicates a map key that names no field of the
// target struct, under DisallowUnknownFields.
var ErrUnknownField = errors.New("cbor: unknown struct field")

// ErrArrayLength indicates an array whose length doesn't match a
// toarray struct: more items than fields, or fewer when a missing
// trailing field isn't a pointer.
var ErrArrayLength = errors.New("cbor: array length doesn't match toarray struct")

// DisallowUnknownFields makes Unmarshal into a struct fail with
// ErrUnknownField when a map key names no field, instead of skipping
// the entry (the forgiving default).
func DisallowUnknownFields() DecoderOption {
	return func(c *decodeConfig) { c.disallowUnknown = true }
}

// WithCaseInsensitiveFieldNames makes struct decoding match a text key
// against field names exactly first, then case-insensitively (the
// encoding/json rule). Without it, only the exact key for the default
// naming matches, as in v0.2. When a map carries both an exact and a
// case-insensitive match for one field, the exact one is used; with
// DisallowUnknownFields the other is an error.
func WithCaseInsensitiveFieldNames() DecoderOption {
	return func(c *decodeConfig) { c.caseInsensitive = true }
}

// WithLegacyNoTextBinaryUnmarshal stops Unmarshal from calling
// encoding.TextUnmarshaler and encoding.BinaryUnmarshaler, as v0.2.2
// did: text and byte strings are stored directly into string- and
// []byte-kinded targets that implement them, and other implementers
// get a type mismatch.
//
// Deprecated: v0.2 compatibility only (proposal 025); removed no
// earlier than v0.32.0.
func WithLegacyNoTextBinaryUnmarshal() DecoderOption {
	return func(c *decodeConfig) { c.legacyNoTextBinary = true }
}

// WithGoFieldNames keys untagged struct fields by the Go field name
// as-is ("UserID", not "userid"), matching encoding/json and
// fxamacker/cbor. Without it, untagged fields use strings.ToLower of the
// field name, as in v0.2. Decode such output with
// WithCaseInsensitiveFieldNames.
func WithGoFieldNames() Option {
	return func(c *encodeConfig) { c.goNames = true }
}
