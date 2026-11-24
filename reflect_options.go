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

// DisallowDroppedTags makes Unmarshal fail with an error wrapping
// ErrTypeMismatch where it would store a tag's content into a target
// that has no place for the tag number, instead of dropping the number
// (the forgiving default): 999(5) into an int, 1(1363896240) into an
// int64. Targets that keep tags are unaffected: Value, any, RawTag, an
// Unmarshaler, time.Time for tags 0 and 1, big.Int for tags 2 and 3,
// and struct fields that declare the tag. Tag 55799 (self-describe),
// which carries no meaning, is still dropped (proposal 037 C15).
func DisallowDroppedTags() DecoderOption {
	return func(c *decodeConfig) { c.disallowDroppedTags = true }
}

// DisallowUndefined makes Unmarshal fail with an error wrapping
// ErrTypeMismatch where it would store undefined (f7) into a target
// that can't tell it from null: by default both leave a Go value at its
// zero value, and any gets nil for both. A Value or an Unmarshaler
// still receives undefined as it is (proposal 037 C16).
func DisallowUndefined() DecoderOption {
	return func(c *decodeConfig) { c.disallowUndefined = true }
}

// strictUnmarshaler backs UnmarshalStrict. It has no internal arena, so
// it is safe for concurrent use.
var strictUnmarshaler = StrictDecoder(WithoutInternalArena(), DisallowDroppedTags(), DisallowUndefined())

// UnmarshalStrict is Unmarshal with StrictDecoder's checks (spec §3.2:
// indefinite lengths, non-shortest arguments, invalid UTF-8, duplicate
// map keys, non-finite floats, null map keys and invalid tag content
// are rejected), DisallowDroppedTags and DisallowUndefined. Package
// Unmarshal stays forgiving; use UnmarshalStrict, or a StrictDecoder's
// Unmarshal with options of your choice, for input that must be
// canonical and lose nothing (proposal 037 C17). It is safe for
// concurrent use.
func UnmarshalStrict(data []byte, v any) error {
	return strictUnmarshaler.Unmarshal(data, v)
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
// earlier than v0.5.0.
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
