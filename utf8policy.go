// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/rfc8949"
)

// InvalidUTF8 selects how text that is not valid UTF-8 is handled; see
// WithInvalidUTF8 (encoder) and WithInvalidUTF8Decoding (decoder).
type InvalidUTF8 = rfc8949.InvalidUTF8

const (
	// InvalidUTF8Reject returns ErrInvalidUTF8 (the encoder default).
	InvalidUTF8Reject = rfc8949.InvalidUTF8Reject
	// InvalidUTF8Allow keeps the bytes as a text string unchanged; not
	// conformant (RFC 8949 §3.1). The decoder default.
	InvalidUTF8Allow = rfc8949.InvalidUTF8Allow
	// InvalidUTF8Replace substitutes U+FFFD for each invalid byte.
	InvalidUTF8Replace = rfc8949.InvalidUTF8Replace
	// InvalidUTF8Lossless keeps the exact bytes in conformant CBOR: tag
	// 273 (WTF-8) or a byte string.
	InvalidUTF8Lossless = rfc8949.InvalidUTF8Lossless
)

// Tags for non-UTF-8 text carried in a byte string (IANA).
const (
	TagCESU8 = cbor.TagCESU8
	TagWTF8  = cbor.TagWTF8
	TagMUTF8 = cbor.TagMUTF8
)

// TextLossless returns Text(s) when s is valid UTF-8 and otherwise the
// InvalidUTF8Lossless form; see cbor.TextLossless.
func TextLossless(s string) Value { return cbor.TextLossless(s) }

// AsText returns the string carried by a text string, a byte string, or
// tag 272/273/274 around a byte string; see cbor.AsText.
func AsText(v Value) (string, error) { return cbor.AsText(v) }
