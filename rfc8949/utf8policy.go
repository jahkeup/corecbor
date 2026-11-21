// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"fmt"
	"unicode/utf8"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/internal/utf8x"
	"github.com/jahkeup/corecbor/wire"
)

// InvalidUTF8 selects how text that is not valid UTF-8 is handled
// (proposal 035). Valid UTF-8 is unaffected by every policy.
type InvalidUTF8 int

const (
	// InvalidUTF8Reject returns ErrInvalidUTF8 (encoder default).
	InvalidUTF8Reject InvalidUTF8 = iota
	// InvalidUTF8Allow writes or accepts the bytes as a text string
	// unchanged. Not conformant (RFC 8949 §3.1). The decoder's default.
	InvalidUTF8Allow
	// InvalidUTF8Replace substitutes U+FFFD for each byte that is not
	// part of a valid UTF-8 sequence, exactly as ranging over a Go
	// string does. Conformant, lossy.
	InvalidUTF8Replace
	// InvalidUTF8Lossless writes conformant CBOR that preserves the
	// exact bytes: tag 273 (WTF-8) when the string is well-formed WTF-8,
	// otherwise a plain byte string (major type 2).
	InvalidUTF8Lossless
)

// encodeInvalidText writes s, which failed UTF-8 validation, under the
// configured policy. It is out of line so the valid-text fast paths
// only pay for the validation they already did.
//
//go:noinline
func encodeInvalidText(dst []byte, s string, opts *EncodeOpts) ([]byte, error) {
	switch opts.InvalidUTF8 {
	case InvalidUTF8Reject:
		return dst, fmt.Errorf("encode text: %w", cbor.ErrInvalidUTF8)
	case InvalidUTF8Allow:
		dst = wire.AppendHead(dst, wire.MajorText, uint64(len(s)))
		return append(dst, s...), nil
	case InvalidUTF8Replace:
		r := utf8x.AppendReplaced(nil, s)
		dst = wire.AppendHead(dst, wire.MajorText, uint64(len(r)))
		return append(dst, r...), nil
	case InvalidUTF8Lossless:
		if utf8x.IsWTF8(s) {
			dst = wire.AppendHead(dst, wire.MajorTag, cbor.TagWTF8)
		}
		dst = wire.AppendHead(dst, wire.MajorBytes, uint64(len(s)))
		return append(dst, s...), nil
	default:
		return dst, fmt.Errorf("%w: unknown InvalidUTF8 policy %d", cbor.ErrInvalidOption, opts.InvalidUTF8)
	}
}

// textNeedsPolicy reports whether s must go through encodeInvalidText:
// validation is enabled and s is not valid UTF-8.
func textNeedsPolicy(s string, opts *EncodeOpts) bool {
	return !opts.AllowInvalidUTF8 && !opts.SkipUTF8Validation && !utf8.ValidString(s)
}

// replaceInvalidText returns s with U+FFFD substituted per invalid byte
// when the decoder is configured to normalize, and s otherwise.
func replaceInvalidText(s string, opts *DecodeOpts) string {
	if opts.ReplaceInvalidUTF8 && !utf8.ValidString(s) {
		return utf8x.Replaced(s)
	}
	return s
}
