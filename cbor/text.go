// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"fmt"
	"unicode/utf8"

	"github.com/jahkeup/corecbor/internal/utf8x"
)

// TextLossless returns Text(s) when s is valid UTF-8, and otherwise a
// conformant form that keeps s's exact bytes: tag 273 (WTF-8) around a
// byte string when s is well-formed WTF-8, or a plain byte string. It
// lets a caller opt in to lossless text field by field (proposal 035);
// AsText reverses it.
func TextLossless(s string) Value {
	if utf8.ValidString(s) {
		return Text(s)
	}
	b := Bytes([]byte(s))
	if utf8x.IsWTF8(s) {
		return MakeTag(TagWTF8, b)
	}
	return b
}

// AsText returns the string carried by v: a text string's bytes, or the
// exact bytes of a byte string or of tag 272 (CESU-8), 273 (WTF-8) or
// 274 (MUTF-8) around a byte string. It returns an error wrapping
// ErrTypeMismatch for anything else. Whether a byte string is text is
// for the caller's schema to decide.
func AsText(v Value) (string, error) {
	switch v.Kind {
	case KindText:
		return v.Str, nil
	case KindBytes:
		return string(v.Bstr), nil
	case KindTag:
		switch v.TagID() {
		case TagCESU8, TagWTF8, TagMUTF8:
			if inner := v.TagInner(); inner.Kind == KindBytes {
				return string(inner.Bstr), nil
			}
		}
	}
	return "", fmt.Errorf("%w: AsText: kind %d is not text", ErrTypeMismatch, v.Kind)
}
