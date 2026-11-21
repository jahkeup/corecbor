// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package utf8x holds the UTF-8 helpers behind the invalid-UTF-8 text
// policies (proposal 035): per-byte replacement and WTF-8 detection.
package utf8x

import "unicode/utf8"

// AppendReplaced appends s to dst with U+FFFD substituted for each byte
// that is not part of a valid UTF-8 sequence. This is exactly what
// ranging over s yields (utf8.RuneError per invalid byte), and what
// encoding/json does when it decodes invalid UTF-8.
func AppendReplaced(dst []byte, s string) []byte {
	for _, r := range s {
		dst = utf8.AppendRune(dst, r)
	}
	return dst
}

// Replaced returns s with U+FFFD substituted per invalid byte (see
// AppendReplaced).
func Replaced(s string) string {
	return string(AppendReplaced(make([]byte, 0, len(s)+8), s))
}

// IsWTF8 reports whether s is well-formed WTF-8 that is not valid UTF-8
// (https://simonsapin.github.io/wtf-8/): every sequence is valid UTF-8
// except for surrogate code points U+D800–U+DFFF encoded as three-byte
// sequences, and no lead surrogate is immediately followed by a trail
// surrogate (such a pair must be encoded as one four-byte sequence).
// Valid UTF-8 returns false: it needs no special representation.
func IsWTF8(s string) bool {
	surrogate := false
	prevLead := false
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			i++
			prevLead = false
			continue
		}
		if c == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2]&0xC0 == 0x80 {
			lead := s[i+1] <= 0xAF // U+D800–U+DBFF
			if !lead && prevLead {
				return false // a surrogate pair must be one four-byte sequence
			}
			surrogate = true
			prevLead = lead
			i += 3
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		i += size
		prevLead = false
	}
	return surrogate
}
