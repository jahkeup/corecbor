// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package diagfmt holds the RFC 8949 §8 diagnostic-notation primitives
// shared by package cbor (Value.String) and the root package
// (Diagnostic, DiagnosticValue). It imports nothing from the module, so
// both can use it without an import cycle.
package diagfmt

import (
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// valueWriter renders a cbor.Value. Package cbor registers it at init;
// the parameter is typed any because this package can't import cbor.
var valueWriter func(b *strings.Builder, v any, compact bool)

// RegisterValueWriter is called once by package cbor.
func RegisterValueWriter(f func(b *strings.Builder, v any, compact bool)) { valueWriter = f }

// WriteValue renders v, which must be a cbor.Value.
func WriteValue(b *strings.Builder, v any, compact bool) { valueWriter(b, v, compact) }

// WriteNegInt writes the CBOR negative integer -1-n. The arithmetic is
// unsigned: for n = 2^64-1 the value is -2^64, which overflows both
// int64 and n+1.
func WriteNegInt(b *strings.Builder, n uint64) {
	b.WriteByte('-')
	if n == math.MaxUint64 {
		b.WriteString("18446744073709551616")
		return
	}
	b.WriteString(strconv.FormatUint(n+1, 10))
}

// WriteBytes writes a byte string as h'..' followed by indicator.
func WriteBytes(b *strings.Builder, p []byte, indicator string) {
	b.WriteString("h'")
	b.WriteString(hex.EncodeToString(p))
	b.WriteByte('\'')
	b.WriteString(indicator)
}

// WriteTextItem writes a text string followed by indicator. Diagnostic
// notation has no text form for invalid UTF-8, so such a string is
// written as its bytes with a comment saying what they are, instead of
// as text that would read as different, valid characters.
func WriteTextItem(b *strings.Builder, s, indicator string) {
	if !utf8.ValidString(s) {
		b.WriteString("/ text, invalid UTF-8 / ")
		WriteBytes(b, []byte(s), indicator)
		return
	}
	b.WriteByte('"')
	writeText(b, s)
	b.WriteByte('"')
	b.WriteString(indicator)
}

// WriteFloat writes f; bits (32 or 64) selects the shortest decimal
// form that round-trips at that precision.
func WriteFloat(b *strings.Builder, f float64, bits int) {
	switch {
	case math.IsInf(f, 1):
		b.WriteString("Infinity")
	case math.IsInf(f, -1):
		b.WriteString("-Infinity")
	case math.IsNaN(f):
		b.WriteString("NaN")
	case f == 0:
		if math.Signbit(f) {
			b.WriteString("-0.0")
		} else {
			b.WriteString("0.0")
		}
	default:
		s := strconv.FormatFloat(f, 'f', -1, bits)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		b.WriteString(s)
	}
}

// WriteSimple writes simple(n).
func WriteSimple(b *strings.Builder, n uint64) { fmt.Fprintf(b, "simple(%d)", n) }

// writeText writes the escaped body of a valid UTF-8 text string.
func writeText(b *strings.Builder, s string) {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(b, "\\u%04x", r)
		case !unicode.IsPrint(r):
			if r <= 0xFFFF {
				fmt.Fprintf(b, "\\u%04x", r)
			} else {
				r1, r2 := utf16Surrogates(r)
				fmt.Fprintf(b, "\\u%04x\\u%04x", r1, r2)
			}
		default:
			b.WriteRune(r)
		}
		i += size
	}
}

func utf16Surrogates(r rune) (uint16, uint16) {
	r -= 0x10000
	return uint16(0xD800 + (r>>10)&0x3FF), uint16(0xDC00 + r&0x3FF)
}
