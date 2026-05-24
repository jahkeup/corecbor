// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jahkeup/corecbor/cbor"
)

type DiagnosticOption func(*diagOpts)

type diagOpts struct {
	compact    bool
	indicators bool
}

func DiagCompact() DiagnosticOption {
	return func(o *diagOpts) { o.compact = true }
}

func DiagIndicators() DiagnosticOption {
	return func(o *diagOpts) { o.indicators = true }
}

func Diagnostic(data []byte, opts ...DiagnosticOption) (string, error) {
	dec := NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return "", err
	}
	return DiagnosticValue(v, opts...), nil
}

func DiagnosticValue(v Value, opts ...DiagnosticOption) string {
	o := &diagOpts{}
	for _, fn := range opts {
		fn(o)
	}
	var b strings.Builder
	diagWrite(&b, v, o)
	return b.String()
}

func diagWrite(b *strings.Builder, v Value, o *diagOpts) {
	switch v.Kind() {
	case cbor.KindUint:
		b.WriteString(strconv.FormatUint(v.UintVal(), 10))

	case cbor.KindNegInt:
		n := v.NegIntVal()
		b.WriteByte('-')
		b.WriteString(strconv.FormatUint(n+1, 10))

	case cbor.KindBytes:
		b.WriteString("h'")
		b.WriteString(hex.EncodeToString(v.BytesVal()))
		b.WriteByte('\'')

	case cbor.KindText:
		b.WriteByte('"')
		diagWriteText(b, v.TextVal())
		b.WriteByte('"')

	case cbor.KindArray:
		b.WriteByte('[')
		for i, item := range v.Array() {
			if i > 0 {
				if o.compact {
					b.WriteByte(',')
				} else {
					b.WriteString(", ")
				}
			}
			diagWrite(b, item, o)
		}
		b.WriteByte(']')

	case cbor.KindMap:
		b.WriteByte('{')
		for i, entry := range v.Map() {
			if i > 0 {
				if o.compact {
					b.WriteByte(',')
				} else {
					b.WriteString(", ")
				}
			}
			diagWrite(b, entry.Key, o)
			if o.compact {
				b.WriteByte(':')
			} else {
				b.WriteString(": ")
			}
			diagWrite(b, entry.Value, o)
		}
		b.WriteByte('}')

	case cbor.KindTag:
		b.WriteString(strconv.FormatUint(v.TagID(), 10))
		b.WriteByte('(')
		diagWrite(b, v.TagInner(), o)
		b.WriteByte(')')

	case cbor.KindBool:
		if v.BoolVal() {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}

	case cbor.KindNull:
		b.WriteString("null")

	case cbor.KindUndefined:
		b.WriteString("undefined")

	case cbor.KindFloat32:
		diagWriteFloat(b, float64(v.Float32Val()), 32)

	case cbor.KindFloat64:
		diagWriteFloat(b, v.Float64Val(), 64)

	case cbor.KindSimple:
		fmt.Fprintf(b, "simple(%d)", v.SimpleVal())

	default:
		b.WriteString("?")
	}
}

func diagWriteFloat(b *strings.Builder, f float64, bits int) {
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

func diagWriteText(b *strings.Builder, s string) {
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
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(b, "\\u%04x", s[i])
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
