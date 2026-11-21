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
	"github.com/jahkeup/corecbor/wire"
)

type DiagnosticOption func(*diagOpts)

type diagOpts struct {
	compact    bool
	indicators bool
}

func DiagCompact() DiagnosticOption {
	return func(o *diagOpts) { o.compact = true }
}

// DiagIndicators enables RFC 8949 §8.1 encoding indicators. It only has
// an effect on Diagnostic, which sees the encoded bytes.
func DiagIndicators() DiagnosticOption {
	return func(o *diagOpts) { o.indicators = true }
}

// Diagnostic decodes data and renders it in RFC 8949 §8 diagnostic
// notation. With DiagIndicators, the §8.1 encoding indicators are
// rendered from the source bytes: "_" for indefinite-length items, and
// "_0".."_3" for arguments (and floats) not in their shortest form.
func Diagnostic(data []byte, opts ...DiagnosticOption) (string, error) {
	dec := NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return "", err
	}
	o := &diagOpts{}
	for _, fn := range opts {
		fn(o)
	}
	if o.indicators {
		var b strings.Builder
		if _, ok := diagWriteRaw(&b, data, 0, 0, o, true); ok {
			return b.String(), nil
		}
		// data already decoded, so the walk can't fail on it; fall back
		// to the value rendering rather than return partial output.
	}
	return DiagnosticValue(v, opts...), nil
}

// DiagnosticValue renders v in RFC 8949 §8 diagnostic notation. A Value
// doesn't record how it was encoded, so DiagIndicators has no effect
// here; use Diagnostic on the encoded bytes to see indicators.
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
	switch v.Kind {
	case cbor.KindUint:
		b.WriteString(strconv.FormatUint(v.UintVal(), 10))

	case cbor.KindNegInt:
		diagWriteNegInt(b, v.NegIntVal())

	case cbor.KindBytes:
		b.WriteString("h'")
		b.WriteString(hex.EncodeToString(v.BytesVal()))
		b.WriteByte('\'')

	case cbor.KindText:
		diagWriteTextItem(b, v.TextVal(), "")

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

// diagWriteNegInt writes the CBOR negative integer -1-n. The arithmetic
// is unsigned: for n = 2^64-1 the value is -2^64, which overflows both
// int64 and n+1.
func diagWriteNegInt(b *strings.Builder, n uint64) {
	b.WriteByte('-')
	if n == math.MaxUint64 {
		b.WriteString("18446744073709551616")
		return
	}
	b.WriteString(strconv.FormatUint(n+1, 10))
}

// diagWriteTextItem writes a text string followed by indicator.
// Diagnostic notation has no text form for invalid UTF-8, so such a
// string is written as its bytes with a comment saying what they are,
// instead of as text that would read as different, valid characters.
func diagWriteTextItem(b *strings.Builder, s, indicator string) {
	if !utf8.ValidString(s) {
		b.WriteString("/ text, invalid UTF-8 / h'")
		b.WriteString(hex.EncodeToString([]byte(s)))
		b.WriteByte('\'')
		b.WriteString(indicator)
		return
	}
	b.WriteByte('"')
	diagWriteText(b, s)
	b.WriteByte('"')
	b.WriteString(indicator)
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

// diagWriteText writes the escaped body of a valid UTF-8 text string.
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

// argIndicator returns the RFC 8949 §8.1 encoding indicator for a head
// whose argument isn't in its shortest form ("_0" for AI 24 through "_3"
// for AI 27), or "" when it is.
func argIndicator(h wire.HeadResult) string {
	if h.AI < wire.AI1Byte || h.AI > wire.AI8Bytes || h.IsShortest() {
		return ""
	}
	return "_" + strconv.Itoa(int(h.AI-wire.AI1Byte))
}

// floatIndicator returns "_2" or "_3" when a float is encoded wider than
// the shortest width that represents it exactly, or "".
func floatIndicator(ai byte, f float64) string {
	switch ai {
	case wire.AI4Bytes:
		if _, ok := wire.EncodeFloat16(f); ok {
			return "_2"
		}
	case wire.AI8Bytes:
		if _, ok := wire.EncodeFloat16(f); ok || wire.CanFloat32Lossless(f) {
			return "_3"
		}
	}
	return ""
}

// diagWriteRaw renders the item at src[off:] with encoding indicators
// and returns the offset after it. ok is false if the bytes aren't a
// well-formed item; Diagnostic validates them first, so that only
// guards against inconsistencies. top mirrors the decoder stripping
// leading self-describe tags (55799).
func diagWriteRaw(b *strings.Builder, src []byte, off, depth int, o *diagOpts, top bool) (next int, ok bool) {
	if off >= len(src) || depth > 512 {
		return off, false
	}
	h := wire.ParseHead(src[off:])
	if h.N == 0 || (h.AI >= 28 && h.AI <= 30) {
		return off, false
	}
	pos := off + h.N
	sep, kv := ", ", ": "
	if o.compact {
		sep, kv = ",", ":"
	}
	indef := h.AI == wire.AIIndefinite

	switch h.Major {
	case wire.MajorUint:
		if indef {
			return off, false
		}
		b.WriteString(strconv.FormatUint(h.Arg, 10))
		b.WriteString(argIndicator(h))
		return pos, true

	case wire.MajorNegInt:
		if indef {
			return off, false
		}
		diagWriteNegInt(b, h.Arg)
		b.WriteString(argIndicator(h))
		return pos, true

	case wire.MajorBytes, wire.MajorText:
		if indef {
			b.WriteString("(_ ")
			for i := 0; ; i++ {
				if pos >= len(src) {
					return off, false
				}
				if src[pos] == wire.BreakCode {
					b.WriteByte(')')
					return pos + 1, true
				}
				if src[pos]&0xe0 != h.Major {
					return off, false
				}
				if i > 0 {
					b.WriteString(sep)
				}
				n, ok := diagWriteRaw(b, src, pos, depth+1, o, false)
				if !ok {
					return off, false
				}
				pos = n
			}
		}
		if h.Arg > uint64(len(src)-pos) {
			return off, false
		}
		end := pos + int(h.Arg)
		if h.Major == wire.MajorBytes {
			b.WriteString("h'")
			b.WriteString(hex.EncodeToString(src[pos:end]))
			b.WriteByte('\'')
			b.WriteString(argIndicator(h))
		} else {
			diagWriteTextItem(b, string(src[pos:end]), argIndicator(h))
		}
		return end, true

	case wire.MajorArray, wire.MajorMap:
		isMap := h.Major == wire.MajorMap
		if isMap {
			b.WriteByte('{')
		} else {
			b.WriteByte('[')
		}
		if indef {
			b.WriteString("_ ")
		} else if ind := argIndicator(h); ind != "" {
			b.WriteString(ind)
			b.WriteByte(' ')
		}
		writeItem := func(i uint64) bool {
			if i > 0 {
				b.WriteString(sep)
			}
			n, ok := diagWriteRaw(b, src, pos, depth+1, o, false)
			if !ok {
				return false
			}
			pos = n
			if isMap {
				b.WriteString(kv)
				if n, ok = diagWriteRaw(b, src, pos, depth+1, o, false); !ok {
					return false
				}
				pos = n
			}
			return true
		}
		if indef {
			for i := uint64(0); ; i++ {
				if pos >= len(src) {
					return off, false
				}
				if src[pos] == wire.BreakCode {
					pos++
					break
				}
				if !writeItem(i) {
					return off, false
				}
			}
		} else {
			// Every item takes at least one byte; don't loop on a count
			// the input can't hold.
			if h.Arg > uint64(len(src)-pos) {
				return off, false
			}
			for i := range h.Arg {
				if !writeItem(i) {
					return off, false
				}
			}
		}
		if isMap {
			b.WriteByte('}')
		} else {
			b.WriteByte(']')
		}
		return pos, true

	case wire.MajorTag:
		if indef {
			return off, false
		}
		if top && h.Arg == cbor.TagSelfDescribe {
			return diagWriteRaw(b, src, pos, depth, o, true)
		}
		b.WriteString(strconv.FormatUint(h.Arg, 10))
		b.WriteString(argIndicator(h))
		b.WriteByte('(')
		n, ok := diagWriteRaw(b, src, pos, depth+1, o, false)
		if !ok {
			return off, false
		}
		b.WriteByte(')')
		return n, true

	default: // major type 7
		switch {
		case h.AI < 20:
			fmt.Fprintf(b, "simple(%d)", h.AI)
		case h.AI == 20:
			b.WriteString("false")
		case h.AI == 21:
			b.WriteString("true")
		case h.AI == 22:
			b.WriteString("null")
		case h.AI == 23:
			b.WriteString("undefined")
		case h.AI == wire.AI1Byte:
			fmt.Fprintf(b, "simple(%d)", h.Arg)
		case h.AI == wire.AI2Bytes:
			diagWriteFloat(b, wire.DecodeFloat16(uint16(h.Arg)), 64)
		case h.AI == wire.AI4Bytes:
			f := float64(math.Float32frombits(uint32(h.Arg)))
			diagWriteFloat(b, f, 32)
			b.WriteString(floatIndicator(h.AI, f))
		case h.AI == wire.AI8Bytes:
			f := math.Float64frombits(h.Arg)
			diagWriteFloat(b, f, 64)
			b.WriteString(floatIndicator(h.AI, f))
		default:
			return off, false
		}
		return pos, true
	}
}
