// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/internal/diagfmt"
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

// Diagnostic validates data and renders it in RFC 8949 §8 diagnostic
// notation from the source bytes, so every map entry appears as
// encoded, including duplicate keys that decoding would resolve. With
// DiagIndicators, the §8.1 encoding indicators are also shown: "_" for
// indefinite-length items, and "_0".."_3" for arguments (and floats)
// not in their shortest form.
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
	// Render from the bytes, not the decoded Value: decoding resolves
	// duplicate map keys (last wins), which would hide entries that are
	// in the input (RFC 8949 §5.6, §8).
	var b strings.Builder
	if _, ok := diagWriteRaw(&b, data, 0, 0, o, true); ok {
		return b.String(), nil
	}
	// data already decoded, so the walk can't fail on it; fall back to
	// the value rendering rather than return partial output.
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
	diagfmt.WriteValue(&b, v, o.compact)
	return b.String()
}

// argIndicator returns the RFC 8949 §8.1 encoding indicator for a head
// whose argument isn't in its shortest form ("_0" for AI 24 through "_3"
// for AI 27), or "" when it is.
// arg returns the argument's encoding indicator when indicators are
// enabled, or "".
func (o *diagOpts) arg(h wire.HeadResult) string {
	if !o.indicators {
		return ""
	}
	return argIndicator(h)
}

// float returns the float's encoding indicator when indicators are
// enabled, or "".
func (o *diagOpts) float(ai byte, f float64) string {
	if !o.indicators {
		return ""
	}
	return floatIndicator(ai, f)
}

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

// diagWriteRaw renders the item at src[off:], with encoding indicators
// when o.indicators is set,
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
		b.WriteString(o.arg(h))
		return pos, true

	case wire.MajorNegInt:
		if indef {
			return off, false
		}
		diagfmt.WriteNegInt(b, h.Arg)
		b.WriteString(o.arg(h))
		return pos, true

	case wire.MajorBytes, wire.MajorText:
		if indef && !o.indicators {
			// Without indicators, render the concatenated chunks as the
			// single string a decoder produces.
			var chunks []byte
			for {
				if pos >= len(src) {
					return off, false
				}
				if src[pos] == wire.BreakCode {
					pos++
					break
				}
				ch := wire.ParseHead(src[pos:])
				if ch.N == 0 || ch.Major != h.Major || ch.AI == wire.AIIndefinite || ch.AI > wire.AI8Bytes ||
					ch.Arg > uint64(len(src)-pos-ch.N) {
					return off, false
				}
				start := pos + ch.N
				end := start + int(ch.Arg)
				chunks = append(chunks, src[start:end]...)
				pos = end
			}
			if h.Major == wire.MajorBytes {
				b.WriteString("h'")
				b.WriteString(hex.EncodeToString(chunks))
				b.WriteByte('\'')
			} else {
				diagfmt.WriteTextItem(b, string(chunks), "")
			}
			return pos, true
		}
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
			b.WriteString(o.arg(h))
		} else {
			diagfmt.WriteTextItem(b, string(src[pos:end]), o.arg(h))
		}
		return end, true

	case wire.MajorArray, wire.MajorMap:
		isMap := h.Major == wire.MajorMap
		if isMap {
			b.WriteByte('{')
		} else {
			b.WriteByte('[')
		}
		if indef && o.indicators {
			b.WriteString("_ ")
		} else if ind := o.arg(h); ind != "" {
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
			// Strip the whole chain in a loop, as Decode does (037 C1).
			for pos < len(src) {
				nh := wire.ParseHead(src[pos:])
				if nh.N == 0 || nh.Major != wire.MajorTag || nh.AI > wire.AI8Bytes || nh.Arg != cbor.TagSelfDescribe {
					break
				}
				pos += nh.N
			}
			return diagWriteRaw(b, src, pos, depth, o, true)
		}
		b.WriteString(strconv.FormatUint(h.Arg, 10))
		b.WriteString(o.arg(h))
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
			diagfmt.WriteFloat(b, wire.DecodeFloat16(uint16(h.Arg)), 64)
		case h.AI == wire.AI4Bytes:
			f := float64(math.Float32frombits(uint32(h.Arg)))
			diagfmt.WriteFloat(b, f, 32)
			b.WriteString(o.float(h.AI, f))
		case h.AI == wire.AI8Bytes:
			f := math.Float64frombits(h.Arg)
			diagfmt.WriteFloat(b, f, 64)
			b.WriteString(o.float(h.AI, f))
		default:
			return off, false
		}
		return pos, true
	}
}
