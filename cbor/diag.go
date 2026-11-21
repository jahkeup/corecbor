// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"strconv"
	"strings"

	"github.com/jahkeup/corecbor/internal/diagfmt"
)

func init() {
	diagfmt.RegisterValueWriter(func(b *strings.Builder, v any, compact bool) {
		appendDiag(b, v.(Value), compact)
	})
}

// String returns the compact diagnostic-notation form of v (RFC 8949
// §8), the same text as corecbor.DiagnosticValue(v, DiagCompact()). It
// implements fmt.Stringer. A Value doesn't record how it was encoded, so
// encoding indicators are never shown.
func (v Value) String() string {
	var b strings.Builder
	appendDiag(&b, v, true)
	return b.String()
}

func appendDiag(b *strings.Builder, v Value, compact bool) {
	sep, kv := ", ", ": "
	if compact {
		sep, kv = ",", ":"
	}
	switch v.Kind {
	case KindUint:
		b.WriteString(strconv.FormatUint(v.Num, 10))
	case KindNegInt:
		diagfmt.WriteNegInt(b, v.Num)
	case KindBytes:
		diagfmt.WriteBytes(b, v.Bstr, "")
	case KindText:
		diagfmt.WriteTextItem(b, v.Str, "")
	case KindArray:
		b.WriteByte('[')
		for i, item := range v.Items {
			if i > 0 {
				b.WriteString(sep)
			}
			appendDiag(b, item, compact)
		}
		b.WriteByte(']')
	case KindMap:
		b.WriteByte('{')
		for i, e := range v.Pairs {
			if i > 0 {
				b.WriteString(sep)
			}
			appendDiag(b, e.Key, compact)
			b.WriteString(kv)
			appendDiag(b, e.Value, compact)
		}
		b.WriteByte('}')
	case KindTag:
		b.WriteString(strconv.FormatUint(v.Num, 10))
		b.WriteByte('(')
		appendDiag(b, v.TagInner(), compact)
		b.WriteByte(')')
	case KindBool:
		if v.BoolVal() {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case KindNull:
		b.WriteString("null")
	case KindUndefined:
		b.WriteString("undefined")
	case KindFloat32:
		diagfmt.WriteFloat(b, float64(v.Float32Val()), 32)
	case KindFloat64:
		diagfmt.WriteFloat(b, v.Float64Val(), 64)
	case KindSimple:
		diagfmt.WriteSimple(b, v.Num)
	default:
		b.WriteString("?")
	}
}
