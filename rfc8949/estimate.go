// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import "github.com/jahkeup/corecbor/cbor"

const maxHeadSize = 9

func EstimateSize(v cbor.Value) int {
	if v.IsZero() {
		return 0
	}
	switch v.Kind() {
	case cbor.KindUint:
		return headSize(v.UintVal())
	case cbor.KindNegInt:
		return headSize(v.NegIntVal())
	case cbor.KindBytes:
		b := v.BytesVal()
		return headSize(uint64(len(b))) + len(b)
	case cbor.KindText:
		s := v.TextVal()
		return headSize(uint64(len(s))) + len(s)
	case cbor.KindArray:
		items := v.Array()
		n := headSize(uint64(len(items)))
		for _, elem := range items {
			n += EstimateSize(elem)
		}
		return n
	case cbor.KindMap:
		pairs := v.Map()
		n := headSize(uint64(len(pairs)))
		for _, entry := range pairs {
			n += EstimateSize(entry.Key) + EstimateSize(entry.Value)
		}
		return n
	case cbor.KindTag:
		return headSize(v.TagID()) + EstimateSize(v.TagInner())
	case cbor.KindBool:
		return 1
	case cbor.KindNull:
		return 1
	case cbor.KindUndefined:
		return 1
	case cbor.KindSimple:
		if v.SimpleVal() < 24 {
			return 1
		}
		return 2
	case cbor.KindFloat32:
		return 5
	case cbor.KindFloat64:
		return 9
	default:
		return maxHeadSize
	}
}

func headSize(arg uint64) int {
	switch {
	case arg < 24:
		return 1
	case arg <= 0xff:
		return 2
	case arg <= 0xffff:
		return 3
	case arg <= 0xffffffff:
		return 5
	default:
		return 9
	}
}

func EncodeWithHint(dst []byte, v cbor.Value, opts EncodeOpts, hint int) ([]byte, error) {
	if avail := cap(dst) - len(dst); avail < hint {
		grown := make([]byte, len(dst), len(dst)+hint)
		copy(grown, dst)
		dst = grown
	}
	return Encode(dst, v, opts)
}
