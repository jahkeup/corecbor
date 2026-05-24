// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import "github.com/jahkeup/corecbor/cbor"

const maxHeadSize = 9

// EstimateSize returns a conservative estimate of the CBOR-encoded size
// of v in bytes. The estimate never underestimates but may overestimate
// by up to 9 bytes per node (using maximum head size rather than shortest
// encoding). The walk is O(tree-size) in CPU and zero-allocation.
func EstimateSize(v cbor.Value) int {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case cbor.Uint:
		return headSize(uint64(val))
	case cbor.NegInt:
		return headSize(uint64(val))
	case cbor.Bytes:
		return headSize(uint64(len(val))) + len(val)
	case cbor.Text:
		return headSize(uint64(len(val))) + len(val)
	case cbor.Array:
		n := headSize(uint64(len(val)))
		for _, elem := range val {
			n += EstimateSize(elem)
		}
		return n
	case cbor.Map:
		n := headSize(uint64(len(val)))
		for _, entry := range val {
			n += EstimateSize(entry.Key) + EstimateSize(entry.Value)
		}
		return n
	case cbor.Tag:
		return headSize(val.ID) + EstimateSize(val.Inner)
	case cbor.Bool:
		return 1
	case cbor.Null:
		return 1
	case cbor.Undefined:
		return 1
	case cbor.Simple:
		if uint8(val) < 24 {
			return 1
		}
		return 2
	case cbor.Float32:
		return 5
	case cbor.Float64:
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

// EncodeWithHint is like Encode but ensures dst has at least hint bytes
// of available capacity before encoding. This avoids intermediate slice
// growth for callers who know their approximate output size.
func EncodeWithHint(dst []byte, v cbor.Value, opts EncodeOpts, hint int) ([]byte, error) {
	if avail := cap(dst) - len(dst); avail < hint {
		grown := make([]byte, len(dst), len(dst)+hint)
		copy(grown, dst)
		dst = grown
	}
	return Encode(dst, v, opts)
}
