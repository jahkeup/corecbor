// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"bytes"
	"cmp"
	"slices"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/wire"
)

type MapKeyOrder struct {
	encodedKeys [][]byte
	indices     []int
}

func PrecomputeMapOrder(keys []cbor.Value, sortMode SortMode, opts EncodeOpts) (*MapKeyOrder, error) {
	type entry struct {
		encoded []byte
		index   int
	}
	entries := make([]entry, len(keys))
	for i, k := range keys {
		enc, err := encode(nil, k, opts)
		if err != nil {
			return nil, err
		}
		entries[i] = entry{encoded: enc, index: i}
	}

	slices.SortFunc(entries, func(a, b entry) int {
		if sortMode == SortLengthFirst {
			if c := cmp.Compare(len(a.encoded), len(b.encoded)); c != 0 {
				return c
			}
		}
		return bytes.Compare(a.encoded, b.encoded)
	})

	order := &MapKeyOrder{
		encodedKeys: make([][]byte, len(entries)),
		indices:     make([]int, len(entries)),
	}
	for i, e := range entries {
		order.encodedKeys[i] = e.encoded
		order.indices[i] = e.index
	}
	return order, nil
}

func EncodeMapPreordered(dst []byte, m []cbor.MapEntry, order *MapKeyOrder, opts EncodeOpts) ([]byte, error) {
	dst = wire.AppendHead(dst, wire.MajorMap, uint64(len(m)))
	var err error
	for i, keyBytes := range order.encodedKeys {
		dst = append(dst, keyBytes...)
		dst, err = encode(dst, m[order.indices[i]].Value, opts)
		if err != nil {
			return dst, err
		}
	}
	return dst, nil
}
