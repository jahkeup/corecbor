// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"io"

	"github.com/jahkeup/corecbor/cbor"
)

// EncodeTo writes the CBOR encoding of v to w without buffering the full
// output in memory first. For maps in deterministic mode, keys must still
// be buffered for sorting.
func EncodeTo(w io.Writer, v cbor.Value, opts EncodeOpts) error {
	buf, err := Encode(nil, v, opts)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}
