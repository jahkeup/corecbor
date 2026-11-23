// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// TestSkipLimitOrderMatchesDecode: a definite-length container that is
// both too long and too deep reports the length limit from Skip, as it
// does from Decode and the stream reader.
func TestSkipLimitOrderMatchesDecode(t *testing.T) {
	opts := DecodeOpts{MaxNestingDepth: 1, MaxArrayLength: 4}
	for name, src := range map[string][]byte{
		"array": {0x81, 0x85, 0, 0, 0, 0, 0}, // [[5 items]] at depth 2
		"map":   {0x81, 0xa5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, decErr := Decode(src, opts)
			_, skipErr := NewCursor(src, opts).Skip()
			if !errors.Is(decErr, cbor.ErrMaxArrayLength) {
				t.Fatalf("Decode err = %v, want ErrMaxArrayLength", decErr)
			}
			if !errors.Is(skipErr, cbor.ErrMaxArrayLength) {
				t.Fatalf("Skip err = %v, want ErrMaxArrayLength", skipErr)
			}
		})
	}
}
