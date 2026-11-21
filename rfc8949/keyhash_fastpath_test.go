// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// keyHash's text fast path must agree with the general hash, or
// duplicate detection would differ between text and other keys.
func TestKeyHashTextFastPath(t *testing.T) {
	for _, s := range []string{"", "a", "k1_ffff", "\xff\xfe", "longer key with spaces"} {
		v := cbor.Text(s)
		if got, want := keyHash(v), keyHashInto(fnvOffset, v); got != want {
			t.Errorf("keyHash(%q) = %x, want %x", s, got, want)
		}
	}
}
