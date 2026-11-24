// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"errors"
	"testing"
)

// Proposal 037 S20: RFC 9052 §3.1 says the RFC 8152 counter signature
// label (7) must be understood by new implementations, so crit may list
// it. A countersignature doesn't change how the message it counter-signs
// is processed; this package passes it through and doesn't verify it.
// The RFC 9338 labels (11, 12) are unprotected, so crit can't list them.
func TestSpec037CritCounterSignature(t *testing.T) {
	v, err := NewVerifier(hardEdPub)
	if err != nil {
		t.Fatal(err)
	}
	msg := signedWith(t, []byte("p"), map[int64]any{7: []byte{1}, 2: []any{int64(7)}})
	if err := v.Verify(msg); err != nil {
		t.Fatalf("crit [7]: %v", err)
	}
	for _, l := range []int64{11, 12} {
		msg := signedWith(t, []byte("p"), map[int64]any{l: []byte{1}, 2: []any{l}})
		if err := v.Verify(msg); !errors.Is(err, ErrCriticalHeader) {
			t.Fatalf("crit [%d]: err = %v, want ErrCriticalHeader", l, err)
		}
	}
}
