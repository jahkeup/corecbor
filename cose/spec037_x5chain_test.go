// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"errors"
	"testing"
)

// Proposal 037 S15: a one-element x5chain array is rejected by X5Chain
// (RFC 9360 §2) and accepted by X5ChainLenient.
func TestSpec037X5ChainSingleElementArray(t *testing.T) {
	var h Headers
	if err := h.SetChecked(headerLabelX5Chain, []any{[]byte{1, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.X5Chain(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("X5Chain: err = %v, want ErrMalformed", err)
	}
	got, err := h.X5ChainLenient()
	if err != nil || len(got) != 1 || string(got[0]) != "\x01\x02\x03" {
		t.Fatalf("X5ChainLenient = %x, %v", got, err)
	}
	var empty Headers
	_ = empty.SetChecked(headerLabelX5Chain, []any{})
	if _, err := empty.X5ChainLenient(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("X5ChainLenient, empty array: err = %v, want ErrMalformed", err)
	}
	var single Headers
	_ = single.SetX5Chain([]byte{9})
	if got, err := single.X5ChainLenient(); err != nil || len(got) != 1 {
		t.Fatalf("X5ChainLenient, bstr: %x, %v", got, err)
	}
}
