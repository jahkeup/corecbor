// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"errors"
	"testing"
)

// Proposal 037 S5: typ (16) MUST NOT be in an unprotected bucket
// (RFC 9596 §2). Signers refuse to emit it, decoding rejects it, and
// DecodeLimits.AllowUnprotectedTyp accepts it from older peers.
func TestSpec037UnprotectedTyp(t *testing.T) {
	var u Headers
	if err := u.SetType("application/example"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSigner(hardEdPriv, WithUnprotectedHeaders(u)); !errors.Is(err, ErrUnsupportedHeader) {
		t.Fatalf("NewSigner, unprotected typ: err = %v, want ErrUnsupportedHeader", err)
	}
	s, err := NewSigner(hardEdPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignMulti([]byte("p"), []*Signer{s}, WithUnprotectedHeaders(u)); !errors.Is(err, ErrUnsupportedHeader) {
		t.Fatalf("SignMulti, unprotected typ: err = %v, want ErrUnsupportedHeader", err)
	}
	// In the protected bucket it is fine.
	if _, err := NewSigner(hardEdPriv, WithProtectedHeaders(u)); err != nil {
		t.Fatalf("protected typ: %v", err)
	}

	// Received: a Sign1 with typ unprotected.
	data := hx(t, "d284"+"43a10127"+"a1"+"10"+"63"+"616263"+"40"+"40") // {16: "abc"}
	if _, err := UnmarshalSign1(data); !errors.Is(err, ErrMalformed) {
		t.Fatalf("UnmarshalSign1, unprotected typ: err = %v, want ErrMalformed", err)
	}
	m, err := UnmarshalSign1With(data, DecodeLimits{AllowUnprotectedTyp: true})
	if err != nil {
		t.Fatalf("AllowUnprotectedTyp: %v", err)
	}
	if _, mt, ok := m.Unprotected.Type(); !ok || mt != "abc" {
		t.Fatalf("typ = %q, %v", mt, ok)
	}
	// A recipient layer too.
	enc := hx(t, "d860"+"84"+"40"+"a0"+"40"+"81"+"83"+"40"+"a2"+"0122"+"1001"+"40") // recipient {1: -3, 16: 1}
	if _, err := UnmarshalEncrypt(enc); !errors.Is(err, ErrMalformed) {
		t.Fatalf("UnmarshalEncrypt, recipient typ: err = %v, want ErrMalformed", err)
	}
}
