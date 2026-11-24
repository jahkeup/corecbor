// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor"
)

// Proposal 037 S14: an empty protected bucket received as h'a0' is kept
// as received when the message is written back, and
// AllowEmptyProtectedAsReceived verifies over those bytes for senders
// that signed over them. By default the Sig_structure uses the
// zero-length string (RFC 9052 §3, cose-wg sign-pass-01).
func TestSpec037EmptyProtectedA0(t *testing.T) {
	A, B := corecbor.MakeArray, corecbor.Bytes
	payload := []byte("p")
	sigOver := func(prot []byte) []byte {
		tbs := encodeCBOR(t, A(corecbor.Text("Signature1"), B(prot), B(nil), B(payload)))
		return ed25519.Sign(hardEdPriv, tbs)
	}
	alg := corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Uint(1), Value: corecbor.NegInt(7)}) // EdDSA
	msg := func(sig []byte) []byte {
		return encodeCBOR(t, corecbor.MakeTag(18, A(B([]byte{0xa0}), alg, B(payload), B(sig))))
	}
	v, _ := NewVerifier(hardEdPub)
	lax, _ := NewVerifier(hardEdPub, AllowEmptyProtectedAsReceived())

	overA0, err := UnmarshalSign1(msg(sigOver([]byte{0xa0})))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(overA0); !errors.Is(err, ErrVerification) {
		t.Fatalf("signed over a0, default: err = %v, want ErrVerification", err)
	}
	if err := lax.Verify(overA0); err != nil {
		t.Fatalf("signed over a0, AllowEmptyProtectedAsReceived: %v", err)
	}

	overEmpty, err := UnmarshalSign1(msg(sigOver(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(overEmpty); err != nil {
		t.Fatalf("signed over h'', default: %v", err)
	}

	// Written back as received.
	raw := msg(sigOver(nil))
	if out, err := MarshalSign1(overEmpty); err != nil || !bytes.Equal(out, raw) {
		t.Fatalf("MarshalSign1 = %x, %v; want %x", out, err, raw)
	}

	// MAC0 over a0.
	key := bytes.Repeat([]byte{0x0b}, 32)
	tag := hmacSHA256(key, encodeCBOR(t, A(corecbor.Text("MAC0"), B([]byte{0xa0}), B(nil), B(payload))))
	m, err := UnmarshalMac0(encodeCBOR(t, corecbor.MakeTag(17, A(B([]byte{0xa0}), corecbor.MakeMap(), B(payload), B(tag)))))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMAC0(m, key, AlgHMAC256); !errors.Is(err, ErrMACVerification) {
		t.Fatalf("MAC0 over a0, default: err = %v", err)
	}
	if err := VerifyMAC0(m, key, AlgHMAC256, AllowMACEmptyProtectedAsReceived()); err != nil {
		t.Fatalf("MAC0 over a0, allowed: %v", err)
	}
}
