// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

// signedWith signs payload as a Sign1 whose protected bucket holds prot.
func signedWith(t *testing.T, payload []byte, prot map[int64]any) *Sign1 {
	t.Helper()
	s, err := NewSigner(hardEdPriv)
	if err != nil {
		t.Fatal(err)
	}
	msg := &Sign1{Payload: payload}
	for l, x := range prot {
		if err := msg.Protected.SetChecked(l, x); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Sign1(msg); err != nil {
		t.Fatal(err)
	}
	return msg
}

// Proposal 037 S13: the hash-envelope verifiers process labels 258-260,
// so a crit listing them is satisfied there (RFC 9052 §3.1, RFC 9995);
// plain Verify doesn't process them and still rejects it.
func TestSpec037HashEnvelopeCrit(t *testing.T) {
	digest := sha256.Sum256([]byte("preimage"))
	msg := signedWith(t, digest[:], map[int64]any{
		258: int64(AlgSHA256), 259: "text/plain",
		2: []any{int64(258), int64(259)},
	})
	v, err := NewVerifier(hardEdPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyHashEnvelope(msg, nil, []byte("preimage")); err != nil {
		t.Fatalf("VerifyHashEnvelope, crit [258, 259]: %v", err)
	}
	k, _ := NewKeyFromPublic(hardEdPub)
	if _, err := VerifySign1HashEnvelope(context.Background(), msg, nil, nil, KeySetResolver(KeySet{k})); err != nil {
		t.Fatalf("VerifySign1HashEnvelope, crit [258, 259]: %v", err)
	}
	if err := v.Verify(msg); !errors.Is(err, ErrCriticalHeader) {
		t.Fatalf("Verify, crit [258]: err = %v, want ErrCriticalHeader", err)
	}
}
