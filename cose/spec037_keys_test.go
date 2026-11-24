// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

// Proposal 037 S4: a COSE_Key's alg restricts it (RFC 9052 §7.1) even
// when WithAllowedAlgorithms is passed: the two are intersected.
func TestSpec037KeyAlgWithAllowList(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k, err := NewKeyFromPublic(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k.SetAlgorithm(AlgPS256)

	var h Headers
	_ = h.SetChecked(int64(1), AlgRS256)
	rs, err := NewSigner(priv, WithProtectedHeaders(h))
	if err != nil {
		t.Fatal(err)
	}
	rsMsg, err := rs.Sign([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	ps, _ := NewSigner(priv)
	psMsg, _ := ps.Sign([]byte("x"))

	v, err := NewVerifierFromKey(k, WithAllowedAlgorithms(AlgPS256, AlgRS256))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(rsMsg); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("RS256 message, PS256 key: err = %v, want ErrAlgorithmMismatch", err)
	}
	if err := v.Verify(psMsg); err != nil {
		t.Fatalf("PS256 message: %v", err)
	}

	// An allow-list that excludes the key's alg leaves nothing to verify.
	if _, err := NewVerifierFromKey(k, WithAllowedAlgorithms(AlgRS256)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("disjoint allow-list: err = %v, want ErrInvalidKey", err)
	}

	// The same for an EC key restricted to ESP256.
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ek, _ := NewKeyFromPublic(&ec.PublicKey)
	ek.SetAlgorithm(AlgESP256)
	ev, err := NewVerifierFromKey(ek, WithAllowedAlgorithms(AlgES256, AlgESP256))
	if err != nil {
		t.Fatal(err)
	}
	es, _ := NewSigner(ec)
	esMsg, _ := es.Sign([]byte("x"))
	if err := ev.Verify(esMsg); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("ES256 message, ESP256 key: err = %v, want ErrAlgorithmMismatch", err)
	}
}
