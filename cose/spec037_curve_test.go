// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor"
)

// Proposal 037 S21: RFC 9053 §2.1 only suggests pairing ES256 with
// P-256 (and ES384/ES512 with P-384/P-521). By default a Verifier binds
// the polymorphic identifier to the key's curve;
// AllowECDSACurveHashMismatch accepts another pairing from senders that
// use one. The fully-specified ESP256/384/512 (RFC 9864) name the curve
// and are never mismatched.
func TestSpec037ECDSACurveHashMismatch(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	A, B := corecbor.MakeArray, corecbor.Bytes
	sign1 := func(alg Algorithm) *Sign1 {
		var p Headers
		p.SetAlgorithm(alg)
		prot, _ := p.encodeProtected()
		tbs := encodeCBOR(t, A(corecbor.Text("Signature1"), B(prot), B(nil), B([]byte("p"))))
		d := sha256.Sum256(tbs)
		der, err := ecdsa.SignASN1(rand.Reader, priv, d[:])
		if err != nil {
			t.Fatal(err)
		}
		raw, err := derToRawECDSA(der, elliptic.P384())
		if err != nil {
			t.Fatal(err)
		}
		m, err := UnmarshalSign1(encodeCBOR(t, corecbor.MakeTag(18, A(B(prot), corecbor.MakeMap(), B([]byte("p")), B(raw)))))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	es256 := sign1(AlgES256)

	v, _ := NewVerifier(&priv.PublicKey)
	if err := v.Verify(es256); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("ES256 on P-384, default: err = %v, want ErrAlgorithmMismatch", err)
	}
	lax, _ := NewVerifier(&priv.PublicKey, AllowECDSACurveHashMismatch())
	if err := lax.Verify(es256); err != nil {
		t.Fatalf("ES256 on P-384, allowed: %v", err)
	}
	if err := lax.Verify(sign1(AlgESP256)); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("ESP256 on P-384, allowed: err = %v, want ErrAlgorithmMismatch", err)
	}
	// The key's own pairing still verifies.
	s, _ := NewSigner(priv)
	m, _ := s.Sign([]byte("p"))
	if err := lax.Verify(m); err != nil {
		t.Fatalf("ES384 on P-384, allowed: %v", err)
	}
}
