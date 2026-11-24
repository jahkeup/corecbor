// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor"
)

// Proposal 037 S10: by default an alg only in the unprotected bucket is
// accepted when it equals the key's (cose-wg sign-pass-01), and a
// missing alg is verified as the key's. RequireProtectedAlgorithm and
// its MAC and encrypt counterparts require a protected alg.
func TestSpec037RequireProtectedAlgorithm(t *testing.T) {
	A, B := corecbor.MakeArray, corecbor.Bytes
	payload := []byte("p")
	uAlg := corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Uint(1), Value: corecbor.NegInt(7)}) // EdDSA
	sig := func() []byte {
		s, _ := NewSigner(hardEdPriv)
		tbs, _ := encodeSigStructure(s.enc, nil, nil, payload)
		b, _ := s.signBytes(t.Context(), AlgEdDSA, tbs)
		return b
	}()
	for name, unprot := range map[string]corecbor.Value{"unprotected alg": uAlg, "no alg": corecbor.MakeMap()} {
		t.Run(name, func(t *testing.T) {
			m, err := UnmarshalSign1(encodeCBOR(t, corecbor.MakeTag(18, A(B(nil), unprot, B(payload), B(sig)))))
			if err != nil {
				t.Fatal(err)
			}
			v, _ := NewVerifier(hardEdPub)
			if err := v.Verify(m); err != nil {
				t.Fatalf("default: %v", err)
			}
			strict, _ := NewVerifier(hardEdPub, RequireProtectedAlgorithm())
			if err := strict.Verify(m); !errors.Is(err, ErrAlgorithmMismatch) {
				t.Fatalf("RequireProtectedAlgorithm: err = %v, want ErrAlgorithmMismatch", err)
			}
		})
	}
	// Protected alg passes under the option.
	s, _ := NewSigner(hardEdPriv)
	good, _ := s.Sign(payload)
	strict, _ := NewVerifier(hardEdPub, RequireProtectedAlgorithm())
	if err := strict.Verify(good); err != nil {
		t.Fatalf("protected alg: %v", err)
	}

	// MAC0 with no alg header.
	key := bytes.Repeat([]byte{0x0b}, 32)
	tag := hmacSHA256(key, encodeCBOR(t, A(corecbor.Text("MAC0"), B(nil), B(nil), B(payload))))
	m, err := UnmarshalMac0(encodeCBOR(t, corecbor.MakeTag(17, A(B(nil), corecbor.MakeMap(), B(payload), B(tag)))))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMAC0(m, key, AlgHMAC256); err != nil {
		t.Fatalf("MAC0 default: %v", err)
	}
	if err := VerifyMAC0(m, key, AlgHMAC256, RequireMACProtectedAlgorithm()); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("MAC0 strict: err = %v, want ErrAlgorithmMismatch", err)
	}

	// Encrypt0 with alg moved to the unprotected bucket.
	aesKey := bytes.Repeat([]byte{0x0d}, 16)
	e, err := Encrypt0Seal(payload, aesKey, AlgA128GCM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Encrypt0Open(e, aesKey, RequireEncryptProtectedAlgorithm()); err != nil {
		t.Fatalf("Encrypt0 strict, protected alg: %v", err)
	}
	moved := &Encrypt0{Unprotected: e.Unprotected, Ciphertext: e.Ciphertext}
	moved.Unprotected.SetAlgorithm(AlgA128GCM)
	if _, err := Encrypt0Open(moved, aesKey, RequireEncryptProtectedAlgorithm()); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("Encrypt0 strict, unprotected alg: err = %v, want ErrAlgorithmMismatch", err)
	}
}
