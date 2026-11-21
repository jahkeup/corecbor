// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

//go:build go1.27

package cose

import (
	"crypto/mldsa"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
)

// rfc9964COSEExamples extracts the Appendix A.2 COSE examples (COSE_Key
// and COSE_Sign1 hex, one per ML-DSA parameter set) from the vendored
// RFC 9964 text.
func rfc9964COSEExamples(t *testing.T) (keys, sign1s [][]byte) {
	t.Helper()
	raw, err := os.ReadFile("../engineering-docs/rfcs/rfc9964.txt")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	i := strings.Index(text, "\nA.2.  COSE")
	if i < 0 {
		t.Fatal("RFC 9964 Appendix A.2 not found")
	}
	text = text[i:]
	extract := func(field string) [][]byte {
		var out [][]byte
		re := regexp.MustCompile(`"` + field + `": "([0-9a-f\s]+)"`)
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			b, err := hex.DecodeString(strings.Join(strings.Fields(m[1]), ""))
			if err != nil {
				t.Fatalf("%s: %v", field, err)
			}
			out = append(out, b)
		}
		return out
	}
	keys, sign1s = extract("key"), extract("sign1")
	if len(keys) != 3 || len(sign1s) != 3 {
		t.Fatalf("found %d keys and %d sign1 examples, want 3 each", len(keys), len(sign1s))
	}
	return keys, sign1s
}

// RFC 9964 Appendix A.2: each example key (seed 00…00) verifies its
// COSE_Sign1, and a Signer built from the key produces messages the same
// key verifies.
func TestMLDSARFC9964Examples(t *testing.T) {
	keys, sign1s := rfc9964COSEExamples(t)
	want := []Algorithm{AlgMLDSA44, AlgMLDSA65, AlgMLDSA87}
	for i := range keys {
		t.Run(want[i].String(), func(t *testing.T) {
			k, err := ParseKey(keys[i])
			if err != nil {
				t.Fatal(err)
			}
			if a, _ := k.Algorithm(); a != want[i] {
				t.Fatalf("key alg %s, want %s", a, want[i])
			}
			pub, err := k.Public()
			if err != nil {
				t.Fatal(err)
			}
			v, err := NewVerifierFromKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := UnmarshalSign1(sign1s[i])
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Verify(msg); err != nil {
				t.Fatalf("RFC 9964 example: %v", err)
			}
			msg.Signature[0] ^= 1
			if err := v.Verify(msg); !errors.Is(err, ErrVerification) {
				t.Fatalf("tampered signature = %v", err)
			}

			s, err := NewSignerFromKey(k)
			if err != nil {
				t.Fatal(err)
			}
			m2, err := s.Sign([]byte("round trip"))
			if err != nil {
				t.Fatal(err)
			}
			if m2.Protected.Algorithm() != want[i] {
				t.Fatalf("emitted alg %s", m2.Protected.Algorithm())
			}
			wire, err := MarshalSign1(m2)
			if err != nil {
				t.Fatal(err)
			}
			back, err := UnmarshalSign1(wire)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Verify(back); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Keys built from Go ML-DSA keys round-trip through COSE_Key, and a pub
// that doesn't match the seed is rejected (RFC 9964 §3).
func TestMLDSAKeyRoundTrip(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	ck, err := NewKeyFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := ck.Algorithm(); a != AlgMLDSA65 || ck.KeyType() != KeyTypeAKP {
		t.Fatalf("COSE_Key kty %d alg %s", ck.KeyType(), a)
	}
	wire, err := ck.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := back.Signer()
	if err != nil {
		t.Fatal(err)
	}
	if !sig.(*mldsa.PrivateKey).Equal(priv) {
		t.Fatal("private key changed across COSE_Key round trip")
	}
	// A NewSigner from the Go key, verified by a NewVerifier from its
	// public key.
	s, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := s.Sign([]byte("x"))
	v, err := NewVerifier(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(msg); err != nil {
		t.Fatal(err)
	}
	// Wrong-parameter-set key: ML-DSA-44 message, ML-DSA-65 verifier.
	other, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	s44, _ := NewSigner(other)
	m44, _ := s44.Sign([]byte("x"))
	if err := v.Verify(m44); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("ML-DSA-44 message with ML-DSA-65 key = %v", err)
	}
	// Mismatched pub.
	bad, _ := ParseKey(wire)
	bad.set(keyLabelAKPPub, other.PublicKey().Bytes())
	if _, err := bad.Signer(); err == nil {
		t.Fatal("mismatched pub accepted")
	}
}
