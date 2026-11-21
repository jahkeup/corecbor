// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

// Proposal 029 Phase 1: RFC 9864 fully-specified algorithms and RSA
// signing.

func testSigners(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	out := map[string]crypto.Signer{}
	for name, c := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()} {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = k
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out["Ed25519"] = ed
	return out
}

func TestSignerAlgEmission(t *testing.T) {
	poly := map[string]Algorithm{"P-256": AlgES256, "P-384": AlgES384, "P-521": AlgES512, "Ed25519": AlgEdDSA}
	full := map[string]Algorithm{"P-256": AlgESP256, "P-384": AlgESP384, "P-521": AlgESP512, "Ed25519": AlgEd25519}
	for name, key := range testSigners(t) {
		t.Run(name, func(t *testing.T) {
			def, err := NewSigner(key)
			if err != nil {
				t.Fatal(err)
			}
			fs, err := NewSigner(key, WithFullySpecifiedAlgorithms())
			if err != nil {
				t.Fatal(err)
			}
			v, err := NewVerifier(key.Public())
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []struct {
				s    *Signer
				want Algorithm
			}{{def, poly[name]}, {fs, full[name]}} {
				msg, err := c.s.Sign([]byte("payload"))
				if err != nil {
					t.Fatal(err)
				}
				if got := msg.Protected.Algorithm(); got != c.want {
					t.Fatalf("emitted alg %s, want %s", got, c.want)
				}
				wire, err := MarshalSign1(msg)
				if err != nil {
					t.Fatal(err)
				}
				back, err := UnmarshalSign1(wire)
				if err != nil {
					t.Fatal(err)
				}
				if err := v.Verify(back); err != nil {
					t.Fatalf("verify %s: %v", c.want, err)
				}
			}
		})
	}
}

// A protected alg naming the fully-specified form selects it without the
// option; one naming a different operation is rejected.
func TestSignerProtectedAlgSelectsForm(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var h Headers
	if err := h.SetChecked(int64(1), AlgESP256); err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(k, WithProtectedHeaders(h))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := s.Sign([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Protected.Algorithm() != AlgESP256 {
		t.Fatalf("alg %s, want ESP256", msg.Protected.Algorithm())
	}
	var bad Headers
	_ = bad.SetChecked(int64(1), AlgESP384)
	if _, err := NewSigner(k, WithProtectedHeaders(bad)); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("ESP384 on P-256 = %v, want ErrAlgorithmMismatch", err)
	}
}

// A fully-specified alg that names a different curve than the key is
// rejected; so is polymorphic-vs-curve mismatch.
func TestVerifyFullySpecifiedWrongCurve(t *testing.T) {
	k256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	s, _ := NewSigner(k256, WithFullySpecifiedAlgorithms())
	msg, err := s.Sign([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	v, _ := NewVerifier(k384.Public())
	if err := v.Verify(msg); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("ESP256 message with P-384 verifier = %v, want ErrAlgorithmMismatch", err)
	}
}

// WithAllowedAlgorithms is exact: allowing ES256 doesn't allow ESP256.
func TestAllowedAlgorithmsExactForm(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, _ := NewSigner(k, WithFullySpecifiedAlgorithms())
	msg, _ := s.Sign([]byte("x"))
	v, _ := NewVerifier(k.Public(), WithAllowedAlgorithms(AlgES256))
	if err := v.Verify(msg); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("ESP256 with ES256-only allow-list = %v", err)
	}
	v, _ = NewVerifier(k.Public(), WithAllowedAlgorithms(AlgES256, AlgESP256))
	if err := v.Verify(msg); err != nil {
		t.Fatal(err)
	}
}

func TestFullySpecifiedHelper(t *testing.T) {
	keys := testSigners(t)
	for _, c := range []struct {
		key  string
		in   Algorithm
		want Algorithm
		ok   bool
	}{
		{"P-256", AlgES256, AlgESP256, true},
		{"P-256", AlgESP256, AlgESP256, true},
		{"P-256", AlgES384, 0, false},
		{"P-384", AlgES384, AlgESP384, true},
		{"P-521", AlgES512, AlgESP512, true},
		{"Ed25519", AlgEdDSA, AlgEd25519, true},
		{"Ed25519", AlgES256, 0, false},
	} {
		got, ok := FullySpecified(c.in, keys[c.key].Public())
		if got != c.want || ok != c.ok {
			t.Errorf("FullySpecified(%s, %s) = %s, %v; want %s, %v", c.in, c.key, got, ok, c.want, c.ok)
		}
	}
}

func TestNewSignerFromKeyFullySpecifiedAlg(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ck, err := NewKeyFromSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	ck.SetAlgorithm(AlgESP256)
	s, err := NewSignerFromKey(ck)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := s.Sign([]byte("x"))
	if msg.Protected.Algorithm() != AlgESP256 {
		t.Fatalf("alg %s, want ESP256", msg.Protected.Algorithm())
	}
	pub, _ := ck.Public()
	v, err := NewVerifierFromKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(msg); err != nil {
		t.Fatal(err)
	}
	// The key is restricted to ESP256, so an ES256 message is refused.
	def, _ := NewSigner(k)
	m2, _ := def.Sign([]byte("x"))
	if err := v.Verify(m2); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("ES256 message with ESP256 key = %v", err)
	}
}

func TestRSASign(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		alg     Algorithm
		allowed []Algorithm
	}{
		{AlgPS256, nil},
		{AlgPS384, nil},
		{AlgPS512, nil},
		{AlgRS256, []Algorithm{AlgRS256}},
		{AlgRS512, []Algorithm{AlgRS512}},
	} {
		t.Run(c.alg.String(), func(t *testing.T) {
			var opts []SignerOption
			if c.alg != AlgPS256 {
				var h Headers
				_ = h.SetChecked(int64(1), c.alg)
				opts = append(opts, WithProtectedHeaders(h))
			}
			s, err := NewSigner(key, opts...)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := s.Sign([]byte("rsa"))
			if err != nil {
				t.Fatal(err)
			}
			if msg.Protected.Algorithm() != c.alg {
				t.Fatalf("alg %s", msg.Protected.Algorithm())
			}
			var vopts []VerifierOption
			if c.allowed != nil {
				vopts = append(vopts, WithAllowedAlgorithms(c.allowed...))
			}
			v, err := NewVerifier(&key.PublicKey, vopts...)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Verify(msg); err != nil {
				t.Fatal(err)
			}
		})
	}
	// RS256 is refused without an explicit allow-list.
	var h Headers
	_ = h.SetChecked(int64(1), AlgRS256)
	s, _ := NewSigner(key, WithProtectedHeaders(h))
	msg, _ := s.Sign([]byte("rsa"))
	v, _ := NewVerifier(&key.PublicKey)
	if err := v.Verify(msg); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("RS256 without allow-list = %v", err)
	}
	// A COSE_Key round trip keeps a working private key.
	ck, err := NewKeyFromSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := ck.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	back.SetAlgorithm(AlgPS384)
	s2, err := NewSignerFromKey(back)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := s2.Sign([]byte("from key"))
	if err != nil {
		t.Fatal(err)
	}
	if m2.Protected.Algorithm() != AlgPS384 {
		t.Fatalf("alg %s, want PS384", m2.Protected.Algorithm())
	}
	if err := v.Verify(m2); err != nil {
		t.Fatal(err)
	}
}
