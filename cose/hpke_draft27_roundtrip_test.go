// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

// hpkeTestKeys returns a private COSE_Key and its public half for the
// suite's KEM curve.
func hpkeTestKeys(t testing.TB, s HPKESuite) (priv, pub *Key) {
	t.Helper()
	p, _ := s.params()
	k, err := p.curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err = NewKeyFromPublic(k.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	priv, err = NewKeyFromPublic(k.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	priv.set(keyLabelD, k.Bytes())
	return priv, pub
}

var hpkeSupportedSuites = []HPKESuite{HPKE0, HPKE1, HPKE2, HPKE3, HPKE4, HPKE7}

func TestHPKEIntegratedRoundTrip(t *testing.T) {
	pt := []byte("integrated payload")
	for _, s := range hpkeSupportedSuites {
		t.Run(s.String(), func(t *testing.T) {
			priv, pub := hpkeTestKeys(t, s)
			pub.SetID([]byte("bob"))
			opts := []EncryptOption{WithDraftHPKE27(), WithEncryptExternalAAD([]byte("aad")), WithHPKEInfo([]byte("info"))}
			msg, err := HPKESeal(pt, pub, s, opts...)
			if err != nil {
				t.Fatal(err)
			}
			if got := msg.Protected.Algorithm(); got != s.IntegratedAlgorithm() {
				t.Fatalf("alg = %s, want %s", got, s.IntegratedAlgorithm())
			}
			if kid := msg.Protected.KeyID(); !bytes.Equal(kid, []byte("bob")) {
				t.Fatalf("protected kid = %q", kid)
			}
			wire, err := MarshalEncrypt0(msg)
			if err != nil {
				t.Fatal(err)
			}
			back, err := UnmarshalEncrypt0(wire)
			if err != nil {
				t.Fatal(err)
			}
			got, err := HPKEOpen(back, priv, opts...)
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("HPKEOpen = %q, %v", got, err)
			}
			// Wrong external AAD or info fails.
			if _, err := HPKEOpen(back, priv, WithDraftHPKE27(), WithHPKEInfo([]byte("info"))); !errors.Is(err, ErrDecryption) {
				t.Errorf("missing external AAD: %v", err)
			}
			if _, err := HPKEOpen(back, priv, WithDraftHPKE27(), WithEncryptExternalAAD([]byte("aad"))); !errors.Is(err, ErrDecryption) {
				t.Errorf("missing info: %v", err)
			}
			// Tampered ciphertext fails.
			back.Ciphertext[0] ^= 1
			if _, err := HPKEOpen(back, priv, opts...); !errors.Is(err, ErrDecryption) {
				t.Errorf("tampered: %v", err)
			}
		})
	}
}

func TestHPKEKeyEncryptionRoundTrip(t *testing.T) {
	pt := []byte("key encryption payload")
	for _, s := range hpkeSupportedSuites {
		t.Run(s.String(), func(t *testing.T) {
			priv, pub := hpkeTestKeys(t, s)
			send := &HPKERecipient{Suite: s, PublicKey: pub, KeyID: []byte("bob"), ExtraInfo: []byte("ctx")}
			msg, err := EncryptMulti(pt, AlgA256GCM, []KeyDeriver{send}, WithDraftHPKE27())
			if err != nil {
				t.Fatal(err)
			}
			rec := &msg.Recipients[0]
			if got := rec.Protected.Algorithm(); got != s.KeyEncryptionAlgorithm() {
				t.Fatalf("recipient alg = %s, want %s", got, s.KeyEncryptionAlgorithm())
			}
			if kid := rec.Protected.KeyID(); !bytes.Equal(kid, []byte("bob")) {
				t.Fatalf("recipient protected kid = %q", kid)
			}
			if _, ok := rec.Unprotected.params[headerLabelHPKEEncapsulatedKey].([]byte); !ok {
				t.Fatal("no ek header")
			}
			wire, err := MarshalEncrypt(msg)
			if err != nil {
				t.Fatal(err)
			}
			back, err := UnmarshalEncrypt(wire)
			if err != nil {
				t.Fatal(err)
			}
			open := &HPKERecipient{Suite: s, PrivateKey: priv, ExtraInfo: []byte("ctx")}
			got, err := DecryptMulti(back, open, 0, WithDraftHPKE27())
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("DecryptMulti = %q, %v", got, err)
			}
			// recipient_extra_info is bound: a different one fails.
			wrong := &HPKERecipient{Suite: s, PrivateKey: priv, ExtraInfo: []byte("other")}
			if _, err := DecryptMulti(back, wrong, 0, WithDraftHPKE27()); !errors.Is(err, ErrDecryption) {
				t.Errorf("wrong extra info: %v", err)
			}
		})
	}
}

// The Recipient_structure binds next_layer_alg: relabeling the content
// algorithm must break the key unwrap (draft-27 §3.3.3).
func TestHPKENextLayerAlgBound(t *testing.T) {
	priv, pub := hpkeTestKeys(t, HPKE0)
	msg, err := EncryptMulti([]byte("x"), AlgA128GCM, []KeyDeriver{&HPKERecipient{Suite: HPKE0, PublicKey: pub}}, WithDraftHPKE27())
	if err != nil {
		t.Fatal(err)
	}
	rec := &msg.Recipients[0]
	protBytes, err := rec.Protected.encodeProtected()
	if err != nil {
		t.Fatal(err)
	}
	r := &HPKERecipient{Suite: HPKE0, PrivateKey: priv}
	if _, err := r.UnwrapKey(rec.Ciphertext, rec.Unprotected, KeyUnwrapOpts{
		CEKAlgorithm: AlgA256GCM, protected: string(protBytes), legacy: legacyEncoding{draftHPKE27: true},
	}); !errors.Is(err, ErrDecryption) {
		t.Fatalf("unwrap with a different next_layer_alg: %v", err)
	}
}

func TestHPKEUnsupportedModesAndKeys(t *testing.T) {
	priv, pub := hpkeTestKeys(t, HPKE0)
	opts := []EncryptOption{WithDraftHPKE27()}

	// mode_psk is not available in Go's crypto/hpke.
	psk := &HPKERecipient{Suite: HPKE0, PublicKey: pub, PSK: []byte("k"), PSKID: []byte("id")}
	if _, err := EncryptMulti([]byte("x"), AlgA128GCM, []KeyDeriver{psk}, opts...); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("PSK seal: %v", err)
	}
	msg, err := HPKESeal([]byte("x"), pub, HPKE0, opts...)
	if err != nil {
		t.Fatal(err)
	}
	pskMsg := *msg
	pskMsg.Protected = Headers{}
	pskMsg.Protected.SetAlgorithm(HPKE0.IntegratedAlgorithm())
	setParam(&pskMsg.Protected, headerLabelHPKEPSKID, []byte("id"))
	if _, err := HPKEOpen(&pskMsg, priv, opts...); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("psk_id open: %v", err)
	}

	// X448 suites are not implementable with the standard library.
	if _, err := HPKESeal([]byte("x"), pub, HPKE5, opts...); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("HPKE-5: %v", err)
	}

	// A key on the wrong curve for the suite is rejected.
	if _, err := HPKESeal([]byte("x"), pub, HPKE1, opts...); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("P-256 key for HPKE-1: %v", err)
	}
	// A key whose alg names another suite is an alg mismatch.
	pub.SetAlgorithm(HPKE7.IntegratedAlgorithm())
	if _, err := HPKESeal([]byte("x"), pub, HPKE0, opts...); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Errorf("key alg HPKE-7 for HPKE-0: %v", err)
	}

	// alg must be protected, and must be an integrated identifier.
	unprot := *msg
	unprot.Protected = Headers{}
	unprot.Unprotected = msg.Unprotected
	setParam(&unprot.Unprotected, headerLabelAlgorithm, int64(HPKE0.IntegratedAlgorithm()))
	if _, err := HPKEOpen(&unprot, priv, opts...); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Errorf("unprotected alg: %v", err)
	}
	ke := *msg
	ke.Protected = Headers{}
	ke.Protected.SetAlgorithm(HPKE0.KeyEncryptionAlgorithm())
	if _, err := HPKEOpen(&ke, priv, opts...); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Errorf("KE alg on Encrypt0: %v", err)
	}
}

// HPKEKey (v0.2.2 format) keeps working unchanged next to the draft API.
func TestHPKEKeyLegacyUnchanged(t *testing.T) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &HPKEKey{PublicKey: k.PublicKey(), PrivateKey: k}
	msg, err := EncryptMulti([]byte("legacy"), AlgA128GCM, []KeyDeriver{legacy})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptMulti(msg, legacy, 0)
	if err != nil || string(got) != "legacy" {
		t.Fatalf("HPKEKey round trip = %q, %v", got, err)
	}
}

// FuzzHPKEOpen: arbitrary COSE_Encrypt0 and COSE_Encrypt bytes never
// panic the HPKE open paths.
func FuzzHPKEOpen(f *testing.F) {
	for _, v := range hpkeDraft27Vectors {
		if b, err := hex.DecodeString(v.ciphertext); err == nil {
			f.Add(b)
		}
	}
	priv, _ := hpkeTestKeys(f, HPKE0)
	f.Fuzz(func(t *testing.T, data []byte) {
		if msg, err := UnmarshalEncrypt0(data); err == nil {
			_, _ = HPKEOpen(msg, priv, WithDraftHPKE27())
		}
		if msg, err := UnmarshalEncrypt(data); err == nil && len(msg.Recipients) > 0 {
			_, _ = DecryptMulti(msg, &HPKERecipient{Suite: HPKE0, PrivateKey: priv}, 0, WithDraftHPKE27())
		}
	})
}
