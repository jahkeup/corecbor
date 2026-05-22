// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestKeyConversion_Ed25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	coseKey, err := NewKeyFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	if coseKey.KeyType() != KeyTypeOKP {
		t.Fatalf("expected OKP key type, got %d", coseKey.KeyType())
	}
	if coseKey.Curve() != CurveEd25519 {
		t.Fatalf("expected Ed25519 curve, got %d", coseKey.Curve())
	}

	recoveredPub, err := coseKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	if !pub.Equal(recoveredPub) {
		t.Fatal("public keys don't match")
	}

	recoveredSigner, err := coseKey.Signer()
	if err != nil {
		t.Fatal(err)
	}

	signer, _ := NewSigner(recoveredSigner)
	msg, _ := signer.Sign([]byte("roundtrip"))
	verifier, _ := NewVerifier(pub)
	if err := verifier.Verify(msg); err != nil {
		t.Fatal("verify with round-tripped key failed:", err)
	}
}

func TestKeyConversion_P256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	coseKey, err := NewKeyFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	if coseKey.KeyType() != KeyTypeEC2 {
		t.Fatalf("expected EC2 key type, got %d", coseKey.KeyType())
	}
	if coseKey.Curve() != CurveP256 {
		t.Fatalf("expected P256 curve, got %d", coseKey.Curve())
	}

	recoveredPub, err := coseKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	ecPub := recoveredPub.(*ecdsa.PublicKey)
	if !priv.PublicKey.Equal(ecPub) {
		t.Fatal("public keys don't match")
	}

	recoveredSigner, err := coseKey.Signer()
	if err != nil {
		t.Fatal(err)
	}

	signer, _ := NewSigner(recoveredSigner)
	msg, _ := signer.Sign([]byte("p256 roundtrip"))
	verifier, _ := NewVerifier(&priv.PublicKey)
	if err := verifier.Verify(msg); err != nil {
		t.Fatal("verify with round-tripped key failed:", err)
	}
}
