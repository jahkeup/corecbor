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

func BenchmarkSign1_Ed25519(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewSigner(priv)
	payload := make([]byte, 1024)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		_, err := signer.Sign(payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify1_Ed25519(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewSigner(priv)
	verifier, _ := NewVerifier(pub)
	payload := make([]byte, 1024)
	msg, _ := signer.Sign(payload)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		if err := verifier.Verify(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign1_ES256(b *testing.B) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := NewSigner(priv)
	payload := make([]byte, 1024)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		_, err := signer.Sign(payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify1_ES256(b *testing.B) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	verifier, _ := NewVerifier(&priv.PublicKey)
	signer, _ := NewSigner(priv)
	payload := make([]byte, 1024)
	msg, _ := signer.Sign(payload)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		if err := verifier.Verify(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt0_AESGCM256(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	rand.Read(key)
	rand.Read(nonce)
	plaintext := make([]byte, 1024)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for b.Loop() {
		_, err := EncryptEncrypt0(plaintext, key, nonce, AlgA256GCM)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshalSign1(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewSigner(priv)
	payload := make([]byte, 256)
	msg, _ := signer.Sign(payload)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		_, err := MarshalSign1(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}
