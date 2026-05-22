// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

//go:build go1.26

package cose

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
)

func generateP256Pair(t *testing.T) (*ecdh.PrivateKey, *ecdh.PublicKey) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return priv, priv.PublicKey()
}

func TestHPKEKey_WrapUnwrap_RoundTrip(t *testing.T) {
	priv, pub := generateP256Pair(t)
	cek := make([]byte, 16)
	if _, err := rand.Read(cek); err != nil {
		t.Fatalf("rand: %v", err)
	}

	wrapper := &HPKEKey{PublicKey: pub}
	opts := KeyWrapOpts{CEKAlgorithm: AlgA128GCM, CEKLength: 16}
	sealed, _, err := wrapper.WrapKey(cek, opts)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	unwrapper := &HPKEKey{PrivateKey: priv}
	got, err := unwrapper.UnwrapKey(sealed, Headers{}, KeyUnwrapOpts{CEKAlgorithm: AlgA128GCM, CEKLength: 16})
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(cek, got) {
		t.Fatalf("CEK mismatch: want %x got %x", cek, got)
	}
}

func TestHPKEKey_WrongPrivateKey(t *testing.T) {
	_, pub := generateP256Pair(t)
	wrongPriv, _ := generateP256Pair(t)

	cek := make([]byte, 16)
	if _, err := rand.Read(cek); err != nil {
		t.Fatalf("rand: %v", err)
	}

	wrapper := &HPKEKey{PublicKey: pub}
	sealed, _, err := wrapper.WrapKey(cek, KeyWrapOpts{CEKAlgorithm: AlgA128GCM, CEKLength: 16})
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	unwrapper := &HPKEKey{PrivateKey: wrongPriv}
	_, err = unwrapper.UnwrapKey(sealed, Headers{}, KeyUnwrapOpts{CEKAlgorithm: AlgA128GCM, CEKLength: 16})
	if err == nil {
		t.Fatal("expected error with wrong private key, got nil")
	}
	if !errors.Is(err, ErrDecryption) {
		t.Fatalf("expected ErrDecryption, got: %v", err)
	}
}

func TestHPKEKey_EncryptMulti_WithHPKE(t *testing.T) {
	priv, pub := generateP256Pair(t)
	plaintext := []byte("hello HPKE COSE")

	recipient := &HPKEKey{PublicKey: pub}
	msg, err := EncryptMulti(plaintext, AlgA128GCM, []KeyDeriver{recipient})
	if err != nil {
		t.Fatalf("EncryptMulti: %v", err)
	}

	decryptor := &HPKEKey{PrivateKey: priv}
	got, err := DecryptMulti(msg, decryptor, 0)
	if err != nil {
		t.Fatalf("DecryptMulti: %v", err)
	}
	if !bytes.Equal(plaintext, got) {
		t.Fatalf("plaintext mismatch: want %q got %q", plaintext, got)
	}
}
