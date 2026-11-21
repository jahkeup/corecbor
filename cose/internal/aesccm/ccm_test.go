// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package aesccm

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	aead, err := New(key, 8, 13)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, 13)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello, AES-CCM-16-64-128!")
	aad := []byte("additional data")

	ct := aead.Seal(nil, nonce, plaintext, aad)
	if len(ct) != len(plaintext)+8 {
		t.Fatalf("ciphertext length: got %d, want %d", len(ct), len(plaintext)+8)
	}

	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestAuthFailure(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	aead, err := New(key, 8, 13)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, 13)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	ct := aead.Seal(nil, nonce, []byte("test"), []byte("aad"))
	ct[0] ^= 0xff

	_, err = aead.Open(nil, nonce, ct, []byte("aad"))
	if err == nil {
		t.Fatal("expected authentication error")
	}
}

func TestWrongAAD(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	aead, err := New(key, 8, 13)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, 13)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	ct := aead.Seal(nil, nonce, []byte("test"), []byte("correct"))
	_, err = aead.Open(nil, nonce, ct, []byte("wrong"))
	if err == nil {
		t.Fatal("expected authentication error with wrong AAD")
	}
}

func TestEmptyPlaintext(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	aead, err := New(key, 8, 13)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, 13)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	ct := aead.Seal(nil, nonce, nil, []byte("aad"))
	if len(ct) != 8 {
		t.Fatalf("empty plaintext ciphertext should be tag-only, got %d bytes", len(ct))
	}

	pt, err := aead.Open(nil, nonce, ct, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(pt))
	}
}
