package cose

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestEncrypt0_AESGCM128_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	plaintext := []byte("hello AES-128-GCM")

	msg, err := EncryptEncrypt0(plaintext, key, nonce, AlgA128GCM)
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecryptEncrypt0(msg, key, nonce, AlgA128GCM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncrypt0_AESGCM256_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	plaintext := []byte("hello AES-256-GCM")

	msg, err := EncryptEncrypt0(plaintext, key, nonce, AlgA256GCM)
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecryptEncrypt0(msg, key, nonce, AlgA256GCM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncrypt0_WrongKey(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)

	msg, err := EncryptEncrypt0([]byte("secret"), key, nonce, AlgA128GCM)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := make([]byte, 16)
	rand.Read(wrongKey)
	_, err = DecryptEncrypt0(msg, wrongKey, nonce, AlgA128GCM)
	if !errors.Is(err, ErrDecryption) {
		t.Fatalf("expected ErrDecryption, got %v", err)
	}
}

func TestEncrypt0_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)

	msg, err := EncryptEncrypt0([]byte("secret"), key, nonce, AlgA128GCM)
	if err != nil {
		t.Fatal(err)
	}

	msg.Ciphertext[0] ^= 0xff
	_, err = DecryptEncrypt0(msg, key, nonce, AlgA128GCM)
	if !errors.Is(err, ErrDecryption) {
		t.Fatalf("expected ErrDecryption, got %v", err)
	}
}

func TestEncrypt0_ExternalAAD(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	aad := []byte("external context")

	msg, err := EncryptEncrypt0([]byte("data"), key, nonce, AlgA128GCM, WithEncryptExternalAAD(aad))
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptEncrypt0(msg, key, nonce, AlgA128GCM)
	if !errors.Is(err, ErrDecryption) {
		t.Fatal("expected decryption failure without matching AAD")
	}

	got, err := DecryptEncrypt0(msg, key, nonce, AlgA128GCM, WithEncryptExternalAAD(aad))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("data")) {
		t.Fatalf("unexpected plaintext: %q", got)
	}
}

func TestMarshalEncrypt0_Tagged(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)

	msg, err := EncryptEncrypt0([]byte("marshal test"), key, nonce, AlgA128GCM)
	if err != nil {
		t.Fatal(err)
	}

	data, err := MarshalEncrypt0(msg)
	if err != nil {
		t.Fatal(err)
	}

	if data[0] != 0xd0 {
		t.Fatalf("expected CBOR tag 16, got first byte 0x%02x", data[0])
	}

	decoded, err := UnmarshalEncrypt0(data)
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecryptEncrypt0(decoded, key, nonce, AlgA128GCM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("marshal test")) {
		t.Fatalf("round-trip through marshal failed: got %q", got)
	}
}

func TestDirectKeyDeriver_WrapUnwrap(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	dk := &DirectKey{Key: key}
	if dk.Algorithm() != AlgDirect {
		t.Fatalf("expected AlgDirect, got %v", dk.Algorithm())
	}

	ciphertext, _, err := dk.WrapKey(nil, KeyWrapOpts{CEKAlgorithm: AlgA256GCM, CEKLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext != nil {
		t.Fatal("direct wrap should produce nil ciphertext")
	}

	cek, err := dk.UnwrapKey(nil, Headers{}, KeyUnwrapOpts{CEKAlgorithm: AlgA256GCM, CEKLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cek, key) {
		t.Fatal("unwrapped key does not match")
	}

	_, _, err = dk.WrapKey(nil, KeyWrapOpts{CEKAlgorithm: AlgA128GCM, CEKLength: 16})
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for length mismatch, got %v", err)
	}
}
