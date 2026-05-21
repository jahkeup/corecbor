package cose

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestMac0_HMAC256_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	payload := []byte("hello HMAC-256")

	msg, err := ComputeMAC0(payload, key, AlgHMAC256)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Tag) != 32 {
		t.Fatalf("expected 32-byte tag, got %d", len(msg.Tag))
	}

	if err := VerifyMAC0(msg, key, AlgHMAC256); err != nil {
		t.Fatal(err)
	}
}

func TestMac0_HMAC512_RoundTrip(t *testing.T) {
	key := make([]byte, 64)
	rand.Read(key)
	payload := []byte("hello HMAC-512")

	msg, err := ComputeMAC0(payload, key, AlgHMAC512)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Tag) != 64 {
		t.Fatalf("expected 64-byte tag, got %d", len(msg.Tag))
	}

	if err := VerifyMAC0(msg, key, AlgHMAC512); err != nil {
		t.Fatal(err)
	}
}

func TestMac0_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	msg, err := ComputeMAC0([]byte("secret"), key, AlgHMAC256)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	err = VerifyMAC0(msg, wrongKey, AlgHMAC256)
	if !errors.Is(err, ErrMACVerification) {
		t.Fatalf("expected ErrMACVerification, got %v", err)
	}
}

func TestMac0_ExternalAAD(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	aad := []byte("external context")

	msg, err := ComputeMAC0([]byte("data"), key, AlgHMAC256, WithMACExternalAAD(aad))
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyMAC0(msg, key, AlgHMAC256)
	if !errors.Is(err, ErrMACVerification) {
		t.Fatal("expected MAC verification failure without matching AAD")
	}

	err = VerifyMAC0(msg, key, AlgHMAC256, WithMACExternalAAD(aad))
	if err != nil {
		t.Fatal(err)
	}
}

func TestMarshalMac0_Tagged(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	msg, err := ComputeMAC0([]byte("marshal test"), key, AlgHMAC256)
	if err != nil {
		t.Fatal(err)
	}

	data, err := MarshalMac0(msg)
	if err != nil {
		t.Fatal(err)
	}

	if data[0] != 0xd1 {
		t.Fatalf("expected CBOR tag 17, got first byte 0x%02x", data[0])
	}

	decoded, err := UnmarshalMac0(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded.Payload, []byte("marshal test")) {
		t.Fatalf("payload mismatch after unmarshal: %q", decoded.Payload)
	}
	if !bytes.Equal(decoded.Tag, msg.Tag) {
		t.Fatal("tag mismatch after unmarshal")
	}

	if err := VerifyMAC0(decoded, key, AlgHMAC256); err != nil {
		t.Fatal("verification failed after marshal round-trip:", err)
	}
}
