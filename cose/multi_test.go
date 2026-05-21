// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestSignMulti_TwoSigners(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer1, err := NewSigner(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	signer2, err := NewSigner(ecPriv)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("multi-signer test payload")
	msg, err := SignMulti(payload, []*Signer{signer1, signer2})
	if err != nil {
		t.Fatal(err)
	}

	if len(msg.Signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(msg.Signatures))
	}

	verifier1, err := NewVerifier(edPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	verifier2, err := NewVerifier(&ecPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := VerifyMulti(msg, []*Verifier{verifier1, verifier2})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(verified, []int{0, 1}) {
		t.Fatalf("expected [0, 1] verified, got %v", verified)
	}
}

func TestVerifyMulti_PartialSuccess(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer1, err := NewSigner(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	signer2, err := NewSigner(ecPriv)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("partial verify test")
	msg, err := SignMulti(payload, []*Signer{signer1, signer2})
	if err != nil {
		t.Fatal(err)
	}

	verifier1, err := NewVerifier(edPriv.Public())
	if err != nil {
		t.Fatal(err)
	}

	verified, err := VerifyMulti(msg, []*Verifier{verifier1})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(verified, []int{0}) {
		t.Fatalf("expected [0] verified, got %v", verified)
	}
}

func TestAddSignature(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer1, err := NewSigner(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	signer2, err := NewSigner(ecPriv)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("add signature test")
	msg, err := SignMulti(payload, []*Signer{signer1})
	if err != nil {
		t.Fatal(err)
	}

	if len(msg.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(msg.Signatures))
	}

	err = msg.AddSignature(signer2)
	if err != nil {
		t.Fatal(err)
	}

	if len(msg.Signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(msg.Signatures))
	}

	verifier1, err := NewVerifier(edPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	verifier2, err := NewVerifier(&ecPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := VerifyMulti(msg, []*Verifier{verifier1, verifier2})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(verified, []int{0, 1}) {
		t.Fatalf("expected [0, 1] verified, got %v", verified)
	}
}

func TestMarshalSign_Tagged(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(edPriv)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("marshal test")
	msg, err := SignMulti(payload, []*Signer{signer})
	if err != nil {
		t.Fatal(err)
	}

	data, err := MarshalSign(msg)
	if err != nil {
		t.Fatal(err)
	}

	// Tag 98 = 0xD8 0x62
	if len(data) < 2 || data[0] != 0xD8 || data[1] != 0x62 {
		t.Fatalf("expected tag 98 (0xD8 0x62) prefix, got %x", data[:2])
	}

	msg2, err := UnmarshalSign(data)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(msg.Payload, msg2.Payload) {
		t.Fatal("payload mismatch after round-trip")
	}
	if len(msg2.Signatures) != 1 {
		t.Fatalf("expected 1 signature after unmarshal, got %d", len(msg2.Signatures))
	}

	verifier, err := NewVerifier(edPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyMulti(msg2, []*Verifier{verifier})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verified, []int{0}) {
		t.Fatalf("expected [0] verified after round-trip, got %v", verified)
	}
}

func TestComputeMACMulti_TwoRecipients(t *testing.T) {
	macKey := make([]byte, 32)
	if _, err := rand.Read(macKey); err != nil {
		t.Fatal(err)
	}

	directKey := &DirectKey{Key: macKey}
	aesKWKey := &AESKWKey{Key: make([]byte, 16)}
	if _, err := rand.Read(aesKWKey.Key); err != nil {
		t.Fatal(err)
	}

	payload := []byte("mac multi test")
	msg, err := ComputeMACMulti(payload, macKey, AlgHMAC256, []KeyDeriver{directKey, aesKWKey})
	if err != nil {
		t.Fatal(err)
	}

	if len(msg.Recipients) != 2 {
		t.Fatalf("expected 2 recipients, got %d", len(msg.Recipients))
	}
	if len(msg.Tag) == 0 {
		t.Fatal("expected non-empty tag")
	}

	err = VerifyMACMulti(msg, directKey, 0)
	if err != nil {
		t.Fatalf("VerifyMACMulti with direct key failed: %v", err)
	}

	err = VerifyMACMulti(msg, aesKWKey, 1)
	if err != nil {
		t.Fatalf("VerifyMACMulti with AES-KW key failed: %v", err)
	}
}

func TestVerifyMACMulti_RecipientUnwraps(t *testing.T) {
	aesKey := make([]byte, 16)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatal(err)
	}
	recipient := &AESKWKey{Key: aesKey}

	payload := []byte("verify mac multi unwrap")
	msg, err := ComputeMACMulti(payload, nil, AlgHMAC256, []KeyDeriver{recipient})
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyMACMulti(msg, recipient, 0)
	if err != nil {
		t.Fatalf("VerifyMACMulti failed: %v", err)
	}

	data, err := MarshalMac(msg)
	if err != nil {
		t.Fatal(err)
	}

	// Tag 97 = 0xD8 0x61
	if len(data) < 2 || data[0] != 0xD8 || data[1] != 0x61 {
		t.Fatalf("expected tag 97 (0xD8 0x61) prefix, got %x", data[:2])
	}

	msg2, err := UnmarshalMac(data)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyMACMulti(msg2, recipient, 0)
	if err != nil {
		t.Fatalf("VerifyMACMulti after round-trip failed: %v", err)
	}
}
