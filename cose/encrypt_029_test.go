// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor"
)

// Proposal 029: Encrypt0 IV handling, PBES2 identifiers, conformant
// ECDH-ES.

func TestEncrypt0SealIV(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	a, err := Encrypt0Seal([]byte("hello"), key, AlgA128GCM)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt0Seal([]byte("hello"), key, AlgA128GCM)
	if err != nil {
		t.Fatal(err)
	}
	iv, ok := a.Unprotected.Get(headerLabelIV).([]byte)
	if !ok || len(iv) != 12 {
		t.Fatalf("IV header = %v", a.Unprotected.Get(headerLabelIV))
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("two seals produced the same ciphertext")
	}
	wire, err := MarshalEncrypt0(a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalEncrypt0(wire)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Encrypt0Open(got, key)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("Encrypt0Open = %q, %v", pt, err)
	}
	// The v0.2 API can open it with the transmitted IV.
	if pt, err := DecryptEncrypt0(got, key, iv, AlgA128GCM); err != nil || string(pt) != "hello" {
		t.Fatalf("DecryptEncrypt0 = %q, %v", pt, err)
	}
	if _, err := Encrypt0Open(got, bytes.Repeat([]byte{8}, 16)); !errors.Is(err, ErrDecryption) {
		t.Fatalf("wrong key = %v", err)
	}

	both := *got
	both.Unprotected = Headers{}
	setParam(&both.Unprotected, headerLabelIV, iv)
	setParam(&both.Unprotected, headerLabelPartialIV, []byte{1})
	if _, err := Encrypt0Open(&both, key); !errors.Is(err, ErrMalformed) {
		t.Fatalf("IV and Partial IV = %v, want ErrMalformed", err)
	}
	none := *got
	none.Unprotected = Headers{}
	if _, err := Encrypt0Open(&none, key); !errors.Is(err, ErrDecryption) {
		t.Fatalf("no IV = %v, want ErrDecryption", err)
	}

	nonce := bytes.Repeat([]byte{1}, 12)
	f1, _ := Encrypt0Seal([]byte("x"), key, AlgA128GCM, WithNonce(nonce))
	f2, _ := Encrypt0Seal([]byte("x"), key, AlgA128GCM, WithNonce(nonce))
	if !bytes.Equal(f1.Ciphertext, f2.Ciphertext) {
		t.Fatal("WithNonce not deterministic")
	}
	if _, err := Encrypt0Seal([]byte("x"), key, AlgA128GCM, WithNonce(nonce[:5])); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short nonce = %v", err)
	}
}

func TestEncrypt0PartialIV(t *testing.T) {
	// AES-CCM-16-64-128 as in OSCORE (RFC 8613): 13-byte Base IV, a
	// short Partial IV (the sequence number).
	key := bytes.Repeat([]byte{3}, 16)
	baseIV := []byte{0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68, 0xee, 0xfb, 0x54, 0x98, 0x7c}
	piv := []byte{0x14}
	msg, err := Encrypt0Seal([]byte("oscore"), key, AlgAESCCM_16_64_128, WithPartialIV(baseIV, piv))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Unprotected.Get(headerLabelIV) != nil {
		t.Fatal("IV header written with a Partial IV")
	}
	if got, _ := msg.Unprotected.Get(headerLabelPartialIV).([]byte); !bytes.Equal(got, piv) {
		t.Fatalf("Partial IV header = %x", got)
	}
	// The nonce is the Base IV with the Partial IV XORed into its tail.
	want := bytes.Clone(baseIV)
	want[12] ^= 0x14
	ref, err := Encrypt0Seal([]byte("oscore"), key, AlgAESCCM_16_64_128, WithNonce(want))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ref.Ciphertext, msg.Ciphertext) {
		t.Fatal("Partial IV nonce isn't Base IV XOR Partial IV")
	}
	if len(msg.Ciphertext) != len("oscore")+8 {
		t.Fatalf("CCM tag length: %d", len(msg.Ciphertext))
	}
	ccm := WithEncryptAlgorithms(AlgAESCCM_16_64_128)
	pt, err := Encrypt0Open(msg, key, ccm, WithPartialIV(baseIV, nil))
	if err != nil || string(pt) != "oscore" {
		t.Fatalf("Encrypt0Open = %q, %v", pt, err)
	}
	if _, err := Encrypt0Open(msg, key, ccm); !errors.Is(err, ErrDecryption) {
		t.Fatalf("no Base IV = %v", err)
	}
	// CCM isn't accepted unless allowed.
	if _, err := Encrypt0Open(msg, key, WithPartialIV(baseIV, nil)); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("CCM by default = %v, want ErrAlgorithmMismatch", err)
	}
	if _, err := Encrypt0Seal(nil, key, AlgAESCCM_16_64_128, WithPartialIV(baseIV, make([]byte, 14))); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("long Partial IV = %v", err)
	}
}

func recipientAlgOf(t *testing.T, r *Recipient) Algorithm {
	t.Helper()
	a, _, err := headerAlg(&r.Protected, &r.Unprotected)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPBES2Identifiers(t *testing.T) {
	p := &PBES2Key{Password: []byte("pw"), Count: 1000}
	msg, err := EncryptMulti([]byte("secret"), AlgA128GCM, []KeyDeriver{p})
	if err != nil {
		t.Fatal(err)
	}
	r := &msg.Recipients[0]
	if a := recipientAlgOf(t, r); a != AlgPrivatePBES2_HS256_A128KW {
		t.Fatalf("recipient alg = %v", a)
	}
	if r.Unprotected.Get(headerLabelPBES2Count) == nil || r.Unprotected.Get(headerLabelLegacyPBES2Count) != nil {
		t.Fatalf("count label: %v", r.Unprotected.params)
	}
	if pt, err := DecryptMulti(msg, p, 0); err != nil || string(pt) != "secret" {
		t.Fatalf("DecryptMulti = %q, %v", pt, err)
	}

	legacy, err := EncryptMulti([]byte("secret"), AlgA128GCM, []KeyDeriver{p}, WithLegacyPBES2Labels())
	if err != nil {
		t.Fatal(err)
	}
	lr := &legacy.Recipients[0]
	if a := recipientAlgOf(t, lr); a != AlgPBES2_HS256_A128KW {
		t.Fatalf("legacy recipient alg = %v", a)
	}
	if lr.Unprotected.Get(headerLabelLegacyPBES2Count) == nil {
		t.Fatal("legacy count label missing")
	}
	if _, err := DecryptMulti(legacy, p, 0); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("-11 without opt-in = %v, want ErrUnsupportedAlgorithm", err)
	}
	if pt, err := DecryptMulti(legacy, p, 0, WithLegacyPBES2Labels()); err != nil || string(pt) != "secret" {
		t.Fatalf("legacy DecryptMulti = %q, %v", pt, err)
	}
	if pt, err := DecryptMulti(legacy, p, 0, CompatV02Encryption()); err != nil || string(pt) != "secret" {
		t.Fatalf("CompatV02Encryption = %q, %v", pt, err)
	}
	// A new message isn't readable in legacy mode.
	if _, err := DecryptMulti(msg, p, 0, WithLegacyPBES2Labels()); err == nil {
		t.Fatal("private-use message opened in legacy mode")
	}
}

func TestECDHESConformant(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []Algorithm{AlgECDH_ES_HKDF_256, AlgECDH_ES_HKDF_512, AlgECDH_ES_A128KW, AlgECDH_ES_A192KW, AlgECDH_ES_A256KW} {
		t.Run(alg.String(), func(t *testing.T) {
			send := &ECDHESKey{
				PeerPublic: priv.PublicKey(), Alg: alg,
				KDF: &ECDHKDFContext{PartyU: PartyInfo{Identity: []byte("alice")}, PartyV: PartyInfo{Identity: []byte("bob")}},
			}
			msg, err := EncryptMulti([]byte("content"), AlgA256GCM, []KeyDeriver{send})
			if err != nil {
				t.Fatal(err)
			}
			wire, err := MarshalEncrypt(msg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := UnmarshalEncrypt(wire)
			if err != nil {
				t.Fatal(err)
			}
			r := &got.Recipients[0]
			if a := recipientAlgOf(t, r); a != alg {
				t.Fatalf("recipient alg = %v", a)
			}
			epk, ok := r.Unprotected.Get(headerLabelEphemeralKey).(corecbor.Value)
			if !ok || epk.Kind != corecbor.KindMap {
				t.Fatalf("ephemeral key isn't a COSE_Key map: %T", r.Unprotected.Get(headerLabelEphemeralKey))
			}
			if direct := isDirectKeyAgreement(alg); direct != (len(r.Ciphertext) == 0) {
				t.Fatalf("direct %v, recipient ciphertext %d bytes", direct, len(r.Ciphertext))
			}
			// The party identities are in the recipient headers, so the
			// recipient doesn't need to configure them.
			recv := &ECDHESKey{PrivateKey: priv, Alg: alg}
			if pt, err := DecryptMulti(got, recv, 0); err != nil || string(pt) != "content" {
				t.Fatalf("DecryptMulti = %q, %v", pt, err)
			}
			// Tampering with a party identity changes the derived key.
			r.Unprotected.params[int64(-21)] = []byte("mallory")
			if _, err := DecryptMulti(got, recv, 0); err == nil {
				t.Fatal("tampered PartyU identity decrypted")
			}
		})
	}
}

func TestECDHESDirectSoleRecipient(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	direct := &ECDHESKey{PeerPublic: priv.PublicKey()}
	other := &AESKWKey{Key: make([]byte, 16)}
	if _, err := EncryptMulti([]byte("x"), AlgA128GCM, []KeyDeriver{direct, other}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("direct with another recipient = %v, want ErrInvalidKey", err)
	}
	msg, err := EncryptMulti([]byte("x"), AlgA128GCM, []KeyDeriver{direct})
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := DecryptMulti(msg, &ECDHESKey{PrivateKey: priv}, 0); err != nil || string(pt) != "x" {
		t.Fatalf("X25519 direct = %q, %v", pt, err)
	}
}

func TestECDHESLegacy(t *testing.T) {
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	send := &ECDHESKey{PeerPublic: priv.PublicKey()}
	recv := &ECDHESKey{PrivateKey: priv}
	// v0.2's -25 wraps a random CEK, so it can share the message.
	msg, err := EncryptMulti([]byte("v02"), AlgA128GCM, []KeyDeriver{send, &AESKWKey{Key: make([]byte, 16)}}, WithLegacyECDHES())
	if err != nil {
		t.Fatal(err)
	}
	r := &msg.Recipients[0]
	if _, raw := r.Unprotected.Get(headerLabelEphemeralKey).([]byte); !raw {
		t.Fatal("legacy ephemeral key isn't a raw point")
	}
	if _, err := DecryptMulti(msg, recv, 0); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("legacy message without opt-in = %v, want ErrUnsupportedAlgorithm", err)
	}
	if pt, err := DecryptMulti(msg, recv, 0, WithLegacyECDHES()); err != nil || string(pt) != "v02" {
		t.Fatalf("legacy DecryptMulti = %q, %v", pt, err)
	}
}

func TestMACMultiECDH(t *testing.T) {
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	key := bytes.Repeat([]byte{9}, 32)
	wrap := &ECDHESKey{PeerPublic: priv.PublicKey(), Alg: AlgECDH_ES_A128KW}
	msg, err := ComputeMACMulti([]byte("p"), key, AlgHMAC256, []KeyDeriver{wrap})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMACMulti(msg, &ECDHESKey{PrivateKey: priv, Alg: AlgECDH_ES_A128KW}, 0); err != nil {
		t.Fatalf("ECDH-ES+A128KW MAC: %v", err)
	}
	// Direct agreement: the agreed key is the MAC key, so none is given.
	direct := &ECDHESKey{PeerPublic: priv.PublicKey()}
	if _, err := ComputeMACMulti([]byte("p"), key, AlgHMAC256, []KeyDeriver{direct}); err == nil {
		t.Fatal("direct MAC with a caller key succeeded")
	}
	dmsg, err := ComputeMACMulti([]byte("p"), nil, AlgHMAC256, []KeyDeriver{direct})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMACMulti(dmsg, &ECDHESKey{PrivateKey: priv}, 0); err != nil {
		t.Fatalf("direct MAC: %v", err)
	}
}
