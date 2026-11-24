// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor"
)

// TestCountersignSignatureAndRecipient countersigns a COSE_Signature
// inside a COSE_Sign and a COSE_recipient (RFC 9338 §2), and checks the
// Countersign_structure each one is signed over (§3.3): two bstr fields,
// so the second (the signature value, the recipient ciphertext) is the
// payload and other_fields is absent.
func TestCountersignSignatureAndRecipient(t *testing.T) {
	cs, _ := NewSigner(hardEdPriv)
	v, _ := NewVerifier(hardEdPub)

	s, _ := NewSigner(hardEdPriv)
	sign, err := SignMulti(content, []*Signer{s})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := EncryptMulti(content, AlgA128GCM, []KeyDeriver{&AESKWKey{Key: bytes.Repeat([]byte{2}, 16)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.Countersign(&sign.Signatures[0]); err != nil {
		t.Fatal(err)
	}
	if err := cs.Countersign0(&sign.Signatures[0]); err != nil {
		t.Fatal(err)
	}
	if err := cs.Countersign(&enc.Recipients[0]); err != nil {
		t.Fatal(err)
	}
	if err := cs.Countersign0(&enc.Recipients[0]); err != nil {
		t.Fatal(err)
	}

	b, err := MarshalSign(sign)
	if err != nil {
		t.Fatal(err)
	}
	if sign, err = UnmarshalSign(b); err != nil {
		t.Fatal(err)
	}
	if b, err = MarshalEncrypt(enc); err != nil {
		t.Fatal(err)
	}
	if enc, err = UnmarshalEncrypt(b); err != nil {
		t.Fatal(err)
	}

	for name, target := range map[string]CountersignTarget{
		"COSE_Signature": &sign.Signatures[0],
		"COSE_recipient": &enc.Recipients[0],
	} {
		t.Run(name, func(t *testing.T) {
			css, err := Countersignatures(target)
			if err != nil || len(css) != 1 {
				t.Fatalf("Countersignatures = %d, %v", len(css), err)
			}
			if err := v.VerifyCountersignature(target, css[0]); err != nil {
				t.Fatalf("VerifyCountersignature: %v", err)
			}
			if err := v.VerifyCountersignature0(target); err != nil {
				t.Fatalf("VerifyCountersignature0: %v", err)
			}

			// The structure signed: ["CounterSignature0", protected, h'',
			// second bstr field].
			l := target.countersignLayer()
			prot, _ := l.prot.encodeProtected()
			tbs := encodeCBOR(t, corecbor.MakeArray(corecbor.Text("CounterSignature0"),
				corecbor.Bytes(orEmpty(prot)), corecbor.Bytes(nil), corecbor.Bytes(orEmpty(l.payload))))
			sig, _ := l.unprot.params[HeaderCountersignature0].([]byte)
			if err := v.verifyBytes(AlgEdDSA, tbs, sig); err != nil {
				t.Fatalf("Countersign_structure differs from RFC 9338 §3.3: %v", err)
			}
		})
	}

	// The message's own signature and decryption are undisturbed.
	if _, err := VerifyMulti(sign, []*Verifier{v}); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptMulti(enc, &AESKWKey{Key: bytes.Repeat([]byte{2}, 16)}, 0); err != nil {
		t.Fatal(err)
	}
	// Changing the countersigned signature invalidates the countersignature.
	sign.Signatures[0].Signature = bytes.Clone(sign.Signatures[0].Signature)
	sign.Signatures[0].Signature[0] ^= 1
	if err := v.VerifyCountersignature0(&sign.Signatures[0]); !errors.Is(err, ErrVerification) {
		t.Fatalf("altered signature: err = %v, want ErrVerification", err)
	}
	// An unsigned COSE_Signature can't be countersigned.
	if err := cs.Countersign(&Signature{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty COSE_Signature: err = %v, want ErrMalformed", err)
	}
}

func orEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// TestCountersignDetached countersigns and verifies messages whose
// payload or ciphertext is detached, with the caller supplying it.
func TestCountersignDetached(t *testing.T) {
	cs, _ := NewSigner(hardEdPriv)
	v, _ := NewVerifier(hardEdPub)
	s, _ := NewSigner(hardEdPriv)

	sign1, _ := s.SignDetached(content)
	sign, _ := SignMultiDetached(content, []*Signer{s})
	macKey := bytes.Repeat([]byte{0x0b}, 32)
	mac0, _ := ComputeMAC0(content, macKey, AlgHMAC256)
	mac0.Payload = nil
	aesKey := bytes.Repeat([]byte{0x0d}, 16)
	enc0, _ := Encrypt0Seal(content, aesKey, AlgA128GCM)
	ct := enc0.Ciphertext
	enc0.Ciphertext = nil

	for name, c := range map[string]struct {
		target   CountersignTarget
		detached []byte
	}{
		"Sign1":    {sign1, content},
		"Sign":     {sign, content},
		"Mac0":     {mac0, content},
		"Encrypt0": {enc0, ct},
	} {
		t.Run(name, func(t *testing.T) {
			if err := cs.Countersign(c.target); !errors.Is(err, ErrMissingPayload) {
				t.Fatalf("Countersign on detached: err = %v, want ErrMissingPayload", err)
			}
			if err := cs.CountersignDetached(c.target, c.detached); err != nil {
				t.Fatal(err)
			}
			if err := cs.Countersign0Detached(c.target, c.detached); err != nil {
				t.Fatal(err)
			}
			css, err := Countersignatures(c.target)
			if err != nil || len(css) != 1 {
				t.Fatalf("Countersignatures = %d, %v", len(css), err)
			}
			if err := v.VerifyCountersignatureDetached(c.target, css[0], c.detached); err != nil {
				t.Fatalf("VerifyCountersignatureDetached: %v", err)
			}
			if err := v.VerifyCountersignature0Detached(c.target, c.detached); err != nil {
				t.Fatalf("VerifyCountersignature0Detached: %v", err)
			}
			if err := v.VerifyCountersignature(c.target, css[0]); !errors.Is(err, ErrMissingPayload) {
				t.Fatalf("VerifyCountersignature without the payload: err = %v, want ErrMissingPayload", err)
			}
			other := append(bytes.Clone(c.detached), 'x')
			if err := v.VerifyCountersignatureDetached(c.target, css[0], other); !errors.Is(err, ErrVerification) {
				t.Fatalf("other detached bytes: err = %v, want ErrVerification", err)
			}
		})
	}

	// A COSE_Signature or COSE_recipient has no detachable content.
	m, _ := SignMulti(content, []*Signer{s})
	if err := cs.CountersignDetached(&m.Signatures[0], content); !errors.Is(err, ErrMalformed) {
		t.Fatalf("CountersignDetached on a COSE_Signature: err = %v, want ErrMalformed", err)
	}
}
