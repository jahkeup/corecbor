// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"testing"
)

// meriadocP256 is the cose-wg example key meriadoc.brandybuck@buckland.example.
func meriadocP256(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.P256().NewPrivateKey(hx(t, "aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Proposal 037 S3 follow-up: DecryptMultiNested opens a recipient
// nested under others and unwraps each layer above it, so the RFC 9052
// Appendix B message decrypts end to end.
func TestSpec037NestedDecrypt(t *testing.T) {
	msg, err := UnmarshalEncrypt(rfc9052AppendixB(t))
	if err != nil {
		t.Fatal(err)
	}
	leaf := &ECDHESKey{PrivateKey: meriadocP256(t)}
	got, err := DecryptMultiNested(msg, leaf, []int{0, 0})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "This is the content." {
		t.Fatalf("plaintext = %q", got)
	}

	// Bad paths.
	for _, path := range [][]int{nil, {1}, {0, 1}, {0, 0, 0}, {-1}} {
		if _, err := DecryptMultiNested(msg, leaf, path); !errors.Is(err, ErrDecryption) {
			t.Fatalf("path %v: err = %v, want ErrDecryption", path, err)
		}
	}
	// A one-element path is DecryptMulti.
	kw := &AESKWKey{Key: bytes.Repeat([]byte{4}, 16)}
	flat, err := EncryptMulti([]byte("x"), AlgA128GCM, []KeyDeriver{kw})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecryptMultiNested(flat, kw, []int{0}); err != nil || string(got) != "x" {
		t.Fatalf("flat path: %q, %v", got, err)
	}
	// COSE_Mac: an AES-KW layer whose key is wrapped by a nested AES-KW.
	macKey := bytes.Repeat([]byte{6}, 32)
	kek1, kek2 := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{8}, 32)
	m, err := ComputeMACMulti([]byte("p"), macKey, AlgHMAC256, []KeyDeriver{&AESKWKey{Key: kek1}})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, _, err := (&AESKWKey{Key: kek2}).WrapKey(kek1, KeyWrapOpts{})
	if err != nil {
		t.Fatal(err)
	}
	var u Headers
	u.SetAlgorithm(AlgA256KW)
	m.Recipients[0].Recipients = []Recipient{{Unprotected: u, Ciphertext: wrapped}}
	b, err := MarshalMac(m)
	if err != nil {
		t.Fatal(err)
	}
	if m, err = UnmarshalMac(b); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMACMultiNested(m, &AESKWKey{Key: kek2}, []int{0, 0}); err != nil {
		t.Fatalf("VerifyMACMultiNested: %v", err)
	}
	if err := VerifyMACMultiNested(m, &AESKWKey{Key: bytes.Repeat([]byte{9}, 32)}, []int{0, 0}); !errors.Is(err, ErrMACVerification) {
		t.Fatalf("wrong leaf key: err = %v, want ErrMACVerification", err)
	}

	// An intermediate layer whose algorithm can't carry a key.
	msg.Recipients[0].Unprotected = Headers{}
	msg.Recipients[0].Unprotected.SetAlgorithm(AlgECDH_ES_A128KW)
	if _, err := DecryptMultiNested(msg, leaf, []int{0, 0}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("ECDH-ES+A128KW intermediate: err = %v, want ErrUnsupportedAlgorithm", err)
	}
}
