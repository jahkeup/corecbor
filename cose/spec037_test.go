// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"errors"
	"testing"
)

// Proposal 037 S1: a direct recipient (RFC 9052 §8.5.1) uses its key as
// the content key, must be the only recipient, and has an empty
// protected bucket and ciphertext.
func TestSpec037DirectRecipient(t *testing.T) {
	aesKey := bytes.Repeat([]byte{0x0d}, 16)
	macKey := bytes.Repeat([]byte{0x0b}, 32)
	kw := &AESKWKey{Key: bytes.Repeat([]byte{0x0e}, 16)}

	t.Run("EncryptMulti", func(t *testing.T) {
		msg, err := EncryptMulti([]byte("hello"), AlgA128GCM, []KeyDeriver{&DirectKey{Key: aesKey}})
		if err != nil {
			t.Fatal(err)
		}
		checkDirectLayout(t, msg.Recipients)
		b, err := MarshalEncrypt(msg)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := UnmarshalEncrypt(b)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecryptMulti(dec, &DirectKey{Key: aesKey}, 0)
		if err != nil || string(got) != "hello" {
			t.Fatalf("DecryptMulti = %q, %v", got, err)
		}
	})
	t.Run("EncryptMulti wrong length", func(t *testing.T) {
		_, err := EncryptMulti([]byte("hello"), AlgA256GCM, []KeyDeriver{&DirectKey{Key: aesKey}})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("err = %v, want ErrInvalidKey", err)
		}
	})
	t.Run("EncryptMulti mixed", func(t *testing.T) {
		for _, rs := range [][]KeyDeriver{
			{&DirectKey{Key: aesKey}, kw},
			{kw, &DirectKey{Key: aesKey}},
		} {
			if _, err := EncryptMulti([]byte("hello"), AlgA128GCM, rs); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("err = %v, want ErrInvalidKey", err)
			}
		}
	})
	t.Run("ComputeMACMulti nil key", func(t *testing.T) {
		msg, err := ComputeMACMulti([]byte("p"), nil, AlgHMAC256, []KeyDeriver{&DirectKey{Key: macKey}})
		if err != nil {
			t.Fatal(err)
		}
		checkDirectLayout(t, msg.Recipients)
		if err := VerifyMACMulti(msg, &DirectKey{Key: macKey}, 0); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("ComputeMACMulti different key", func(t *testing.T) {
		other := bytes.Repeat([]byte{0x0c}, 32)
		_, err := ComputeMACMulti([]byte("p"), other, AlgHMAC256, []KeyDeriver{&DirectKey{Key: macKey}})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("err = %v, want ErrInvalidKey", err)
		}
	})
	t.Run("ComputeMACMulti mixed", func(t *testing.T) {
		_, err := ComputeMACMulti([]byte("p"), macKey, AlgHMAC256, []KeyDeriver{&DirectKey{Key: macKey}, kw})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("err = %v, want ErrInvalidKey", err)
		}
	})
	t.Run("Key.KeyDeriver content alg", func(t *testing.T) {
		k := symKey(t, aesKey, AlgA128GCM, KeyOpEncrypt, KeyOpDecrypt)
		d, err := k.KeyDeriver(AlgDirect)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := EncryptMulti([]byte("hi"), AlgA128GCM, []KeyDeriver{d})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := DecryptMulti(msg, d, 0); err != nil || string(got) != "hi" {
			t.Fatalf("DecryptMulti = %q, %v", got, err)
		}
		// The key's alg binds the content algorithm.
		if _, err := EncryptMulti([]byte("hi"), AlgA256GCM, []KeyDeriver{d}); !errors.Is(err, ErrAlgorithmMismatch) {
			t.Fatalf("other content alg: err = %v, want ErrAlgorithmMismatch", err)
		}
	})
	t.Run("Key.KeyDeriver MAC ops", func(t *testing.T) {
		k := symKey(t, macKey, AlgDirect, KeyOpMACCreate, KeyOpMACVerify)
		d, err := k.KeyDeriver(AlgDirect)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := ComputeMACMulti([]byte("p"), nil, AlgHMAC256, []KeyDeriver{d})
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyMACMulti(msg, d, 0); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Key.KeyDeriver wrap ops only", func(t *testing.T) {
		k := symKey(t, aesKey, 0, KeyOpWrapKey, KeyOpUnwrapKey)
		if _, err := k.KeyDeriver(AlgDirect); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("err = %v, want ErrInvalidKey (a wrap key is not a content key)", err)
		}
	})
}

func checkDirectLayout(t *testing.T, rs []Recipient) {
	t.Helper()
	if len(rs) != 1 {
		t.Fatalf("%d recipients, want 1", len(rs))
	}
	r := rs[0]
	if !r.Protected.IsEmpty() {
		t.Fatalf("direct recipient protected bucket not empty: %v", r.Protected.params)
	}
	if r.Unprotected.Algorithm() != AlgDirect {
		t.Fatalf("direct recipient unprotected alg = %v", r.Unprotected.Algorithm())
	}
	if len(r.Ciphertext) != 0 {
		t.Fatalf("direct recipient ciphertext = %x", r.Ciphertext)
	}
}

func symKey(t *testing.T, k []byte, alg Algorithm, ops ...KeyOp) *Key {
	t.Helper()
	key := &Key{params: map[int64]any{keyLabelKty: int64(KeyTypeSymmetric), keyLabelSymK: k}}
	if alg != 0 {
		key.SetAlgorithm(alg)
	}
	if len(ops) > 0 {
		key.SetOps(ops...)
	}
	return key
}
