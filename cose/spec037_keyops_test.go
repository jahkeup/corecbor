// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"errors"
	"testing"
)

// Proposal 037 S12: (*Key).KeyDeriver honors the direction of key_ops:
// an AES-KW key wraps only with wrapKey and unwraps only with unwrapKey
// (RFC 9053 §6.2.1), and encrypt/decrypt alone don't make it a KEK.
func TestSpec037KeyDeriverDirection(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, 16)
	full, err := symKey(t, raw, 0, KeyOpWrapKey, KeyOpUnwrapKey).KeyDeriver(AlgA128KW)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := EncryptMulti([]byte("x"), AlgA128GCM, []KeyDeriver{full})
	if err != nil {
		t.Fatal(err)
	}

	wrapOnly, err := symKey(t, raw, 0, KeyOpWrapKey).KeyDeriver(AlgA128KW)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptMulti([]byte("x"), AlgA128GCM, []KeyDeriver{wrapOnly}); err != nil {
		t.Fatalf("wrapKey-only key wrapping: %v", err)
	}
	if _, err := DecryptMulti(msg, wrapOnly, 0); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("wrapKey-only key unwrapping: err = %v, want ErrInvalidKey", err)
	}

	unwrapOnly, err := symKey(t, raw, 0, KeyOpUnwrapKey).KeyDeriver(AlgA128KW)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptMulti([]byte("x"), AlgA128GCM, []KeyDeriver{unwrapOnly}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("unwrapKey-only key wrapping: err = %v, want ErrInvalidKey", err)
	}
	if _, err := DecryptMulti(msg, unwrapOnly, 0); err != nil {
		t.Fatalf("unwrapKey-only key unwrapping: %v", err)
	}

	if _, err := symKey(t, raw, 0, KeyOpEncrypt, KeyOpDecrypt).KeyDeriver(AlgA128KW); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("encrypt/decrypt key as AES-KW: err = %v, want ErrInvalidKey", err)
	}

	// Direct: encrypt seals, decrypt opens.
	encOnly, err := symKey(t, raw, 0, KeyOpEncrypt).KeyDeriver(AlgDirect)
	if err != nil {
		t.Fatal(err)
	}
	dm, err := EncryptMulti([]byte("x"), AlgA128GCM, []KeyDeriver{encOnly})
	if err != nil {
		t.Fatalf("encrypt-only direct key sealing: %v", err)
	}
	if _, err := DecryptMulti(dm, encOnly, 0); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("encrypt-only direct key opening: err = %v, want ErrInvalidKey", err)
	}
}
