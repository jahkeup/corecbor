// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"errors"
	"testing"
)

// Proposal 037 S9: a COSE_recipient must carry alg (RFC 9052 §8.5.1,
// §8.5.2, §8.5.4, §8.5.5); one without it isn't opened as the key's
// algorithm.
func TestSpec037RecipientWithoutAlg(t *testing.T) {
	kw := &AESKWKey{Key: bytes.Repeat([]byte{0x0e}, 16)}
	enc, err := EncryptMulti([]byte("hi"), AlgA128GCM, []KeyDeriver{kw})
	if err != nil {
		t.Fatal(err)
	}
	enc.Recipients[0].Unprotected = Headers{}
	if _, err := DecryptMulti(enc, kw, 0); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("DecryptMulti, no recipient alg: err = %v, want ErrAlgorithmMismatch", err)
	}

	mac, err := ComputeMACMulti([]byte("hi"), bytes.Repeat([]byte{1}, 32), AlgHMAC256, []KeyDeriver{kw})
	if err != nil {
		t.Fatal(err)
	}
	mac.Recipients[0].Unprotected = Headers{}
	if err := VerifyMACMulti(mac, kw, 0); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("VerifyMACMulti, no recipient alg: err = %v, want ErrAlgorithmMismatch", err)
	}
}
