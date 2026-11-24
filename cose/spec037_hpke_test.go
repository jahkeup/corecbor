// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
)

// Proposal 037 S18: under WithDraftHPKE27, alg 35 means HPKE-0, so the
// deprecated HPKEKey (which labels its own recipients 35) is refused
// there instead of mixing the two meanings. Without the selector it
// works as before.
func TestSpec037HPKEKeyUnderDraft27(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	send := &HPKEKey{PublicKey: priv.PublicKey()}
	recv := &HPKEKey{PrivateKey: priv}
	msg, err := EncryptMulti([]byte("x"), AlgA128GCM, []KeyDeriver{send})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptMulti(msg, recv, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptMulti([]byte("x"), AlgA128GCM, []KeyDeriver{send}, WithDraftHPKE27()); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("EncryptMulti, HPKEKey under draft-27: err = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := DecryptMulti(msg, recv, 0, WithDraftHPKE27()); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("DecryptMulti, HPKEKey under draft-27: err = %v, want ErrUnsupportedAlgorithm", err)
	}
}
