// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor"
)

// Proposal 037 S11: an ECDH-ES ephemeral key (header -1) is a public
// key; one that carries a private key (d, -4) is rejected.
func TestSpec037EphemeralKeyWithPrivate(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []Algorithm{AlgECDH_ES_HKDF_256, AlgECDH_ES_A128KW} {
		t.Run(alg.String(), func(t *testing.T) {
			msg, err := EncryptMulti([]byte("x"), AlgA128GCM, []KeyDeriver{&ECDHESKey{PeerPublic: priv.PublicKey(), Alg: alg}})
			if err != nil {
				t.Fatal(err)
			}
			recv := &ECDHESKey{PrivateKey: priv, Alg: alg}
			if _, err := DecryptMulti(msg, recv, 0); err != nil {
				t.Fatal(err)
			}
			// Replace the ephemeral key with a complete key pair.
			eph, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			k, err := NewKeyFromSigner(eph)
			if err != nil {
				t.Fatal(err)
			}
			v, err := k.toValue()
			if err != nil {
				t.Fatal(err)
			}
			r := &msg.Recipients[0]
			if _, ok := r.Unprotected.Get(headerLabelEphemeralKey).(corecbor.Value); !ok {
				t.Fatalf("ephemeral key header = %T", r.Unprotected.Get(headerLabelEphemeralKey))
			}
			r.Unprotected.Set(headerLabelEphemeralKey, v)
			if _, err := DecryptMulti(msg, recv, 0); !errors.Is(err, ErrMalformed) {
				t.Fatalf("ephemeral key with d: err = %v, want ErrMalformed", err)
			}
		})
	}
}
