// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// Tests for the proposal 037 edhoc findings (E1–E20), each written to
// fail against the behavior the review recorded.

// E3: after Signature_or_MAC_2 fails to verify, the Initiator exposes
// neither the Responder's credential nor EAD_2.
func TestE3_NoPeerValuesAfterFailedMessage2(t *testing.T) {
	ini, res := pair(t, []byte{1}, []byte{2}, func(_ *InitiatorConfig, rc *ResponderConfig) {
		rc.EAD2 = []EADItem{{Label: 5, Value: []byte("x")}}
	})
	m1, _ := ini.CreateMessage1()
	m2, err := res.ProcessMessage1(m1)
	if err != nil {
		t.Fatal(err)
	}
	// PLAINTEXT_2 ends with Signature_or_MAC_2 then EAD_2 (05 41 78); flip
	// the signature's last byte so the credential resolves but the
	// signature fails.
	bad := bytes.Clone(m2)
	bad[len(bad)-4] ^= 1
	if _, err := ini.ProcessMessage2(bad); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered signature: %v", err)
	}
	if c := ini.PeerCredential(); c != nil {
		t.Errorf("PeerCredential after failed verification = %+v, want nil", c)
	}
	if e := ini.PeerEAD(); e != nil {
		t.Errorf("PeerEAD after failed verification = %+v, want nil", e)
	}
}

// E3: after Signature_or_MAC_3 fails to verify, the Responder exposes
// neither the Initiator's credential nor EAD_3 (nor EAD_1).
func TestE3_NoPeerValuesAfterFailedMessage3(t *testing.T) {
	_, other := edPair(t)
	ini, res := pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, rc *ResponderConfig) {
		ic.EAD1 = []EADItem{{Label: 4}}
		ic.EAD3 = []EADItem{{Label: 6, Value: []byte("y")}}
		// The resolver accepts the CCS but binds it to another key, so
		// the credential resolves and the signature check fails.
		rc.Peers = resolverFunc(func(_ context.Context, id IDCred) (*Credential, error) {
			return &Credential{Raw: id.KCCS, IDCred: id, PublicKey: other}, nil
		})
	})
	m1, _ := ini.CreateMessage1()
	m2, err := res.ProcessMessage1(m1)
	if err != nil {
		t.Fatal(err)
	}
	m3, err := ini.ProcessMessage2(m2)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.ProcessMessage3(m3); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key: %v", err)
	}
	if c := res.PeerCredential(); c != nil {
		t.Errorf("PeerCredential after failed verification = %+v, want nil", c)
	}
	if e := res.PeerEAD(); e != nil {
		t.Errorf("PeerEAD after failed verification = %+v, want nil", e)
	}
}
