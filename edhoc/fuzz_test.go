// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// fuzzParties returns fixed-key method 0 suite 0 configurations, so each
// fuzz iteration is cheap and deterministic.
func fuzzParties() (InitiatorConfig, ResponderConfig) {
	iPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	rPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	ic := InitiatorConfig{Suites: []CipherSuite{Suite0}, PrivateKey: iPriv, PeerPublic: rPriv.Public(), ConnectionID: []byte{1}}
	rc := ResponderConfig{Suites: []CipherSuite{Suite0}, PrivateKey: rPriv, PeerPublic: iPriv.Public(), ConnectionID: []byte{2}}
	return ic, rc
}

// fuzzMessages runs one genuine handshake and returns its messages.
func fuzzMessages(f *testing.F) (m1, m2, m3, m4 []byte) {
	ic, rc := fuzzParties()
	ini, _ := NewInitiator(ic)
	res, _ := NewResponder(rc)
	var err error
	if m1, err = ini.CreateMessage1(); err != nil {
		f.Fatal(err)
	}
	if m2, err = res.ProcessMessage1(m1); err != nil {
		f.Fatal(err)
	}
	if m3, err = ini.ProcessMessage2(m2); err != nil {
		f.Fatal(err)
	}
	if err = res.ProcessMessage3(m3); err != nil {
		f.Fatal(err)
	}
	if m4, err = res.CreateMessage4(); err != nil {
		f.Fatal(err)
	}
	return m1, m2, m3, m4
}

func addSeeds(f *testing.F, seeds ...[]byte) {
	for _, s := range seeds {
		f.Add(s)
	}
	f.Add([]byte{})
	f.Add([]byte{0x02, 0x02})                // error message, ERR_CODE 2
	f.Add([]byte{0x01, 0x63, 'b', 'a', 'd'}) // error message, ERR_CODE 1
	f.Add([]byte{0x58, 0x20})                // truncated bstr
	f.Add(bytes.Repeat([]byte{0x9f}, 64))    // nested indefinite arrays
}

func FuzzProcessMessage1NeverPanic(f *testing.F) {
	m1, _, _, _ := fuzzMessages(f)
	addSeeds(f, m1, []byte{0x03, 0x82, 0x06, 0x02, 0x58, 0x20})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, rc := fuzzParties()
		res, _ := NewResponder(rc)
		_, _ = res.ProcessMessage1(data)
	})
}

func FuzzProcessMessage2NeverPanic(f *testing.F) {
	_, m2, _, _ := fuzzMessages(f)
	addSeeds(f, m2)
	f.Fuzz(func(t *testing.T, data []byte) {
		ic, _ := fuzzParties()
		ini, _ := NewInitiator(ic)
		if _, err := ini.CreateMessage1(); err != nil {
			t.Fatal(err)
		}
		_, _ = ini.ProcessMessage2(data)
	})
}

func FuzzProcessMessage3NeverPanic(f *testing.F) {
	m1, _, m3, _ := fuzzMessages(f)
	addSeeds(f, m3)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, rc := fuzzParties()
		res, _ := NewResponder(rc)
		if _, err := res.ProcessMessage1(m1); err != nil {
			t.Fatal(err)
		}
		_ = res.ProcessMessage3(data)
	})
}

func FuzzProcessMessage4NeverPanic(f *testing.F) {
	_, _, _, m4 := fuzzMessages(f)
	addSeeds(f, m4)
	f.Fuzz(func(t *testing.T, data []byte) {
		ic, rc := fuzzParties()
		ini, _ := NewInitiator(ic)
		res, _ := NewResponder(rc)
		m1, _ := ini.CreateMessage1()
		m2, err := res.ProcessMessage1(m1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ini.ProcessMessage2(m2); err != nil {
			t.Fatal(err)
		}
		_ = ini.ProcessMessage4(data)
	})
}
