// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"errors"
	"testing"
)

// FuzzCountersign: any decoded message's countersignatures parse or are
// ErrMalformed, and verifying them (full and abbreviated) never panics.
// Seeds include the RFC 9338 Appendix A messages.
func FuzzCountersign(f *testing.F) {
	addCOSESeeds(f)
	verifiers := []*Verifier{fuzzVerifier}
	for _, v := range rfc9338Vectors(f) {
		f.Add(encodeCBOR(f, v.msg))
		vv, err := NewVerifier(v.key)
		if err != nil {
			f.Fatal(err)
		}
		verifiers = append(verifiers, vv)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var targets []CountersignTarget
		if m, err := UnmarshalSign1(data); err == nil {
			targets = append(targets, m)
		}
		if m, err := UnmarshalSign(data); err == nil {
			targets = append(targets, m)
			for i := range m.Signatures {
				targets = append(targets, &m.Signatures[i])
			}
		}
		if m, err := UnmarshalMac0(data); err == nil {
			targets = append(targets, m)
		}
		if m, err := UnmarshalMac(data); err == nil {
			targets = append(targets, m)
			for i := range m.Recipients {
				targets = append(targets, &m.Recipients[i])
			}
		}
		if m, err := UnmarshalEncrypt0(data); err == nil {
			targets = append(targets, m)
		}
		if m, err := UnmarshalEncrypt(data); err == nil {
			targets = append(targets, m)
			for i := range m.Recipients {
				targets = append(targets, &m.Recipients[i])
			}
		}
		for _, tg := range targets {
			css, err := Countersignatures(tg)
			if err != nil && !errors.Is(err, ErrMalformed) {
				t.Fatalf("Countersignatures: untyped error %v", err)
			}
			for _, v := range verifiers {
				for _, cs := range css {
					_ = v.VerifyCountersignature(tg, cs)
					_ = v.VerifyCountersignatureDetached(tg, cs, data)
				}
				_ = v.VerifyCountersignature0(tg)
				_ = v.VerifyCountersignature0Detached(tg, nil)
			}
		}
	})
}
