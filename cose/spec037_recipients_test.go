// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"errors"
	"testing"
)

// Proposal 037 S2: an AE key-wrap recipient (AES-KW, PBES2) has an
// empty protected bucket and alg in the unprotected bucket (RFC 9052
// §8.5.2), and one that isn't is rejected on open (§5.4) unless the
// caller allows it.
func TestSpec037KeyWrapRecipientLayout(t *testing.T) {
	kw := &AESKWKey{Key: bytes.Repeat([]byte{0x0e}, 16)}
	pb := &PBES2Key{Password: []byte("pw"), Count: 1000}
	macKey := bytes.Repeat([]byte{0x0b}, 32)

	for name, d := range map[string]KeyDeriver{"AES-KW": kw, "PBES2": pb} {
		t.Run(name, func(t *testing.T) {
			enc, err := EncryptMulti([]byte("hi"), AlgA128GCM, []KeyDeriver{d})
			if err != nil {
				t.Fatal(err)
			}
			mac, err := ComputeMACMulti([]byte("hi"), macKey, AlgHMAC256, []KeyDeriver{d})
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range []Recipient{enc.Recipients[0], mac.Recipients[0]} {
				if !r.Protected.IsEmpty() {
					t.Fatalf("protected bucket = %v, want empty", r.Protected.params)
				}
				if r.Unprotected.Algorithm() != d.Algorithm() {
					t.Fatalf("unprotected alg = %v, want %v", r.Unprotected.Algorithm(), d.Algorithm())
				}
			}
			if _, err := DecryptMulti(enc, d, 0); err != nil {
				t.Fatal(err)
			}
			if err := VerifyMACMulti(mac, d, 0); err != nil {
				t.Fatal(err)
			}

			// The v0.2 layout: alg in the protected bucket.
			old := moveAlgToProtected(t, enc)
			if _, err := DecryptMulti(old, d, 0); !errors.Is(err, ErrMalformed) {
				t.Fatalf("protected alg: err = %v, want ErrMalformed", err)
			}
			if got, err := DecryptMulti(old, d, 0, AllowProtectedRecipientHeaders()); err != nil || string(got) != "hi" {
				t.Fatalf("protected alg, allowed: %q, %v", got, err)
			}
			oldMac := &Mac{
				Protected: mac.Protected, Unprotected: mac.Unprotected, Payload: mac.Payload, Tag: mac.Tag,
				Recipients: moveAlgToProtected(t, &Encrypt{Recipients: mac.Recipients}).Recipients,
			}
			if err := VerifyMACMulti(oldMac, d, 0); !errors.Is(err, ErrMalformed) {
				t.Fatalf("MAC protected alg: err = %v, want ErrMalformed", err)
			}
			if err := VerifyMACMulti(oldMac, d, 0, AllowMACProtectedRecipientHeaders()); err != nil {
				t.Fatalf("MAC protected alg, allowed: %v", err)
			}
		})
	}

	// Direct recipients follow the same rule (§8.5.1).
	dk := &DirectKey{Key: bytes.Repeat([]byte{0x0d}, 16)}
	enc, err := EncryptMulti([]byte("hi"), AlgA128GCM, []KeyDeriver{dk})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptMulti(moveAlgToProtected(t, enc), dk, 0); !errors.Is(err, ErrMalformed) {
		t.Fatalf("direct, protected alg: err = %v, want ErrMalformed", err)
	}
}

// moveAlgToProtected returns a copy of msg whose recipients carry alg in
// the protected bucket, as v0.2 wrote them.
func moveAlgToProtected(t *testing.T, msg *Encrypt) *Encrypt {
	t.Helper()
	out := *msg
	out.Recipients = make([]Recipient, len(msg.Recipients))
	for i, r := range msg.Recipients {
		var p, u Headers
		p.SetAlgorithm(r.Unprotected.Algorithm())
		for k, v := range r.Unprotected.params {
			if k != headerLabelAlgorithm {
				u.Set(k, v)
			}
		}
		out.Recipients[i] = Recipient{Protected: p, Unprotected: u, Ciphertext: r.Ciphertext}
	}
	return &out
}
