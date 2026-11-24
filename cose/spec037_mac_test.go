// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"errors"
	"testing"
)

// Proposal 037 S6: an HMAC key shorter than the hash output is rejected
// by default (RFC 9053 §3.1); InsecureAllowShortMACKeys accepts it.
func TestSpec037MACKeyLength(t *testing.T) {
	for _, c := range []struct {
		alg Algorithm
		min int
	}{
		{AlgHMAC256_64, 32},
		{AlgHMAC256, 32},
		{AlgHMAC384, 48},
		{AlgHMAC512, 64},
	} {
		t.Run(c.alg.String(), func(t *testing.T) {
			short := bytes.Repeat([]byte{1}, c.min-1)
			ok := bytes.Repeat([]byte{1}, c.min)
			if _, err := ComputeMAC0([]byte("p"), short, c.alg); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("ComputeMAC0 short key: err = %v, want ErrInvalidKey", err)
			}
			msg, err := ComputeMAC0([]byte("p"), short, c.alg, InsecureAllowShortMACKeys())
			if err != nil {
				t.Fatalf("ComputeMAC0 short key, opt-in: %v", err)
			}
			opts := []MACOption{WithMACAlgorithms(c.alg)}
			if err := VerifyMAC0(msg, short, c.alg, opts...); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("VerifyMAC0 short key: err = %v, want ErrInvalidKey", err)
			}
			if err := VerifyMAC0(msg, short, c.alg, append(opts, InsecureAllowShortMACKeys())...); err != nil {
				t.Fatalf("VerifyMAC0 short key, opt-in: %v", err)
			}
			if _, err := ComputeMAC0([]byte("p"), ok, c.alg); err != nil {
				t.Fatalf("ComputeMAC0 %d-byte key: %v", c.min, err)
			}
			// An empty key stays invalid even with the opt-in.
			if _, err := ComputeMAC0([]byte("p"), nil, c.alg, InsecureAllowShortMACKeys()); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("empty key, opt-in: err = %v, want ErrInvalidKey", err)
			}
		})
	}

	short := bytes.Repeat([]byte{1}, 16)
	kw := &AESKWKey{Key: bytes.Repeat([]byte{2}, 16)}
	if _, err := ComputeMACMulti([]byte("p"), short, AlgHMAC256, []KeyDeriver{kw}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("ComputeMACMulti short key: err = %v, want ErrInvalidKey", err)
	}
	m, err := ComputeMACMulti([]byte("p"), short, AlgHMAC256, []KeyDeriver{kw}, InsecureAllowShortMACKeys())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMACMulti(m, kw, 0); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("VerifyMACMulti short unwrapped key: err = %v, want ErrInvalidKey", err)
	}
	if err := VerifyMACMulti(m, kw, 0, InsecureAllowShortMACKeys()); err != nil {
		t.Fatalf("VerifyMACMulti short unwrapped key, opt-in: %v", err)
	}
}
