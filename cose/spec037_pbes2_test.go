// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"errors"
	"testing"
)

// Proposal 037 S7: PBES2 has floors on the iteration count, salt length
// and password (RFC 7518 §4.8.1, RFC 8018, NIST SP 800-132) when sealing
// and opening, and seals with a current default count.
func TestSpec037PBES2Floors(t *testing.T) {
	cek := bytes.Repeat([]byte{3}, 16)
	salt16 := bytes.Repeat([]byte{0x5a}, 16)

	t.Run("default count", func(t *testing.T) {
		_, h, err := (&PBES2Key{Password: []byte("pw"), Salt: salt16}).WrapKey(cek, KeyWrapOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if got := h.Get(headerLabelPBES2Count); got != int64(600_000) {
			t.Fatalf("default count = %v, want 600000", got)
		}
	})

	t.Run("seal floors", func(t *testing.T) {
		for name, k := range map[string]*PBES2Key{
			"count 999":      {Password: []byte("pw"), Salt: salt16, Count: 999},
			"count -1":       {Password: []byte("pw"), Salt: salt16, Count: -1},
			"salt 15":        {Password: []byte("pw"), Salt: salt16[:15], Count: 1000},
			"empty salt":     {Password: []byte("pw"), Salt: []byte{}, Count: 1000},
			"empty password": {Salt: salt16, Count: 1000},
		} {
			if _, _, err := k.WrapKey(cek, KeyWrapOpts{}); !errors.Is(err, ErrInvalidKey) {
				t.Errorf("%s: err = %v, want ErrInvalidKey", name, err)
			}
		}
		if _, _, err := (&PBES2Key{Password: []byte("pw"), Salt: salt16, Count: 1000}).WrapKey(cek, KeyWrapOpts{}); err != nil {
			t.Fatalf("count 1000, 16-byte salt: %v", err)
		}
	})

	t.Run("open floors", func(t *testing.T) {
		// Wrap below the floors by hand, as an old sender could have.
		weak := func(salt []byte, count int64, pw string) (ct []byte, h Headers) {
			k := &PBES2Key{Password: []byte(pw), Salt: salt, Count: int(count)}
			ct, h, err := k.wrap(cek, KeyWrapOpts{})
			if err != nil {
				t.Fatal(err)
			}
			return ct, h
		}
		for name, c := range map[string]struct {
			salt  []byte
			count int64
			pw    string
		}{
			"count 999":      {salt16, 999, "pw"},
			"salt 7":         {salt16[:7], 1000, "pw"},
			"empty password": {salt16, 1000, ""},
		} {
			ct, h := weak(c.salt, c.count, c.pw)
			strict := &PBES2Key{Password: []byte(c.pw)}
			if _, err := strict.UnwrapKey(ct, h, KeyUnwrapOpts{}); !errors.Is(err, ErrDecryption) {
				t.Errorf("%s: err = %v, want ErrDecryption", name, err)
			}
			lax := &PBES2Key{Password: []byte(c.pw), InsecureAllowWeakParams: true}
			got, err := lax.UnwrapKey(ct, h, KeyUnwrapOpts{})
			if err != nil || !bytes.Equal(got, cek) {
				t.Errorf("%s with InsecureAllowWeakParams: %x, %v", name, got, err)
			}
		}
		// An 8-byte salt is the RFC 7518 minimum and opens by default.
		ct, h := weak(salt16[:8], 1000, "pw")
		if _, err := (&PBES2Key{Password: []byte("pw")}).UnwrapKey(ct, h, KeyUnwrapOpts{}); err != nil {
			t.Fatalf("8-byte salt: %v", err)
		}
	})
}
