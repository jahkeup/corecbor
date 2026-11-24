// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"errors"
	"testing"
)

// Proposal 037 S16: JWK conversion follows RFC 7517 §4.3 (use and
// key_ops consistent, no duplicate key_ops) and doesn't rewrite a kid
// that a JWK can't carry.
func TestSpec037JWK(t *testing.T) {
	const x = `"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"`
	for name, c := range map[string]struct {
		jwk  string
		want error
	}{
		"use sig, key_ops verify":  {`{"kty":"OKP","crv":"Ed25519",` + x + `,"use":"sig","key_ops":["verify"]}`, nil},
		"use enc, key_ops verify":  {`{"kty":"OKP","crv":"Ed25519",` + x + `,"use":"enc","key_ops":["verify"]}`, ErrInvalidKey},
		"use sig, key_ops encrypt": {`{"kty":"OKP","crv":"Ed25519",` + x + `,"use":"sig","key_ops":["encrypt"]}`, ErrInvalidKey},
		"unknown use, key_ops":     {`{"kty":"OKP","crv":"Ed25519",` + x + `,"use":"other","key_ops":["verify"]}`, ErrInvalidKey},
		"duplicate key_ops":        {`{"kty":"OKP","crv":"Ed25519",` + x + `,"key_ops":["verify","verify"]}`, ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := KeyFromJWK([]byte(c.jwk))
			if c.want == nil && err != nil {
				t.Fatalf("err = %v", err)
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}

	k, err := KeyFromJWK([]byte(`{"kty":"OKP","crv":"Ed25519",` + x + `}`))
	if err != nil {
		t.Fatal(err)
	}
	k.SetID([]byte{0xff, 0xfe})
	if _, err := k.JWK(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("JWK with non-UTF-8 kid: err = %v, want ErrInvalidKey", err)
	}
}
