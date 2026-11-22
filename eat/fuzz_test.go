// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat_test

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/eat"
)

func fuzzSeeds(f *testing.F) {
	for _, s := range []string{
		rfcA21Payload, rfcA22TEE,
		"a10a4800010203040506",                         // nonce
		"a1190100510201020304050607080910111213141516", // ueid
		"a119010702",                         // dbgstat
		"a119010a6a68747470733a2f2f78",       // submods: tstr (JSON)
		"a119010aa16161a1190107f5",           // submods: inline claims
		"a119010aa161614401020304",           // submods: nested token
		"a119010aa1616182016161",             // submods: detached digest
		"a119010ba119010aa16161a0",           // legacy submods key
		"a119010c82a20161610261623",          // legacy sw-components
		"a1190108a2011a00000001021a00000002", // location
		"d9025a8243a10a40a1616143010203",     // detached bundle
		"a0", "80", "ff", "",
	} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
}

var fuzzOptions = [][]eat.Option{nil, {eat.CompatV02()}} //nolint:staticcheck // legacy numbering is fuzzed too

// FuzzDecodeClaims: arbitrary bytes return an error or claims that
// re-encode to bytes that decode again, in both numberings; Validate
// never panics.
func FuzzDecodeClaims(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, opts := range fuzzOptions {
			c, err := eat.DecodeClaims(data, opts...)
			if err != nil {
				continue
			}
			_ = c.Validate()
			out, err := c.Encode(opts...)
			if err != nil {
				continue // a decoded value the encoder rejects (e.g. an out-of-range number)
			}
			if _, err := eat.DecodeClaims(out, opts...); err != nil {
				t.Fatalf("re-decode of %x (from %x): %v", out, data, err)
			}
		}
	})
}

// FuzzAppraise: decoded claims through an appraiser with every check
// enabled never panic, and with a SubmodPolicy set, a token, JSON or
// detached submod with no verifier is never accepted (fail closed).
func FuzzAppraise(f *testing.F) {
	fuzzSeeds(f)
	min := eat.DebugDisabled
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := eat.DecodeClaims(data)
		if err != nil {
			return
		}
		a := eat.NewAppraiser()
		a.CWTValidator = nil
		a.RequireNonce = []byte{0, 1, 2, 3, 4, 5, 6, 7}
		a.RequireSecureBoot = true
		a.MinDebugStatus = &min
		a.RequireProfile = "https://example.com"
		_ = a.AppraiseContext(context.Background(), c)

		open := eat.NewAppraiser()
		open.CWTValidator = nil
		open.ValidateValues = false
		open.SubmodPolicy = func(string, *eat.Claims) error { return nil }
		err = open.AppraiseContext(context.Background(), c)
		for _, s := range c.Submods {
			if s.Claims == nil && err == nil {
				t.Fatalf("unverifiable submod accepted: %x", data)
			}
		}
		if err != nil && !errors.Is(err, eat.ErrSubmodUnverified) && len(c.Submods) == 0 {
			t.Fatalf("permissive appraiser rejected %x: %v", data, err)
		}
	})
}

// FuzzDecodeDetachedBundle: arbitrary bytes return an error or a bundle
// with at least one detached claims set, and never panic.
func FuzzDecodeDetachedBundle(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := eat.DecodeDetachedBundle(data)
		if err != nil {
			return
		}
		if len(b.Detached) == 0 {
			t.Fatalf("bundle %x decoded with no detached claims sets", data)
		}
	})
}
