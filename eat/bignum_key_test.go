// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/eat"
)

// TestDecodeRejectsIntegerBignumKeys: a bignum claim key with an
// integer value would re-encode as that integer claim (bignum 10 as
// nonce), so it is rejected, including inside submodules.
func TestDecodeRejectsIntegerBignumKeys(t *testing.T) {
	for name, h := range map[string]string{
		"bignum 10 (nonce)": "a1c2410a3830",
		"negative bignum":   "a1c3410a01",
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := hex.DecodeString(h)
			for _, opts := range [][]eat.Option{nil, {eat.CompatV02()}} { //nolint:staticcheck // legacy numbering too
				if _, err := eat.DecodeClaims(b, opts...); !errors.Is(err, eat.ErrMalformedEAT) {
					t.Fatalf("DecodeClaims(%s) err = %v, want ErrMalformedEAT", h, err)
				}
			}
		})
	}

	// Submods {"a": {bignum 10: 1}}: 266 in RFC numbering, 268 in v0.2's.
	sub := func(key string) []byte {
		b, _ := hex.DecodeString("a1" + key + "a1" + "6161" + "a1c2410a01")
		return b
	}
	if _, err := eat.DecodeClaims(sub("19010a")); !errors.Is(err, eat.ErrMalformedEAT) {
		t.Errorf("submodule (RFC numbering) err = %v, want ErrMalformedEAT", err)
	}
	if _, err := eat.DecodeClaims(sub("19010c"), eat.CompatV02()); !errors.Is(err, eat.ErrMalformedEAT) { //nolint:staticcheck // legacy numbering
		t.Errorf("submodule (v0.2 numbering) err = %v, want ErrMalformedEAT", err)
	}
	// Control: the same submodule with a plain key decodes.
	ok, _ := hex.DecodeString("a1" + "19010a" + "a1" + "6161" + "a1" + "3a" + "00010000" + "01")
	if _, err := eat.DecodeClaims(ok); err != nil {
		t.Errorf("control submodule: %v", err)
	}
}
