// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cwt"
)

// TestDecodeRejectsIntegerBignumKeys: a bignum claim key with an
// integer value re-encodes as that integer, so bignum 1 would come back
// as iss. Such keys are rejected; larger bignums stay distinct and
// round-trip.
func TestDecodeRejectsIntegerBignumKeys(t *testing.T) {
	for name, h := range map[string]string{
		"bignum 1 (iss)":      "a1c24101f6",
		"bignum 10":           "a1c2410a3830",
		"negative bignum -11": "a1c3410a01",
		"leading zeros":       "a1c2490000000000000000" + "01" + "f6",
		"max uint64":          "a1c248ffffffffffffffff01",
		"empty bignum (zero)": "a1c24001",
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := hex.DecodeString(h)
			if _, err := cwt.DecodeClaimsSet(b); !errors.Is(err, cwt.ErrMalformedClaims) {
				t.Fatalf("DecodeClaimsSet(%s) err = %v, want ErrMalformedClaims", h, err)
			}
		})
	}

	b, _ := hex.DecodeString("a1c249010000000000000000" + "01") // 2^64
	cs, err := cwt.DecodeClaimsSet(b)
	if err != nil {
		t.Fatalf("2^64 key: %v", err)
	}
	out, err := cs.Encode()
	if err != nil || !bytes.Equal(out, b) {
		t.Fatalf("Encode = %x, %v; want %x", out, err, b)
	}
}
