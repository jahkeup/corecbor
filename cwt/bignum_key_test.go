// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cwt"
)

// TestDecodeRejectsIntegerBignumKeys: a bignum claim key with an
// integer value re-encodes as that integer, so bignum 1 would come back
// as iss. Such keys are rejected as ambiguous; larger bignums are
// rejected as non-integer keys.
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

	// Larger bignums aren't integer keys either (RFC 8392 §3; 037 W15):
	// rejected, but not as ambiguous.
	b, _ := hex.DecodeString("a1c249010000000000000000" + "01") // 2^64
	_, err := cwt.DecodeClaimsSet(b)
	if !errors.Is(err, cwt.ErrMalformedClaims) || errors.Is(err, cwt.ErrAmbiguousClaimKey) {
		t.Fatalf("2^64 key: %v, want ErrMalformedClaims only", err)
	}
}

// TestAmbiguousClaimKeyError: the rejection is recognizable
// (ErrAmbiguousClaimKey, still ErrMalformedClaims) and names the key as
// it was received, leading zeros included, so callers can find it.
func TestAmbiguousClaimKeyError(t *testing.T) {
	for _, tc := range []struct{ in, key string }{
		{"a1c24101f6", "c24101"},
		{"a1c3410a01", "c3410a"},
		{"a1c243000001f6", "c243000001"},
		{"a1c24001", "c240"},
	} {
		b, _ := hex.DecodeString(tc.in)
		_, err := cwt.DecodeClaimsSet(b)
		if !errors.Is(err, cwt.ErrAmbiguousClaimKey) || !errors.Is(err, cwt.ErrMalformedClaims) {
			t.Fatalf("%s: err = %v, want ErrAmbiguousClaimKey and ErrMalformedClaims", tc.in, err)
		}
		var ce *cwt.ClaimError
		if !errors.As(err, &ce) {
			t.Fatalf("%s: err %v is not a *ClaimError", tc.in, err)
		}
		if got := hex.EncodeToString([]byte(ce.Key.Raw)); got != tc.key {
			t.Errorf("%s: ClaimError.Key.Raw = %s, want %s", tc.in, got, tc.key)
		}
	}
}
