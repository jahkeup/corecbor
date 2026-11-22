// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"errors"
	"math"
	"testing"

	"github.com/jahkeup/corecbor"
)

// Proposal 036 item 3: integer claim helpers use corecbor's checked
// accessors. Boundary values must keep their v0.2.2-compatible results:
// in-range integers convert exactly; values beyond int64 never wrap.
var intBoundaries = []struct {
	name    string
	v       corecbor.Value
	want    int64
	inRange bool
}{
	{"MaxInt64", corecbor.Uint(math.MaxInt64), math.MaxInt64, true},
	{"MaxInt64+1", corecbor.Uint(math.MaxInt64 + 1), 0, false},
	{"MinInt64", corecbor.NegInt(math.MaxInt64), math.MinInt64, true},
	{"MinInt64-1", corecbor.NegInt(math.MaxInt64 + 1), 0, false},
	{"MaxUint64", corecbor.Uint(math.MaxUint64), 0, false},
}

func TestClaimKeyOfBoundaries(t *testing.T) {
	for _, tc := range intBoundaries {
		k := claimKeyOf(tc.v)
		if tc.inRange {
			if k.Raw != "" || k.IsText || k.Int != tc.want {
				t.Errorf("%s: claimKeyOf = %+v, want IntKey(%d)", tc.name, k, tc.want)
			}
		} else if k.Raw == "" {
			t.Errorf("%s: claimKeyOf = %+v, want a Raw key (no wrap)", tc.name, k)
		}
	}
}

func TestFromValueBoundaries(t *testing.T) {
	for _, tc := range intBoundaries {
		got := fromValue(tc.v)
		if tc.inRange {
			if n, ok := got.(int64); !ok || n != tc.want {
				t.Errorf("%s: fromValue = %#v, want int64(%d)", tc.name, got, tc.want)
			}
		} else if _, ok := got.(corecbor.Value); !ok {
			t.Errorf("%s: fromValue = %#v, want the corecbor.Value unchanged", tc.name, got)
		}
	}
}

func TestNumericDateBoundaries(t *testing.T) {
	for _, tc := range intBoundaries {
		got, err := ParseNumericDate(tc.v)
		if tc.inRange {
			if err != nil || got.Unix() != tc.want {
				t.Errorf("%s: ParseNumericDate = %v, %v; want unix %d", tc.name, got, err, tc.want)
			}
		} else if !errors.Is(err, ErrMalformedClaims) || !errors.Is(err, corecbor.ErrTimeRange) {
			t.Errorf("%s: err = %v, want ErrMalformedClaims and ErrTimeRange", tc.name, err)
		}
	}
}

func TestExiBoundaries(t *testing.T) {
	for _, v := range []uint64{0, math.MaxInt64, math.MaxInt64 + 1, math.MaxUint64} {
		data, err := corecbor.New(corecbor.ModeCoreDeterministic).Encode(nil,
			corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Uint(uint64(ClaimExi)), Value: corecbor.Uint(v)}))
		if err != nil {
			t.Fatal(err)
		}
		cs, err := DecodeClaimsSet(data)
		if err != nil {
			t.Fatalf("exi %d: %v", v, err)
		}
		if cs.Exi == nil || *cs.Exi != v {
			t.Errorf("exi %d: decoded %v", v, cs.Exi)
		}
	}
	// A negative exi is not an ACE exi value; it stays an unmodeled claim.
	data, _ := corecbor.New(corecbor.ModeCoreDeterministic).Encode(nil,
		corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Uint(uint64(ClaimExi)), Value: corecbor.NegInt(0)}))
	cs, err := DecodeClaimsSet(data)
	if err != nil || cs.Exi != nil {
		t.Errorf("negative exi: Exi = %v, err = %v; want nil, nil", cs.Exi, err)
	}
}
