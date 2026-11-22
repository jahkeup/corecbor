// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

import (
	"errors"
	"math"
	"testing"

	"github.com/jahkeup/corecbor"
)

// Proposal 036 item 3: eat's integer helpers use corecbor's checked
// accessors. In-range integers convert exactly; values beyond int64
// never wrap onto other keys or values.
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

func TestIntKeyBoundaries(t *testing.T) {
	for _, tc := range intBoundaries {
		n, ok := intKey(tc.v)
		if ok != tc.inRange || (ok && n != tc.want) {
			t.Errorf("%s: intKey = %d, %v; want %d, %v", tc.name, n, ok, tc.want, tc.inRange)
		}
	}
	if _, ok := intKey(corecbor.Text("1")); ok {
		t.Error("intKey(text) reported an integer")
	}
}

func TestParseIntClaimBoundaries(t *testing.T) {
	for _, tc := range intBoundaries {
		n, err := parseIntClaim(tc.v)
		if tc.inRange {
			if err != nil || n != tc.want {
				t.Errorf("%s: parseIntClaim = %d, %v; want %d", tc.name, n, err, tc.want)
			}
		} else if !errors.Is(err, ErrMalformedEAT) {
			t.Errorf("%s: err = %v, want ErrMalformedEAT", tc.name, err)
		}
	}
}

func TestParseUintClaimBoundaries(t *testing.T) {
	for _, v := range []uint64{0, math.MaxInt64, math.MaxInt64 + 1, math.MaxUint64} {
		if n, err := parseUintClaim(corecbor.Uint(v)); err != nil || n != v {
			t.Errorf("parseUintClaim(%d) = %d, %v", v, n, err)
		}
	}
	for _, v := range []corecbor.Value{corecbor.NegInt(0), corecbor.NegInt(math.MaxUint64), corecbor.Text("1")} {
		if _, err := parseUintClaim(v); !errors.Is(err, ErrMalformedEAT) {
			t.Errorf("parseUintClaim(%v) err = %v, want ErrMalformedEAT", v, err)
		}
	}
}
