// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package psa

import (
	"errors"
	"math"
	"testing"

	"github.com/jahkeup/corecbor"
)

// Proposal 036 item 3: intOf uses corecbor's checked Int64 accessor.
func TestIntOfBoundaries(t *testing.T) {
	cases := []struct {
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
		{"text", corecbor.Text("1"), 0, false},
	}
	for _, tc := range cases {
		n, err := intOf(tc.v, "x")
		if tc.inRange {
			if err != nil || n != tc.want {
				t.Errorf("%s: intOf = %d, %v; want %d", tc.name, n, err, tc.want)
			}
		} else if !errors.Is(err, ErrMalformedPSA) {
			t.Errorf("%s: err = %v, want ErrMalformedPSA", tc.name, err)
		}
	}
}
