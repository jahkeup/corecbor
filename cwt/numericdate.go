// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"fmt"
	"math"
	"time"

	"github.com/jahkeup/corecbor"
)

// NumericDate is the RFC 8392 §2 NumericDate: seconds since the epoch
// as an integer or a floating-point number, untagged.
type NumericDate struct{ time.Time }

// MarshalCBORValue returns the NumericDate encoding of d: an integer
// when d has no sub-second part, otherwise a float64.
func (d NumericDate) MarshalCBORValue() corecbor.Value { return numericDate(d.Time) }

// ParseNumericDate decodes a NumericDate. Integers outside the int64
// range and non-finite or out-of-range floats return an error wrapping
// ErrMalformedClaims and corecbor.ErrTimeRange; v0.2.2 wrapped them
// into unrelated times (an nbf beyond the int64 range became a past
// time and passed validation).
func ParseNumericDate(v corecbor.Value) (NumericDate, error) {
	t, err := parseNumericDate(v)
	return NumericDate{t}, err
}

func numericDate(t time.Time) corecbor.Value {
	sec := t.Unix()
	nsec := t.Nanosecond()
	if nsec == 0 {
		return intValue(sec)
	}
	return corecbor.Float64(float64(sec) + float64(nsec)/1e9)
}

func parseNumericDate(v corecbor.Value) (time.Time, error) {
	switch v.Kind {
	case corecbor.KindUint, corecbor.KindNegInt:
		n, err := v.Int64()
		if err != nil {
			if v.Kind == corecbor.KindUint {
				return time.Time{}, fmt.Errorf("%w: %w: %d", ErrMalformedClaims, corecbor.ErrTimeRange, v.UintVal())
			}
			return time.Time{}, fmt.Errorf("%w: %w: -1-%d", ErrMalformedClaims, corecbor.ErrTimeRange, v.NegIntVal())
		}
		return time.Unix(n, 0), nil
	case corecbor.KindFloat64:
		return floatDate(v.Float64Val())
	case corecbor.KindFloat32:
		return floatDate(float64(v.Float32Val()))
	default:
		return time.Time{}, fmt.Errorf("%w: expected numeric, got kind %d", ErrMalformedClaims, v.Kind)
	}
}

func floatDate(f float64) (time.Time, error) {
	// -2^63 is exactly representable; 2^63 is not a valid int64.
	if math.IsNaN(f) || f < math.MinInt64 || f >= math.MaxInt64 {
		return time.Time{}, fmt.Errorf("%w: %w: %g", ErrMalformedClaims, corecbor.ErrTimeRange, f)
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), nil
}
