// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"fmt"
	"math"
	"time"
)

// RFC 9581 time map keys (§3, Time Tag Map Keys registry).
const (
	etimeKeyBase        = 1   // base time, as tag 1 content (int or float)
	etimeKeyDecimal     = 4   // base time as decimal fraction (unsupported here)
	etimeKeyBigfloat    = 5   // base time as bigfloat (unsupported here)
	etimeKeyTimescale   = 13  // critical timescale
	etimeKeyTimescaleE  = -1  // elective timescale
	etimeKeyTimescaleE2 = -13 // elective timescale (same meaning as -1)
)

// etimeFractions maps the RFC 9581 §3.3 decimal fraction keys this
// package models to their scale in nanoseconds. Keys -12, -15 and -18
// (pico/femto/atto) are finer than time.Time and are rejected.
var etimeFractions = map[int64]int64{-3: 1e6, -6: 1e3, -9: 1}

// ExtendedTime is the decoded form of RFC 9581 tag 1001: a time in UTC
// (the default timescale) plus every map entry this package doesn't
// interpret, so the value round-trips. Extra holds elective keys such
// as clock quality (-2, -4, -5, -7, -8), the time-zone hint (-10/10)
// and IXDTF suffix information (-11/11), and an explicit UTC
// timescale.
type ExtendedTime struct {
	Time  time.Time
	Extra []MapEntry
}

// fractionKey picks the coarsest decimal fraction key that represents
// ns exactly.
func fractionKey(ns int64) (int64, int64) {
	switch {
	case ns%1e6 == 0:
		return -3, ns / 1e6
	case ns%1e3 == 0:
		return -6, ns / 1e3
	default:
		return -9, ns
	}
}

// etimeEntries returns key 1 (integer seconds) and, when needed, the
// coarsest exact decimal fraction key for the sub-second part.
func etimeEntries(sec, ns int64) []MapEntry {
	out := []MapEntry{{Key: intValue(etimeKeyBase), Value: intValue(sec)}}
	if ns != 0 {
		k, v := fractionKey(ns)
		out = append(out, MapEntry{Key: intValue(k), Value: Uint(uint64(v))})
	}
	return out
}

// ExtendedTimeTo returns Tag(1001, map) with key 1 holding integer
// seconds since the epoch, a decimal fraction key (-3, -6 or -9) when
// et.Time has sub-second precision, and et.Extra. Extra entries whose
// keys collide with keys 1, 4, 5 or the fraction keys are dropped,
// since the time itself is authoritative.
func ExtendedTimeTo(et ExtendedTime) Value {
	entries := etimeEntries(et.Time.Unix(), int64(et.Time.Nanosecond()))
	for _, e := range et.Extra {
		if k, ok := intOf(e.Key); ok && (k == etimeKeyBase || k == etimeKeyDecimal || k == etimeKeyBigfloat || isFractionKey(k)) {
			continue
		}
		entries = append(entries, e)
	}
	return MakeTag(TagExtendedTime, MakeMapFromSlice(entries))
}

func isFractionKey(k int64) bool {
	switch k {
	case -3, -6, -9, -12, -15, -18:
		return true
	}
	return false
}

// etimeParts is the interpreted content of a tag 1001/1002 map.
type etimeParts struct {
	sec, ns int64
	isFloat bool
	f       float64
	extra   []MapEntry
}

// parseEtime applies RFC 9581 §3 to a tag 1001/1002 map: exactly one
// base-time key, at most one decimal fraction (only with an integer
// key 1), timescale 0 (UTC) only, unknown unsigned keys are an error
// (critical), and other negative-integer and text keys are kept.
func parseEtime(m Value, id uint64) (etimeParts, error) {
	var p etimeParts
	if m.Kind != KindMap {
		return p, fmt.Errorf("%w: tag %d content must be a map", ErrMalformedTag, id)
	}
	haveBase, haveFrac := false, false
	var fracKey, fracVal int64
	for _, e := range m.Map() {
		k, isInt := intOf(e.Key)
		switch {
		case !isInt && e.Key.Kind == KindText:
			p.extra = append(p.extra, e)
		case !isInt:
			return p, fmt.Errorf("%w: tag %d map key must be an integer or text", ErrMalformedTag, id)
		case k == etimeKeyBase:
			if haveBase {
				return p, fmt.Errorf("%w: tag %d has more than one base time", ErrMalformedTag, id)
			}
			haveBase = true
			if n, ok := intOf(e.Value); ok {
				p.sec = n
			} else if e.Value.Kind == KindFloat64 || e.Value.Kind == KindFloat32 {
				p.isFloat = true
				p.f = e.Value.Float64Val()
				if e.Value.Kind == KindFloat32 {
					p.f = float64(e.Value.Float32Val())
				}
			} else if e.Value.Kind == KindUint || e.Value.Kind == KindNegInt {
				return p, fmt.Errorf("%w: tag %d base time out of range", ErrTimeRange, id)
			} else {
				return p, fmt.Errorf("%w: tag %d key 1 must be an integer or float", ErrMalformedTag, id)
			}
		case k == etimeKeyDecimal || k == etimeKeyBigfloat:
			return p, fmt.Errorf("%w: tag %d decimal-fraction and bigfloat base times (keys 4, 5) are not supported", ErrMalformedTag, id)
		case isFractionKey(k):
			if haveFrac {
				return p, fmt.Errorf("%w: tag %d has more than one decimal fraction key", ErrMalformedTag, id)
			}
			haveFrac = true
			scale, supported := etimeFractions[k]
			if !supported {
				return p, fmt.Errorf("%w: tag %d fraction key %d is finer than nanoseconds", ErrMalformedTag, id, k)
			}
			if e.Value.Kind != KindUint || e.Value.UintVal() > math.MaxInt64/uint64(scale) {
				return p, fmt.Errorf("%w: tag %d fraction key %d must be a uint", ErrMalformedTag, id, k)
			}
			fracKey, fracVal = k, int64(e.Value.UintVal())*scale
		case k == etimeKeyTimescale || k == etimeKeyTimescaleE || k == etimeKeyTimescaleE2:
			if ts, ok := intOf(e.Value); !ok || ts != 0 {
				return p, fmt.Errorf("%w: tag %d timescale other than UTC (0) is not supported", ErrMalformedTag, id)
			}
			p.extra = append(p.extra, e)
		case k >= 0:
			return p, fmt.Errorf("%w: tag %d unsupported critical or base-time key %d", ErrMalformedTag, id, k)
		default:
			p.extra = append(p.extra, e)
		}
	}
	if !haveBase {
		return p, fmt.Errorf("%w: tag %d has no supported base time (key 1)", ErrMalformedTag, id)
	}
	if haveFrac {
		if p.isFloat {
			return p, fmt.Errorf("%w: tag %d fraction key %d requires an integer key 1", ErrMalformedTag, id, fracKey)
		}
		p.ns = fracVal
	}
	return p, nil
}

// AsExtendedTime decodes RFC 9581 tag 1001. It supports base time key 1
// (integer or float seconds) with an optional -3/-6/-9 decimal
// fraction, and the UTC timescale. Decimal-fraction and bigfloat base
// times (keys 4, 5), fractions finer than nanoseconds, other
// timescales and unknown unsigned (critical) keys return an error
// wrapping ErrMalformedTag; other keys are returned in Extra.
func AsExtendedTime(t Value) (ExtendedTime, error) {
	inner, id, err := expectTag(t, "extended time", TagExtendedTime)
	if err != nil {
		return ExtendedTime{}, err
	}
	p, err := parseEtime(inner, id)
	if err != nil {
		return ExtendedTime{}, err
	}
	if p.isFloat {
		tm, err := floatEpoch(p.f)
		if err != nil {
			return ExtendedTime{}, err
		}
		return ExtendedTime{Time: tm, Extra: p.extra}, nil
	}
	// Normalize nanoseconds of a fraction >= 1s into the seconds.
	extraSec := p.ns / 1e9
	if (extraSec > 0 && p.sec > math.MaxInt64-extraSec) || (extraSec < 0 && p.sec < math.MinInt64-extraSec) {
		return ExtendedTime{}, fmt.Errorf("%w: tag 1001 time out of range", ErrTimeRange)
	}
	return ExtendedTime{Time: time.Unix(p.sec+extraSec, p.ns%1e9).UTC(), Extra: p.extra}, nil
}

// DurationTo returns RFC 9581 tag 1002: key 1 holds whole seconds
// (rounded toward negative infinity, so the unsigned decimal fraction
// added to it is non-negative), plus a -3/-6/-9 fraction when needed.
func DurationTo(d time.Duration) Value {
	sec := int64(d / time.Second)
	ns := int64(d % time.Second)
	if ns < 0 {
		sec--
		ns += 1e9
	}
	return MakeTag(TagDuration, MakeMapFromSlice(etimeEntries(sec, ns)))
}

// AsDuration decodes RFC 9581 tag 1002 with the same key rules as
// AsExtendedTime; elective keys are ignored. A duration outside
// time.Duration's range returns an error wrapping ErrTimeRange.
func AsDuration(t Value) (time.Duration, error) {
	inner, id, err := expectTag(t, "duration", TagDuration)
	if err != nil {
		return 0, err
	}
	p, err := parseEtime(inner, id)
	if err != nil {
		return 0, err
	}
	if p.isFloat {
		ns := p.f * 1e9
		if math.IsNaN(ns) || ns < math.MinInt64 || ns >= math.MaxInt64 {
			return 0, fmt.Errorf("%w: tag 1002 duration %g s out of range", ErrTimeRange, p.f)
		}
		return time.Duration(ns), nil
	}
	const nsPerSec int64 = 1e9
	if p.sec > math.MaxInt64/nsPerSec || p.sec < math.MinInt64/nsPerSec {
		return 0, fmt.Errorf("%w: tag 1002 duration %d s out of range", ErrTimeRange, p.sec)
	}
	total := p.sec * 1e9
	if total > math.MaxInt64-p.ns {
		return 0, fmt.Errorf("%w: tag 1002 duration out of range", ErrTimeRange)
	}
	return time.Duration(total + p.ns), nil
}
