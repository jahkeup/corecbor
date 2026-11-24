// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"fmt"
	"math"
	"math/big"
	"time"
)

const (
	TagDateTimeString uint64 = 0
	TagEpochDateTime  uint64 = 1
	TagUnsignedBignum uint64 = 2
	TagNegativeBignum uint64 = 3
	TagEncodedCBOR    uint64 = 24
	TagURI            uint64 = 32
	TagSelfDescribe   uint64 = 55799

	// Non-UTF-8 text in a byte string (IANA): CESU-8, WTF-8, MUTF-8.
	TagCESU8 uint64 = 272
	TagWTF8  uint64 = 273
	TagMUTF8 uint64 = 274
)

// AsTime interprets a Tag Value with ID 0 or 1 as a time.Time. It
// returns an error wrapping ErrTimeRange if the encoded instant is
// outside the range representable by time.Time, or if a float epoch is
// NaN or ±Inf.
func AsTime(t Value) (time.Time, error) {
	if t.Kind != KindTag {
		return time.Time{}, mismatchf("cbor: expected Tag value, got kind %d", t.Kind)
	}
	switch t.TagID() {
	case TagDateTimeString:
		inner := t.TagInner()
		if inner.Kind != KindText {
			return time.Time{}, mismatchf("cbor: tag 0 inner must be Text, got kind %d", inner.Kind)
		}
		return time.Parse(time.RFC3339, inner.TextVal())
	case TagEpochDateTime:
		inner := t.TagInner()
		switch inner.Kind {
		case KindUint:
			if inner.UintVal() > math.MaxInt64 {
				return time.Time{}, fmt.Errorf("%w: epoch %d", ErrTimeRange, inner.UintVal())
			}
			return time.Unix(int64(inner.UintVal()), 0).UTC(), nil
		case KindNegInt:
			if inner.NegIntVal() > math.MaxInt64 {
				return time.Time{}, fmt.Errorf("%w: epoch -1-%d", ErrTimeRange, inner.NegIntVal())
			}
			sec := -1 - int64(inner.NegIntVal())
			return time.Unix(sec, 0).UTC(), nil
		case KindFloat32:
			return floatEpoch(float64(inner.Float32Val()))
		case KindFloat64:
			return floatEpoch(inner.Float64Val())
		default:
			return time.Time{}, mismatchf("cbor: tag 1 inner must be Uint/NegInt/Float, got kind %d", inner.Kind)
		}
	default:
		return time.Time{}, mismatchf("cbor: expected tag 0 or 1, got tag %d", t.TagID())
	}
}

// floatEpoch converts float epoch seconds to a time.Time, splitting
// whole and fractional seconds so large values don't overflow when
// scaled to nanoseconds.
func floatEpoch(f float64) (time.Time, error) {
	// -2^63 is exactly representable as a float64; 2^63 is not an int64.
	if math.IsNaN(f) || f < math.MinInt64 || f >= math.MaxInt64 {
		return time.Time{}, fmt.Errorf("%w: epoch %g", ErrTimeRange, f)
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC(), nil
}

// TimeTo encodes t as tag 1 with an integer epoch-seconds argument
// (major type 0 at or after the epoch, major type 1 before it).
// Sub-second precision is truncated; use TimeToFloat to retain it.
func TimeTo(t time.Time) Value {
	sec := t.Unix()
	if sec >= 0 {
		return MakeTag(TagEpochDateTime, Uint(uint64(sec)))
	}
	return MakeTag(TagEpochDateTime, NegInt(uint64(-1-sec)))
}

func TimeToFloat(t time.Time) Value {
	sec := float64(t.Unix()) + float64(t.Nanosecond())/1e9
	return MakeTag(TagEpochDateTime, Float64(sec))
}

func TimeToString(t time.Time) Value {
	return MakeTag(TagDateTimeString, Text(t.UTC().Format(time.RFC3339)))
}

func AsBigInt(t Value) (*big.Int, error) {
	if t.Kind != KindTag {
		return nil, mismatchf("cbor: expected Tag value, got kind %d", t.Kind)
	}
	switch t.TagID() {
	case TagUnsignedBignum:
		inner := t.TagInner()
		if inner.Kind != KindBytes {
			return nil, mismatchf("cbor: tag 2 inner must be Bytes, got kind %d", inner.Kind)
		}
		n := new(big.Int).SetBytes(inner.BytesVal())
		return n, nil
	case TagNegativeBignum:
		inner := t.TagInner()
		if inner.Kind != KindBytes {
			return nil, mismatchf("cbor: tag 3 inner must be Bytes, got kind %d", inner.Kind)
		}
		n := new(big.Int).SetBytes(inner.BytesVal())
		n.Add(n, big.NewInt(1))
		n.Neg(n)
		return n, nil
	default:
		return nil, mismatchf("cbor: expected tag 2 or 3, got tag %d", t.TagID())
	}
}

// BigIntTo encodes n as tag 2 or 3. A nil n encodes as Null.
func BigIntTo(n *big.Int) Value {
	if n == nil {
		return Null()
	}
	if n.Sign() >= 0 {
		return MakeTag(TagUnsignedBignum, Bytes(n.Bytes()))
	}
	v := new(big.Int).Abs(n)
	v.Sub(v, big.NewInt(1))
	return MakeTag(TagNegativeBignum, Bytes(v.Bytes()))
}

// BigIntToPreferred returns the RFC 8949 §3.4.3 preferred
// representation of n: Uint or NegInt when n fits in 64 bits,
// otherwise Tag(2|3, Bytes) with no leading zeros. A nil n returns Null.
func BigIntToPreferred(n *big.Int) Value {
	if n == nil {
		return Null()
	}
	if n.Sign() >= 0 {
		if n.IsUint64() {
			return Uint(n.Uint64())
		}
		return MakeTag(TagUnsignedBignum, Bytes(n.Bytes()))
	}
	v := new(big.Int).Abs(n)
	v.Sub(v, big.NewInt(1))
	if v.IsUint64() {
		return NegInt(v.Uint64())
	}
	return MakeTag(TagNegativeBignum, Bytes(v.Bytes()))
}

// AsBigIntAny interprets an integer in either form RFC 8949 allows:
// major type 0/1 (Uint, NegInt) or a tag 2/3 bignum. AsBigInt accepts
// only the tag form.
func AsBigIntAny(v Value) (*big.Int, error) {
	switch v.Kind {
	case KindUint:
		return new(big.Int).SetUint64(v.UintVal()), nil
	case KindNegInt:
		n := new(big.Int).SetUint64(v.NegIntVal())
		n.Add(n, big.NewInt(1))
		return n.Neg(n), nil
	default:
		return AsBigInt(v)
	}
}

// AsNestedCBOR returns the embedded bytes of a tag 24 value. It does
// not check them: they may be empty, ill-formed, or hold more than one
// data item, none of which is valid tag 24 content (RFC 8949 §3.4.5.1). Decoder.DecodeEncodedCBOR in the root package
// requires exactly one well-formed item and decodes it, and the
// decoder's RejectInvalidTagContent checks the same while decoding; to
// build a tag 24 value, use WrapEncodedCBOR or Encoder.EncodeEncodedCBOR.
func AsNestedCBOR(t Value) ([]byte, error) {
	if t.Kind != KindTag {
		return nil, mismatchf("cbor: expected Tag value, got kind %d", t.Kind)
	}
	if t.TagID() != TagEncodedCBOR {
		return nil, mismatchf("cbor: expected tag 24, got tag %d", t.TagID())
	}
	inner := t.TagInner()
	if inner.Kind != KindBytes {
		return nil, mismatchf("cbor: tag 24 inner must be Bytes, got kind %d", inner.Kind)
	}
	return inner.BytesVal(), nil
}

// textError keeps a fixed message while wrapping a sentinel, so
// errors.Is matches without changing the v0.2.2 text.
type textError struct {
	msg string
	err error
}

func (e *textError) Error() string { return e.msg }

func (e *textError) Unwrap() error { return e.err }

// mismatchf returns a formatted error that wraps ErrTypeMismatch.
func mismatchf(format string, args ...any) error {
	return &textError{msg: fmt.Sprintf(format, args...), err: ErrTypeMismatch}
}
