// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"fmt"
	"math/big"
	"time"
)

// Well-known CBOR tag numbers from the IANA registry.
const (
	TagDateTimeString uint64 = 0     // RFC 3339 text string
	TagEpochDateTime  uint64 = 1     // integer or float epoch seconds
	TagUnsignedBignum uint64 = 2     // byte string
	TagNegativeBignum uint64 = 3     // byte string
	TagEncodedCBOR    uint64 = 24    // byte string containing CBOR
	TagURI            uint64 = 32    // text string
	TagSelfDescribe   uint64 = 55799 // self-describe marker
)

// AsTime interprets a Tag value with ID 0 or 1 as a time.Time.
// Tag 0: parses the inner Text as RFC 3339.
// Tag 1: interprets the inner Uint/NegInt/Float as epoch seconds.
func AsTime(t Value) (time.Time, error) {
	if t.Kind() != KindTag {
		return time.Time{}, fmt.Errorf("cbor: expected tag, got kind %d", t.Kind())
	}
	id := t.TagID()
	inner := t.TagInner()
	switch id {
	case TagDateTimeString:
		if inner.Kind() != KindText {
			return time.Time{}, fmt.Errorf("cbor: tag 0 inner must be Text, got kind %d", inner.Kind())
		}
		return time.Parse(time.RFC3339, inner.Text())
	case TagEpochDateTime:
		switch inner.Kind() {
		case KindUint:
			return time.Unix(int64(inner.Uint()), 0).UTC(), nil
		case KindNegInt:
			sec := -1 - int64(inner.NegInt())
			return time.Unix(sec, 0).UTC(), nil
		case KindFloat32:
			f := float64(inner.Float32())
			return time.Unix(0, int64(f*1e9)).UTC(), nil
		case KindFloat64:
			f := inner.Float64()
			return time.Unix(0, int64(f*1e9)).UTC(), nil
		default:
			return time.Time{}, fmt.Errorf("cbor: tag 1 inner must be Uint/NegInt/Float, got kind %d", inner.Kind())
		}
	default:
		return time.Time{}, fmt.Errorf("cbor: expected tag 0 or 1, got tag %d", id)
	}
}

// TimeTo creates a Tag(1, epoch) from a time.Time using integer
// seconds. Sub-second precision is lost; use TimeToFloat for sub-second.
func TimeTo(t time.Time) Value {
	return MakeTag(TagEpochDateTime, Uint(uint64(t.Unix())))
}

// TimeToFloat creates a Tag(1, float64) from a time.Time preserving
// sub-second precision.
func TimeToFloat(t time.Time) Value {
	sec := float64(t.Unix()) + float64(t.Nanosecond())/1e9
	return MakeTag(TagEpochDateTime, Float64(sec))
}

// TimeToString creates a Tag(0, text) from a time.Time in RFC 3339 format.
func TimeToString(t time.Time) Value {
	return MakeTag(TagDateTimeString, Text(t.UTC().Format(time.RFC3339)))
}

// AsBigInt interprets a Tag value with ID 2 or 3 as a *big.Int.
// Tag 2: unsigned bignum (positive).
// Tag 3: negative bignum (-1 - value).
func AsBigInt(t Value) (*big.Int, error) {
	if t.Kind() != KindTag {
		return nil, fmt.Errorf("cbor: expected tag, got kind %d", t.Kind())
	}
	id := t.TagID()
	inner := t.TagInner()
	switch id {
	case TagUnsignedBignum:
		if inner.Kind() != KindBytes {
			return nil, fmt.Errorf("cbor: tag 2 inner must be Bytes, got kind %d", inner.Kind())
		}
		n := new(big.Int).SetBytes(inner.Bytes())
		return n, nil
	case TagNegativeBignum:
		if inner.Kind() != KindBytes {
			return nil, fmt.Errorf("cbor: tag 3 inner must be Bytes, got kind %d", inner.Kind())
		}
		// actual value = -1 - bignum
		n := new(big.Int).SetBytes(inner.Bytes())
		n.Add(n, big.NewInt(1))
		n.Neg(n)
		return n, nil
	default:
		return nil, fmt.Errorf("cbor: expected tag 2 or 3, got tag %d", id)
	}
}

// BigIntTo creates a Tag(2 or 3, bytes) from a *big.Int.
func BigIntTo(n *big.Int) Value {
	if n.Sign() >= 0 {
		return MakeTag(TagUnsignedBignum, Bytes(n.Bytes()))
	}
	// negative: encode as tag 3 with value = -1 - n (i.e., |n| - 1)
	v := new(big.Int).Abs(n)
	v.Sub(v, big.NewInt(1))
	return MakeTag(TagNegativeBignum, Bytes(v.Bytes()))
}

// AsNestedCBOR interprets a Tag value with ID 24 (encoded CBOR data item).
// Returns the raw byte string for the caller to decode separately.
func AsNestedCBOR(t Value) ([]byte, error) {
	if t.Kind() != KindTag {
		return nil, fmt.Errorf("cbor: expected tag, got kind %d", t.Kind())
	}
	if t.TagID() != TagEncodedCBOR {
		return nil, fmt.Errorf("cbor: expected tag 24, got tag %d", t.TagID())
	}
	inner := t.TagInner()
	if inner.Kind() != KindBytes {
		return nil, fmt.Errorf("cbor: tag 24 inner must be Bytes, got kind %d", inner.Kind())
	}
	return inner.Bytes(), nil
}
