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

// AsTime interprets a Tag with ID 0 or 1 as a time.Time.
// Tag 0: parses the inner Text as RFC 3339.
// Tag 1: interprets the inner Uint/NegInt/Float as epoch seconds.
// Returns an error if the tag ID is not 0 or 1, or the inner value
// is the wrong type.
func AsTime(t Tag) (time.Time, error) {
	switch t.ID {
	case TagDateTimeString:
		text, ok := t.Inner.(Text)
		if !ok {
			return time.Time{}, fmt.Errorf("cbor: tag 0 inner must be Text, got %T", t.Inner)
		}
		return time.Parse(time.RFC3339, string(text))
	case TagEpochDateTime:
		switch v := t.Inner.(type) {
		case Uint:
			return time.Unix(int64(v), 0).UTC(), nil
		case NegInt:
			// NegInt(n) represents -1 - n
			sec := -1 - int64(v)
			return time.Unix(sec, 0).UTC(), nil
		case Float32:
			f := float64(v)
			return time.Unix(0, int64(f*1e9)).UTC(), nil
		case Float64:
			return time.Unix(0, int64(float64(v)*1e9)).UTC(), nil
		default:
			return time.Time{}, fmt.Errorf("cbor: tag 1 inner must be Uint/NegInt/Float, got %T", t.Inner)
		}
	default:
		return time.Time{}, fmt.Errorf("cbor: expected tag 0 or 1, got tag %d", t.ID)
	}
}

// TimeTo creates a Tag(1, epoch) from a time.Time using integer
// seconds. Sub-second precision is lost; use TimeToFloat for sub-second.
func TimeTo(t time.Time) Tag {
	return Tag{ID: TagEpochDateTime, Inner: Uint(t.Unix())}
}

// TimeToFloat creates a Tag(1, float64) from a time.Time preserving
// sub-second precision.
func TimeToFloat(t time.Time) Tag {
	sec := float64(t.Unix()) + float64(t.Nanosecond())/1e9
	return Tag{ID: TagEpochDateTime, Inner: Float64(sec)}
}

// TimeToString creates a Tag(0, text) from a time.Time in RFC 3339 format.
func TimeToString(t time.Time) Tag {
	return Tag{ID: TagDateTimeString, Inner: Text(t.UTC().Format(time.RFC3339))}
}

// AsBigInt interprets a Tag with ID 2 or 3 as a *big.Int.
// Tag 2: unsigned bignum (positive).
// Tag 3: negative bignum (-1 - value).
func AsBigInt(t Tag) (*big.Int, error) {
	switch t.ID {
	case TagUnsignedBignum:
		b, ok := t.Inner.(Bytes)
		if !ok {
			return nil, fmt.Errorf("cbor: tag 2 inner must be Bytes, got %T", t.Inner)
		}
		n := new(big.Int).SetBytes([]byte(b))
		return n, nil
	case TagNegativeBignum:
		b, ok := t.Inner.(Bytes)
		if !ok {
			return nil, fmt.Errorf("cbor: tag 3 inner must be Bytes, got %T", t.Inner)
		}
		// actual value = -1 - bignum
		n := new(big.Int).SetBytes([]byte(b))
		n.Add(n, big.NewInt(1))
		n.Neg(n)
		return n, nil
	default:
		return nil, fmt.Errorf("cbor: expected tag 2 or 3, got tag %d", t.ID)
	}
}

// BigIntTo creates a Tag(2 or 3, bytes) from a *big.Int.
func BigIntTo(n *big.Int) Tag {
	if n.Sign() >= 0 {
		return Tag{ID: TagUnsignedBignum, Inner: Bytes(n.Bytes())}
	}
	// negative: encode as tag 3 with value = -1 - n (i.e., |n| - 1)
	v := new(big.Int).Abs(n)
	v.Sub(v, big.NewInt(1))
	return Tag{ID: TagNegativeBignum, Inner: Bytes(v.Bytes())}
}

// AsNestedCBOR interprets a Tag with ID 24 (encoded CBOR data item).
// Returns the raw byte string for the caller to decode separately.
func AsNestedCBOR(t Tag) ([]byte, error) {
	if t.ID != TagEncodedCBOR {
		return nil, fmt.Errorf("cbor: expected tag 24, got tag %d", t.ID)
	}
	b, ok := t.Inner.(Bytes)
	if !ok {
		return nil, fmt.Errorf("cbor: tag 24 inner must be Bytes, got %T", t.Inner)
	}
	return []byte(b), nil
}
