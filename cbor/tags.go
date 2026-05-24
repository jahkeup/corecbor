// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"fmt"
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
)

// AsTime interprets a Tag Value with ID 0 or 1 as a time.Time.
func AsTime(t Value) (time.Time, error) {
	if t.Kind() != KindTag {
		return time.Time{}, fmt.Errorf("cbor: expected Tag value, got kind %d", t.Kind())
	}
	switch t.TagID() {
	case TagDateTimeString:
		inner := t.TagInner()
		if inner.Kind() != KindText {
			return time.Time{}, fmt.Errorf("cbor: tag 0 inner must be Text, got kind %d", inner.Kind())
		}
		return time.Parse(time.RFC3339, inner.TextVal())
	case TagEpochDateTime:
		inner := t.TagInner()
		switch inner.Kind() {
		case KindUint:
			return time.Unix(int64(inner.UintVal()), 0).UTC(), nil
		case KindNegInt:
			sec := -1 - int64(inner.NegIntVal())
			return time.Unix(sec, 0).UTC(), nil
		case KindFloat32:
			f := float64(inner.Float32Val())
			return time.Unix(0, int64(f*1e9)).UTC(), nil
		case KindFloat64:
			return time.Unix(0, int64(inner.Float64Val()*1e9)).UTC(), nil
		default:
			return time.Time{}, fmt.Errorf("cbor: tag 1 inner must be Uint/NegInt/Float, got kind %d", inner.Kind())
		}
	default:
		return time.Time{}, fmt.Errorf("cbor: expected tag 0 or 1, got tag %d", t.TagID())
	}
}

func TimeTo(t time.Time) Value {
	return MakeTag(TagEpochDateTime, Uint(uint64(t.Unix())))
}

func TimeToFloat(t time.Time) Value {
	sec := float64(t.Unix()) + float64(t.Nanosecond())/1e9
	return MakeTag(TagEpochDateTime, Float64(sec))
}

func TimeToString(t time.Time) Value {
	return MakeTag(TagDateTimeString, Text(t.UTC().Format(time.RFC3339)))
}

func AsBigInt(t Value) (*big.Int, error) {
	if t.Kind() != KindTag {
		return nil, fmt.Errorf("cbor: expected Tag value, got kind %d", t.Kind())
	}
	switch t.TagID() {
	case TagUnsignedBignum:
		inner := t.TagInner()
		if inner.Kind() != KindBytes {
			return nil, fmt.Errorf("cbor: tag 2 inner must be Bytes, got kind %d", inner.Kind())
		}
		n := new(big.Int).SetBytes(inner.BytesVal())
		return n, nil
	case TagNegativeBignum:
		inner := t.TagInner()
		if inner.Kind() != KindBytes {
			return nil, fmt.Errorf("cbor: tag 3 inner must be Bytes, got kind %d", inner.Kind())
		}
		n := new(big.Int).SetBytes(inner.BytesVal())
		n.Add(n, big.NewInt(1))
		n.Neg(n)
		return n, nil
	default:
		return nil, fmt.Errorf("cbor: expected tag 2 or 3, got tag %d", t.TagID())
	}
}

func BigIntTo(n *big.Int) Value {
	if n.Sign() >= 0 {
		return MakeTag(TagUnsignedBignum, Bytes(n.Bytes()))
	}
	v := new(big.Int).Abs(n)
	v.Sub(v, big.NewInt(1))
	return MakeTag(TagNegativeBignum, Bytes(v.Bytes()))
}

func AsNestedCBOR(t Value) ([]byte, error) {
	if t.Kind() != KindTag {
		return nil, fmt.Errorf("cbor: expected Tag value, got kind %d", t.Kind())
	}
	if t.TagID() != TagEncodedCBOR {
		return nil, fmt.Errorf("cbor: expected tag 24, got tag %d", t.TagID())
	}
	inner := t.TagInner()
	if inner.Kind() != KindBytes {
		return nil, fmt.Errorf("cbor: tag 24 inner must be Bytes, got kind %d", inner.Kind())
	}
	return inner.BytesVal(), nil
}
