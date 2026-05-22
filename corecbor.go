// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"math/big"
	"time"

	"github.com/jahkeup/corecbor/cbor"
)

type (
	Value     = cbor.Value
	Uint      = cbor.Uint
	NegInt    = cbor.NegInt
	Bytes     = cbor.Bytes
	Text      = cbor.Text
	Array     = cbor.Array
	MapEntry  = cbor.MapEntry
	Map       = cbor.Map
	Tag       = cbor.Tag
	Bool      = cbor.Bool
	Null      = cbor.Null
	Undefined = cbor.Undefined
	Simple    = cbor.Simple
	Float32   = cbor.Float32
	Float64   = cbor.Float64
)

// Tag constants re-exported from cbor package.
const (
	TagDateTimeString = cbor.TagDateTimeString
	TagEpochDateTime  = cbor.TagEpochDateTime
	TagUnsignedBignum = cbor.TagUnsignedBignum
	TagNegativeBignum = cbor.TagNegativeBignum
	TagEncodedCBOR    = cbor.TagEncodedCBOR
	TagURI            = cbor.TagURI
	TagSelfDescribe   = cbor.TagSelfDescribe
)

var (
	ErrNonShortest         = cbor.ErrNonShortest
	ErrIndefiniteLength    = cbor.ErrIndefiniteLength
	ErrInvalidUTF8         = cbor.ErrInvalidUTF8
	ErrDuplicateMapKey     = cbor.ErrDuplicateMapKey
	ErrUnknownTag          = cbor.ErrUnknownTag
	ErrNonFiniteFloat      = cbor.ErrNonFiniteFloat
	ErrNullMapKey          = cbor.ErrNullMapKey
	ErrTrailingBytes       = cbor.ErrTrailingBytes
	ErrTruncated           = cbor.ErrTruncated
	ErrMaxNestingDepth     = cbor.ErrMaxNestingDepth
	ErrMaxArrayLength      = cbor.ErrMaxArrayLength
	ErrMaxByteStringLength = cbor.ErrMaxByteStringLength
	ErrInvalidMode         = cbor.ErrInvalidMode
	ErrNilValue            = cbor.ErrNilValue
	ErrReservedAI          = cbor.ErrReservedAI
	ErrNonStringKey        = cbor.ErrNonStringKey
)

// AsTime interprets a Tag with ID 0 or 1 as a time.Time.
func AsTime(t Tag) (time.Time, error) { return cbor.AsTime(t) }

// TimeTo creates a Tag(1, epoch) from a time.Time using integer seconds.
func TimeTo(t time.Time) Tag { return cbor.TimeTo(t) }

// TimeToFloat creates a Tag(1, float64) from a time.Time preserving sub-second precision.
func TimeToFloat(t time.Time) Tag { return cbor.TimeToFloat(t) }

// TimeToString creates a Tag(0, text) from a time.Time in RFC 3339 format.
func TimeToString(t time.Time) Tag { return cbor.TimeToString(t) }

// AsBigInt interprets a Tag with ID 2 or 3 as a *big.Int.
func AsBigInt(t Tag) (*big.Int, error) { return cbor.AsBigInt(t) }

// BigIntTo creates a Tag(2 or 3, bytes) from a *big.Int.
func BigIntTo(n *big.Int) Tag { return cbor.BigIntTo(n) }

// AsNestedCBOR interprets a Tag with ID 24 (encoded CBOR data item).
func AsNestedCBOR(t Tag) ([]byte, error) { return cbor.AsNestedCBOR(t) }
