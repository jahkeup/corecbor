// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"math/big"
	"time"

	"github.com/jahkeup/corecbor/cbor"
)

type (
	Value    = cbor.Value
	MapEntry = cbor.MapEntry
	Kind     = cbor.Kind
)

// Kind constants re-exported from cbor package.
const (
	KindInvalid   = cbor.KindInvalid
	KindUint      = cbor.KindUint
	KindNegInt    = cbor.KindNegInt
	KindBytes     = cbor.KindBytes
	KindText      = cbor.KindText
	KindArray     = cbor.KindArray
	KindMap       = cbor.KindMap
	KindTag       = cbor.KindTag
	KindBool      = cbor.KindBool
	KindNull      = cbor.KindNull
	KindUndefined = cbor.KindUndefined
	KindFloat32   = cbor.KindFloat32
	KindFloat64   = cbor.KindFloat64
	KindSimple    = cbor.KindSimple
)

// Constructor functions re-exported from cbor package.
var (
	Uint      = cbor.Uint
	NegInt    = cbor.NegInt
	Bytes     = cbor.Bytes
	Text      = cbor.Text
	MakeArray = cbor.MakeArray
	MakeMap   = cbor.MakeMap
	MakeTag   = cbor.MakeTag
	Bool      = cbor.Bool
	Null      = cbor.Null
	Undefined = cbor.Undefined
	Float32   = cbor.Float32
	Float64   = cbor.Float64
	Simple    = cbor.Simple
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
func AsTime(t Value) (time.Time, error) { return cbor.AsTime(t) }

// TimeTo creates a Tag(1, epoch) from a time.Time using integer seconds.
func TimeTo(t time.Time) Value { return cbor.TimeTo(t) }

// TimeToFloat creates a Tag(1, float64) from a time.Time preserving sub-second precision.
func TimeToFloat(t time.Time) Value { return cbor.TimeToFloat(t) }

// TimeToString creates a Tag(0, text) from a time.Time in RFC 3339 format.
func TimeToString(t time.Time) Value { return cbor.TimeToString(t) }

// AsBigInt interprets a Tag with ID 2 or 3 as a *big.Int.
func AsBigInt(t Value) (*big.Int, error) { return cbor.AsBigInt(t) }

// BigIntTo creates a Tag(2 or 3, bytes) from a *big.Int.
func BigIntTo(n *big.Int) Value { return cbor.BigIntTo(n) }

// AsNestedCBOR interprets a Tag with ID 24 (encoded CBOR data item).
func AsNestedCBOR(t Value) ([]byte, error) { return cbor.AsNestedCBOR(t) }

// AsStringMap converts a map ([]MapEntry) to map[string]Value.
func AsStringMap(m []MapEntry) (map[string]Value, error) { return cbor.AsStringMap(m) }
