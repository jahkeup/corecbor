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

	MakeArrayFromSlice = cbor.MakeArrayFromSlice
	MakeMapFromSlice   = cbor.MakeMapFromSlice
	AsStringMap        = cbor.AsStringMap
)

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

func AsTime(t Value) (time.Time, error)    { return cbor.AsTime(t) }
func TimeTo(t time.Time) Value             { return cbor.TimeTo(t) }
func TimeToFloat(t time.Time) Value        { return cbor.TimeToFloat(t) }
func TimeToString(t time.Time) Value       { return cbor.TimeToString(t) }
func AsBigInt(t Value) (*big.Int, error)   { return cbor.AsBigInt(t) }
func BigIntTo(n *big.Int) Value            { return cbor.BigIntTo(n) }
func AsNestedCBOR(t Value) ([]byte, error) { return cbor.AsNestedCBOR(t) }
