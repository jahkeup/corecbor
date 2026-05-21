package corecbor

import "github.com/jahkeup/corecbor/cbor"

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
)
