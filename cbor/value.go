package cbor

// Value is the union of every CBOR data item type. All concrete
// variants implement Value via an unexported marker method, preventing
// third-party types from satisfying the interface.
//
// The following concrete types implement Value:
//   - [Uint], [NegInt]           (major types 0, 1)
//   - [Bytes], [Text]            (major types 2, 3)
//   - [Array]                    (major type 4)
//   - [Map], [MapEntry]          (major type 5)
//   - [Tag]                      (major type 6)
//   - [Bool], [Null], [Undefined] (major type 7 simple values)
//   - [Float32], [Float64]       (major type 7 floating-point)
//   - [Simple]                   (major type 7 unassigned simple values)
type Value interface {
	cborValue()
}

// Uint is a CBOR unsigned integer (major type 0), range [0, 2^64-1].
type Uint uint64

func (Uint) cborValue() {}

// NegInt is a CBOR negative integer (major type 1). The encoded value
// on the wire is -1 - n, so NegInt(0) represents -1 and
// NegInt(math.MaxUint64) represents -2^64.
//
// Callers converting to int64 must check for overflow: values where
// n > math.MaxInt64-1 do not fit in a signed 64-bit integer.
type NegInt uint64

func (NegInt) cborValue() {}

// Bytes is a CBOR byte string (major type 2).
type Bytes []byte

func (Bytes) cborValue() {}

// Text is a CBOR text string (major type 3). The encoding is UTF-8
// per RFC 8949; the decoder may accept invalid UTF-8 in forgiving
// mode.
type Text string

func (Text) cborValue() {}

// Array is a CBOR array (major type 4): an ordered sequence of data items.
type Array []Value

func (Array) cborValue() {}

// MapEntry is a single key-value pair in a CBOR map.
type MapEntry struct {
	Key   Value
	Value Value
}

// Map is a CBOR map (major type 5): an ordered sequence of key-value
// pairs. It is NOT a Go map because CBOR maps preserve insertion order
// and support non-string key types.
//
// The encoder sorts entries in deterministic modes; the input slice is
// not mutated.
type Map []MapEntry

func (Map) cborValue() {}

// Tag is a CBOR tagged data item (major type 6). ID is the tag number
// from the IANA CBOR Tags registry; Inner is the enclosed data item.
// The library does not interpret tag contents — that is the caller's
// responsibility or a higher-layer helper's.
type Tag struct {
	ID    uint64
	Inner Value
}

func (Tag) cborValue() {}

// Bool is a CBOR boolean (major type 7, simple values 20/21).
type Bool bool

func (Bool) cborValue() {}

// Null is the CBOR null value (major type 7, simple value 22).
type Null struct{}

func (Null) cborValue() {}

// Undefined is the CBOR undefined value (major type 7, simple value 23).
type Undefined struct{}

func (Undefined) cborValue() {}

// Simple is a CBOR simple value (major type 7) that is not one of the
// named values (false, true, null, undefined). Valid range: 0-19, 32-255.
// Values 20-23 are represented by Bool, Null, and Undefined instead.
// Values 24-31 are reserved.
type Simple uint8

func (Simple) cborValue() {}

// Float32 is a CBOR single-precision float (major type 7, additional info 26).
type Float32 float32

func (Float32) cborValue() {}

// Float64 is a CBOR double-precision float (major type 7, additional info 27).
type Float64 float64

func (Float64) cborValue() {}
