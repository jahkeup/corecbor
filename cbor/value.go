// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import "math"

// Kind identifies the CBOR data type stored in a Value.
type Kind uint8

const (
	KindInvalid   Kind = iota
	KindUint           // major type 0
	KindNegInt         // major type 1
	KindBytes          // major type 2
	KindText           // major type 3
	KindArray          // major type 4
	KindMap            // major type 5
	KindTag            // major type 6
	KindBool           // major type 7 simple 20/21
	KindNull           // major type 7 simple 22
	KindUndefined      // major type 7 simple 23
	KindFloat32        // major type 7 AI 26
	KindFloat64        // major type 7 AI 27
	KindSimple         // major type 7 unassigned simple values
)

// Value is the tagged-union representation of every CBOR data item type.
// The zero Value has Kind == KindInvalid.
type Value struct {
	kind  Kind
	num   uint64     // Uint, NegInt, Float64(bits), Float32(bits), Bool(0/1), Simple, Tag ID
	str   string     // Text
	bytes []byte     // Bytes
	items []Value    // Array, Tag(items[0] = inner)
	pairs []MapEntry // Map
}

// MapEntry is a single key-value pair in a CBOR map.
type MapEntry struct {
	Key   Value
	Value Value
}

// Kind returns the CBOR type discriminator.
func (v Value) Kind() Kind { return v.kind }

// IsZero reports whether v is the zero Value (KindInvalid).
func (v Value) IsZero() bool { return v.kind == KindInvalid }

// --- Constructors ---

// Uint creates a CBOR unsigned integer (major type 0), range [0, 2^64-1].
func Uint(n uint64) Value {
	return Value{kind: KindUint, num: n}
}

// NegInt creates a CBOR negative integer (major type 1). The encoded value
// on the wire is -1 - n, so NegInt(0) represents -1 and
// NegInt(math.MaxUint64) represents -2^64.
func NegInt(n uint64) Value {
	return Value{kind: KindNegInt, num: n}
}

// Bytes creates a CBOR byte string (major type 2).
func Bytes(b []byte) Value {
	return Value{kind: KindBytes, bytes: b}
}

// Text creates a CBOR text string (major type 3).
func Text(s string) Value {
	return Value{kind: KindText, str: s}
}

// MakeArray creates a CBOR array (major type 4).
func MakeArray(items ...Value) Value {
	return Value{kind: KindArray, items: items}
}

// MakeMap creates a CBOR map (major type 5).
func MakeMap(pairs ...MapEntry) Value {
	return Value{kind: KindMap, pairs: pairs}
}

// MakeTag creates a CBOR tagged data item (major type 6).
func MakeTag(id uint64, inner Value) Value {
	return Value{kind: KindTag, num: id, items: []Value{inner}}
}

// Bool creates a CBOR boolean (major type 7, simple values 20/21).
func Bool(v bool) Value {
	var n uint64
	if v {
		n = 1
	}
	return Value{kind: KindBool, num: n}
}

// Null creates the CBOR null value (major type 7, simple value 22).
func Null() Value {
	return Value{kind: KindNull}
}

// Undefined creates the CBOR undefined value (major type 7, simple value 23).
func Undefined() Value {
	return Value{kind: KindUndefined}
}

// Float32 creates a CBOR single-precision float (major type 7, AI 26).
func Float32(f float32) Value {
	return Value{kind: KindFloat32, num: uint64(math.Float32bits(f))}
}

// Float64 creates a CBOR double-precision float (major type 7, AI 27).
func Float64(f float64) Value {
	return Value{kind: KindFloat64, num: math.Float64bits(f)}
}

// Simple creates a CBOR simple value (major type 7) that is not one of the
// named values (false, true, null, undefined). Valid range: 0-19, 32-255.
func Simple(v uint8) Value {
	return Value{kind: KindSimple, num: uint64(v)}
}

// --- Accessors ---

// UintVal returns the uint64 value. Panics if Kind != KindUint.
func (v Value) UintVal() uint64 {
	return v.num
}

// NegIntVal returns the uint64 value. Panics if Kind != KindNegInt.
func (v Value) NegIntVal() uint64 {
	return v.num
}

// BytesVal returns the byte slice. Panics if Kind != KindBytes.
func (v Value) BytesVal() []byte {
	return v.bytes
}

// TextVal returns the string value.
func (v Value) TextVal() string {
	return v.str
}

// Array returns the items slice.
func (v Value) Array() []Value {
	return v.items
}

// Map returns the map entries.
func (v Value) Map() []MapEntry {
	return v.pairs
}

// TagID returns the tag number.
func (v Value) TagID() uint64 {
	return v.num
}

// TagInner returns the tagged inner value.
func (v Value) TagInner() Value {
	if len(v.items) == 0 {
		return Value{}
	}
	return v.items[0]
}

// BoolVal returns the boolean value.
func (v Value) BoolVal() bool {
	return v.num != 0
}

// Float32Val returns the float32 value.
func (v Value) Float32Val() float32 {
	return math.Float32frombits(uint32(v.num))
}

// Float64Val returns the float64 value.
func (v Value) Float64Val() float64 {
	return math.Float64frombits(v.num)
}

// SimpleVal returns the simple value.
func (v Value) SimpleVal() uint8 {
	return uint8(v.num)
}

// --- Helpers for making slices ---

// MakeArrayFromSlice creates an array Value from a pre-allocated slice.
func MakeArrayFromSlice(items []Value) Value {
	return Value{kind: KindArray, items: items}
}

// MakeMapFromSlice creates a map Value from a pre-allocated slice.
func MakeMapFromSlice(pairs []MapEntry) Value {
	return Value{kind: KindMap, pairs: pairs}
}
