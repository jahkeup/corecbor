// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"math"
)

// Kind identifies the CBOR data item type stored in a Value.
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
	KindBool           // major type 7 simple values 20/21
	KindNull           // major type 7 simple value 22
	KindUndefined      // major type 7 simple value 23
	KindFloat32        // major type 7 float32
	KindFloat64        // major type 7 float64
	KindSimple         // major type 7 unassigned simple values
)

// Value is a tagged-union struct representing any CBOR data item.
// The zero value has Kind()==KindInvalid and IsZero()==true.
type Value struct {
	kind  Kind
	num   uint64     // Uint, NegInt, Float64 bits, Float32 bits, Bool, Simple, Tag ID
	str   string     // Text
	bytes []byte     // Bytes
	items []Value    // Array, Tag inner (items[0])
	pairs []MapEntry // Map
}

// MapEntry is a single key-value pair in a CBOR map.
type MapEntry struct {
	Key   Value
	Value Value
}

// Kind returns the type of CBOR data item stored in v.
func (v Value) Kind() Kind { return v.kind }

// IsZero reports whether v is the zero Value (KindInvalid).
func (v Value) IsZero() bool { return v.kind == KindInvalid }

// --- Constructors ---

// Uint creates a CBOR unsigned integer value (major type 0).
func Uint(n uint64) Value {
	return Value{kind: KindUint, num: n}
}

// NegInt creates a CBOR negative integer value (major type 1).
// The encoded value on the wire is -1 - n, so NegInt(0) represents -1.
func NegInt(n uint64) Value {
	return Value{kind: KindNegInt, num: n}
}

// Bytes creates a CBOR byte string value (major type 2).
func Bytes(b []byte) Value {
	return Value{kind: KindBytes, bytes: b}
}

// Text creates a CBOR text string value (major type 3).
func Text(s string) Value {
	return Value{kind: KindText, str: s}
}

// MakeArray creates a CBOR array value (major type 4).
func MakeArray(items ...Value) Value {
	return Value{kind: KindArray, items: items}
}

// MakeMap creates a CBOR map value (major type 5).
func MakeMap(pairs ...MapEntry) Value {
	return Value{kind: KindMap, pairs: pairs}
}

// MakeTag creates a CBOR tagged data item (major type 6).
func MakeTag(id uint64, inner Value) Value {
	return Value{kind: KindTag, num: id, items: []Value{inner}}
}

// Bool creates a CBOR boolean value (major type 7, simple values 20/21).
func Bool(b bool) Value {
	var n uint64
	if b {
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

// Float32 creates a CBOR single-precision float value.
func Float32(f float32) Value {
	return Value{kind: KindFloat32, num: uint64(math.Float32bits(f))}
}

// Float64 creates a CBOR double-precision float value.
func Float64(f float64) Value {
	return Value{kind: KindFloat64, num: math.Float64bits(f)}
}

// Simple creates a CBOR simple value (major type 7) that is not one of the
// named values (false, true, null, undefined). Valid range: 0-19, 32-255.
func Simple(s uint8) Value {
	return Value{kind: KindSimple, num: uint64(s)}
}

// --- Accessors ---

// Uint returns the unsigned integer value. Panics if Kind != KindUint.
func (v Value) Uint() uint64 {
	if v.kind != KindUint {
		panic("cbor: Value.Uint called on non-Uint value")
	}
	return v.num
}

// NegInt returns the negative integer argument. Panics if Kind != KindNegInt.
func (v Value) NegInt() uint64 {
	if v.kind != KindNegInt {
		panic("cbor: Value.NegInt called on non-NegInt value")
	}
	return v.num
}

// Bytes returns the byte string. Panics if Kind != KindBytes.
func (v Value) Bytes() []byte {
	if v.kind != KindBytes {
		panic("cbor: Value.Bytes called on non-Bytes value")
	}
	return v.bytes
}

// Text returns the text string. Panics if Kind != KindText.
func (v Value) Text() string {
	if v.kind != KindText {
		panic("cbor: Value.Text called on non-Text value")
	}
	return v.str
}

// Array returns the array items. Panics if Kind != KindArray.
func (v Value) Array() []Value {
	if v.kind != KindArray {
		panic("cbor: Value.Array called on non-Array value")
	}
	return v.items
}

// Map returns the map entries. Panics if Kind != KindMap.
func (v Value) Map() []MapEntry {
	if v.kind != KindMap {
		panic("cbor: Value.Map called on non-Map value")
	}
	return v.pairs
}

// TagID returns the tag number. Panics if Kind != KindTag.
func (v Value) TagID() uint64 {
	if v.kind != KindTag {
		panic("cbor: Value.TagID called on non-Tag value")
	}
	return v.num
}

// TagInner returns the tagged inner value. Panics if Kind != KindTag.
func (v Value) TagInner() Value {
	if v.kind != KindTag {
		panic("cbor: Value.TagInner called on non-Tag value")
	}
	if len(v.items) == 0 {
		return Value{}
	}
	return v.items[0]
}

// Bool returns the boolean value. Panics if Kind != KindBool.
func (v Value) Bool() bool {
	if v.kind != KindBool {
		panic("cbor: Value.Bool called on non-Bool value")
	}
	return v.num != 0
}

// Float32 returns the float32 value. Panics if Kind != KindFloat32.
func (v Value) Float32() float32 {
	if v.kind != KindFloat32 {
		panic("cbor: Value.Float32 called on non-Float32 value")
	}
	return math.Float32frombits(uint32(v.num))
}

// Float64 returns the float64 value. Panics if Kind != KindFloat64.
func (v Value) Float64() float64 {
	if v.kind != KindFloat64 {
		panic("cbor: Value.Float64 called on non-Float64 value")
	}
	return math.Float64frombits(v.num)
}

// Simple returns the simple value. Panics if Kind != KindSimple.
func (v Value) Simple() uint8 {
	if v.kind != KindSimple {
		panic("cbor: Value.Simple called on non-Simple value")
	}
	return uint8(v.num)
}
