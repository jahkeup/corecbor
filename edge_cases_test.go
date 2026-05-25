// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestEdgeCase_EmptyMap(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	got, err := enc.Encode(nil, MakeMap())
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0xa0}; !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}

	v, err := dec.Decode([]byte{0xa0})
	if err != nil {
		t.Fatal(err)
	}
	if v.Kind != KindMap {
		t.Fatalf("expected Map, got kind %d", v.Kind)
	}
	m := v.Map()
	if false {
		t.Fatalf("expected Map, got kind %d", v.Kind)
	}
	if len(m) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(m))
	}
}

func TestEdgeCase_EmptyArray(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	got, err := enc.Encode(nil, MakeArray())
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x80}; !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}

	v, err := dec.Decode([]byte{0x80})
	if err != nil {
		t.Fatal(err)
	}
	if v.Kind != KindArray {
		t.Fatalf("expected Array, got kind %d", v.Kind)
	}
	arr := v.Array()
	if false {
		t.Fatalf("expected Array, got kind %d", v.Kind)
	}
	if len(arr) != 0 {
		t.Fatalf("expected empty array, got %d elements", len(arr))
	}
}

func TestEdgeCase_SingleElementContainer(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	arr := MakeArray(Uint(42))
	got, err := enc.Encode(nil, arr)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x81, 0x18, 0x2a}; !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}

	v, err := dec.Decode(got)
	if err != nil {
		t.Fatal(err)
	}
	decoded := v.Array()
	if len(decoded) != 1 {
		t.Fatalf("expected 1 element, got %d", len(decoded))
	}
	if decoded[0].UintVal() != 42 {
		t.Fatalf("expected 42, got %v", decoded[0])
	}
}

func TestEdgeCase_TwentyFourElementContainer(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	arr := make([]Value, 24)
	for i := range 24 {
		arr[i] = Uint(uint64(i))
	}

	got, err := enc.Encode(nil, MakeArrayFromSlice(arr))
	if err != nil {
		t.Fatal(err)
	}
	// 24 elements: major type 4 (array) with arg 24 → 0x98 0x18
	if got[0] != 0x98 || got[1] != 0x18 {
		t.Fatalf("expected header 0x98 0x18 for 24 elements, got %x %x", got[0], got[1])
	}

	v, err := dec.Decode(got)
	if err != nil {
		t.Fatal(err)
	}
	decoded := v.Array()
	if len(decoded) != 24 {
		t.Fatalf("expected 24 elements, got %d", len(decoded))
	}
}

func TestEdgeCase_MapWithMixedKeyTypes(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	m := MakeMap(
		MapEntry{Key: Bytes([]byte{0x01}), Value: Uint(4)}, MapEntry{Key: Text("z"), Value: Uint(3)}, MapEntry{Key: Uint(10), Value: Uint(1)}, MapEntry{Key: NegInt(0), Value: Uint(2)},
	)

	encoded, err := enc.Encode(nil, m)
	if err != nil {
		t.Fatal(err)
	}

	// Core deterministic: bytewise-lex sort of encoded keys.
	// Uint(10) → 0x0a (1 byte)
	// NegInt(0) → 0x20 (1 byte)
	// Bytes([01]) → 0x41 0x01 (2 bytes)
	// Text("z") → 0x61 0x7a (2 bytes)
	// Sort order: 0x0a < 0x20 < 0x4101 < 0x617a
	v, err := dec.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoded := v.Map()
	if len(decoded) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(decoded))
	}

	// Verify sort order by re-encoding and comparing.
	reEncoded, err := enc.Encode(nil, MakeMapFromSlice(decoded))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reEncoded) {
		t.Fatalf("re-encoded mismatch:\n  first:  %x\n  second: %x", encoded, reEncoded)
	}
}

func TestEdgeCase_NegIntZero(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	got, err := enc.Encode(nil, NegInt(0))
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x20}; !bytes.Equal(got, want) {
		t.Fatalf("NegInt(0) encoded as %x, want 20", got)
	}

	v, err := dec.Decode([]byte{0x20})
	if err != nil {
		t.Fatal(err)
	}
	if v.Kind != KindNegInt || v.NegIntVal() != 0 {
		t.Fatalf("decode 0x20: got %T(%v), want NegInt(0)", v, v)
	}
}

func TestEdgeCase_NestedTags(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	nested := MakeTag(1, MakeTag(2, MakeTag(3, Uint(99))))

	encoded, err := enc.Encode(nil, nested)
	if err != nil {
		t.Fatal(err)
	}

	v, err := dec.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}

	reEncoded, err := enc.Encode(nil, v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reEncoded) {
		t.Fatalf("nested tags not preserved on round-trip:\n  first:  %x\n  second: %x", encoded, reEncoded)
	}
}

func TestEdgeCase_ZeroBytesVsZeroText(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	emptyBytes, err := enc.Encode(nil, Bytes(nil))
	if err != nil {
		t.Fatal(err)
	}
	emptyText, err := enc.Encode(nil, Text(""))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(emptyBytes, emptyText) {
		t.Fatal("empty bytes and empty text should encode differently")
	}
	if want := []byte{0x40}; !bytes.Equal(emptyBytes, want) {
		t.Fatalf("empty bytes: got %x, want 40", emptyBytes)
	}
	if want := []byte{0x60}; !bytes.Equal(emptyText, want) {
		t.Fatalf("empty text: got %x, want 60", emptyText)
	}

	vb, err := dec.Decode([]byte{0x40})
	if err != nil {
		t.Fatal(err)
	}
	vt, err := dec.Decode([]byte{0x60})
	if err != nil {
		t.Fatal(err)
	}
	if vb.Kind != KindBytes {
		t.Fatalf("0x40 decoded as kind %d, want Bytes", vb.Kind)
	}
	if vt.Kind != KindText {
		t.Fatalf("0x60 decoded as kind %d, want Text", vt.Kind)
	}
}

func TestEdgeCase_Tag24_EncodedCBOR(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	innerEncoded, err := enc.Encode(nil, Uint(42))
	if err != nil {
		t.Fatal(err)
	}

	tag24 := MakeTag(24, Bytes(innerEncoded))
	encoded, err := enc.Encode(nil, tag24)
	if err != nil {
		t.Fatal(err)
	}

	v, err := dec.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}

	reEncoded, err := enc.Encode(nil, v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reEncoded) {
		t.Fatalf("Tag24 round-trip failed:\n  first:  %x\n  second: %x", encoded, reEncoded)
	}
}

func TestEdgeCase_SelfDescribeTag(t *testing.T) {
	dec := NewDecoder()
	enc := New(ModeCoreDeterministic)

	// Tag 55799 wrapping Uint(42): d9d9f7 182a
	// Decoder should strip the self-describe tag.
	wrapped, err := enc.Encode(nil, MakeTag(TagSelfDescribe, Uint(42)))
	if err != nil {
		t.Fatal(err)
	}

	v, err := dec.Decode(wrapped)
	if err != nil {
		t.Fatal(err)
	}

	// Decoder strips 55799, so we should get Uint(42) directly.
	if v.Kind != KindUint {
		t.Fatalf("expected Uint after stripping self-describe, got kind %d", v.Kind)
	}
	u := v.UintVal()
	if u != 42 {
		t.Fatalf("expected 42, got %v", u)
	}

	// Encoder does not add it — encoding Uint(42) should be just 0x182a.
	plain, err := enc.Encode(nil, Uint(42))
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x18, 0x2a}; !bytes.Equal(plain, want) {
		t.Fatalf("encoder should not add self-describe: got %x, want %x", plain, want)
	}
}

func TestEdgeCase_FloatNegativeZero(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	dec := NewDecoder()

	negZero := Float64(math.Copysign(0, -1))
	posZero := Float64(0.0)

	negEncoded, err := enc.Encode(nil, negZero)
	if err != nil {
		t.Fatal(err)
	}
	posEncoded, err := enc.Encode(nil, posZero)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(negEncoded, posEncoded) {
		t.Fatal("-0.0 and +0.0 should encode differently")
	}

	v, err := dec.Decode(negEncoded)
	if err != nil {
		t.Fatal(err)
	}

	reEncoded, err := enc.Encode(nil, v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(negEncoded, reEncoded) {
		t.Fatalf("-0.0 round-trip failed:\n  first:  %x\n  second: %x", negEncoded, reEncoded)
	}
}

func TestEdgeCase_DuplicateMapKeysLastWins(t *testing.T) {
	dec := NewDecoder()

	// Map with two Uint(1) keys: {1: 10, 1: 20} — permissive decoder, last wins.
	// a2 01 0a 01 14 → map(2) key=1 val=10 key=1 val=20
	input := []byte{0xa2, 0x01, 0x0a, 0x01, 0x14}

	v, err := dec.Decode(input)
	if err != nil {
		t.Fatal(err)
	}

	m := v.Map()
	// Decoder deduplicates in-place: 1 entry remains with last value winning.
	if len(m) != 1 {
		t.Fatalf("expected 1 deduplicated entry, got %d", len(m))
	}
	if m[0].Value.UintVal() != 20 {
		t.Fatalf("expected last-wins value 20, got %v", m[0].Value)
	}
}

func TestEdgeCase_AdversarialNesting(t *testing.T) {
	dec := NewDecoder(WithMaxNestingDepth(4))

	// Build deeply nested array: [[[[[ ... ]]]]].
	// 5 levels of nesting → exceeds depth limit of 4.
	input := []byte{0x81, 0x81, 0x81, 0x81, 0x81, 0x00}

	_, err := dec.Decode(input)
	if err == nil {
		t.Fatal("expected error for excessive nesting")
	}
	if !errors.Is(err, ErrMaxNestingDepth) {
		t.Fatalf("expected ErrMaxNestingDepth, got: %v", err)
	}
}

func TestEdgeCase_AdversarialArrayLength(t *testing.T) {
	dec := NewDecoder(WithMaxArrayLength(16))

	// Array declaring 2^64-1 elements: 9b ffffffffffffffff
	input := []byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	_, err := dec.Decode(input)
	if err == nil {
		t.Fatal("expected error for adversarial array length")
	}
	if !errors.Is(err, ErrMaxArrayLength) {
		t.Fatalf("expected ErrMaxArrayLength, got: %v", err)
	}
}

func TestEdgeCase_TruncatedInput(t *testing.T) {
	dec := NewDecoder()

	// 0x18 means "uint, 1-byte arg follows" but no byte follows.
	_, err := dec.Decode([]byte{0x18})
	if err == nil {
		t.Fatal("expected error for truncated input")
	}
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("expected ErrTruncated, got: %v", err)
	}
}

func TestEdgeCase_TrailingBytes(t *testing.T) {
	dec := NewDecoder()

	// Two complete values: Uint(0) Uint(0).
	_, err := dec.Decode([]byte{0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for trailing bytes")
	}
	if !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("expected ErrTrailingBytes, got: %v", err)
	}
}
