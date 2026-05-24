// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func encodeCBOR(t *testing.T, v cbor.Value) []byte {
	t.Helper()
	b, err := Encode(nil, v, EncodeOpts{})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

func TestCursorSkipScalars(t *testing.T) {
	values := []cbor.Value{
		cbor.Uint(0), cbor.Uint(1000), cbor.Uint(0xffffffff),
		cbor.NegInt(0), cbor.NegInt(255),
		cbor.Bytes{0x01, 0x02, 0x03},
		cbor.Text("hello"),
		cbor.Bool(true), cbor.Bool(false),
		cbor.Null{}, cbor.Undefined{},
		cbor.Float32(1.5), cbor.Float64(3.14),
		cbor.Simple(16),
	}
	for _, v := range values {
		src := encodeCBOR(t, v)
		c := NewCursor(src, DecodeOpts{})
		n, err := c.Skip()
		if err != nil {
			t.Fatalf("Skip(%T): %v", v, err)
		}
		if n != len(src) {
			t.Fatalf("Skip(%T) consumed %d, want %d", v, n, len(src))
		}
	}
}

func TestCursorSkipContainers(t *testing.T) {
	values := []cbor.Value{
		cbor.Array{cbor.Uint(1), cbor.Uint(2), cbor.Uint(3)},
		cbor.Map{
			{Key: cbor.Text("a"), Value: cbor.Uint(1)},
			{Key: cbor.Text("b"), Value: cbor.Uint(2)},
		},
		cbor.Tag{ID: 1, Inner: cbor.Uint(42)},
		cbor.Array{cbor.Array{cbor.Uint(1)}, cbor.Map{{Key: cbor.Uint(0), Value: cbor.Null{}}}},
	}
	for _, v := range values {
		src := encodeCBOR(t, v)
		c := NewCursor(src, DecodeOpts{})
		n, err := c.Skip()
		if err != nil {
			t.Fatalf("Skip(%T): %v", v, err)
		}
		if n != len(src) {
			t.Fatalf("Skip(%T) consumed %d, want %d", v, n, len(src))
		}
	}
}

func TestCursorRawBytes(t *testing.T) {
	v := cbor.Map{
		{Key: cbor.Text("x"), Value: cbor.Uint(1)},
		{Key: cbor.Text("y"), Value: cbor.Uint(2)},
	}
	src := encodeCBOR(t, v)
	c := NewCursor(src, DecodeOpts{})
	raw, err := c.RawBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != len(src) {
		t.Fatalf("RawBytes len %d, want %d", len(raw), len(src))
	}
}

func TestCursorEnterArrayExitArray(t *testing.T) {
	arr := cbor.Array{cbor.Uint(10), cbor.Uint(20), cbor.Uint(30)}
	src := encodeCBOR(t, arr)
	c := NewCursor(src, DecodeOpts{})

	count, err := c.EnterArray()
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("count = %d, want 3", count)
	}

	v, err := c.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if v != cbor.Uint(10) {
		t.Fatalf("first = %v, want Uint(10)", v)
	}

	err = c.ExitArray()
	if err != nil {
		t.Fatal(err)
	}

	if c.Offset() != len(src) {
		t.Fatalf("after exit: offset = %d, want %d", c.Offset(), len(src))
	}
}

func TestCursorEnterMapFindKey(t *testing.T) {
	m := cbor.Map{
		{Key: cbor.Text("id"), Value: cbor.Uint(42)},
		{Key: cbor.Text("name"), Value: cbor.Text("alice")},
		{Key: cbor.Text("score"), Value: cbor.Float64(99.5)},
	}
	src := encodeCBOR(t, m)
	c := NewCursor(src, DecodeOpts{})

	_, err := c.EnterMap()
	if err != nil {
		t.Fatal(err)
	}

	err = c.FindMapKey("name")
	if err != nil {
		t.Fatal(err)
	}

	v, err := c.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if v != cbor.Text("alice") {
		t.Fatalf("name value = %v, want Text(alice)", v)
	}

	err = c.ExitMap()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCursorFindMapKeyNotFound(t *testing.T) {
	m := cbor.Map{
		{Key: cbor.Text("a"), Value: cbor.Uint(1)},
		{Key: cbor.Text("b"), Value: cbor.Uint(2)},
	}
	src := encodeCBOR(t, m)
	c := NewCursor(src, DecodeOpts{})
	c.EnterMap()

	err := c.FindMapKey("z")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestCursorNestedAccess(t *testing.T) {
	outer := cbor.Map{
		{Key: cbor.Text("header"), Value: cbor.Map{
			{Key: cbor.Text("alg"), Value: cbor.NegInt(6)},
			{Key: cbor.Text("kid"), Value: cbor.Bytes{0x01}},
		}},
		{Key: cbor.Text("payload"), Value: cbor.Bytes(make([]byte, 100))},
	}
	src := encodeCBOR(t, outer)
	c := NewCursor(src, DecodeOpts{})

	c.EnterMap()
	c.FindMapKey("header")
	c.EnterMap()
	c.FindMapKey("alg")
	v, err := c.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if v != cbor.NegInt(6) {
		t.Fatalf("alg = %v, want NegInt(6)", v)
	}
	c.ExitMap()
	c.ExitMap()

	if c.Offset() != len(src) {
		t.Fatalf("after nested exit: offset = %d, want %d", c.Offset(), len(src))
	}
}

func TestCursorExitWithoutEnter(t *testing.T) {
	src := encodeCBOR(t, cbor.Uint(1))
	c := NewCursor(src, DecodeOpts{})
	err := c.ExitArray()
	if !errors.Is(err, ErrNotInContainer) {
		t.Fatalf("expected ErrNotInContainer, got: %v", err)
	}
}

func TestCursorKind(t *testing.T) {
	src := encodeCBOR(t, cbor.Text("hello"))
	c := NewCursor(src, DecodeOpts{})
	kind, err := c.Kind()
	if err != nil {
		t.Fatal(err)
	}
	if kind != 0x60 {
		t.Fatalf("kind = %02x, want 0x60 (text)", kind)
	}
}

func buildLargeCBOR(n int) []byte {
	m := make(cbor.Map, n)
	for i := range n {
		m[i] = cbor.MapEntry{
			Key:   cbor.Text(fmt.Sprintf("key-%04d", i)),
			Value: cbor.Bytes(make([]byte, 100)),
		}
	}
	src, _ := Encode(nil, m, EncodeOpts{})
	return src
}

func BenchmarkCursorSkipLarge(b *testing.B) {
	src := buildLargeCBOR(1000)
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for range b.N {
		c := NewCursor(src, DecodeOpts{})
		c.Skip() //nolint:errcheck
	}
}

func BenchmarkCursorFindMapKey(b *testing.B) {
	src := buildLargeCBOR(50)
	b.ResetTimer()
	for range b.N {
		c := NewCursor(src, DecodeOpts{})
		c.EnterMap()              //nolint:errcheck
		c.FindMapKey("key-0025") //nolint:errcheck
		c.Decode()               //nolint:errcheck
	}
}

func BenchmarkCursorFindMapKeyLast(b *testing.B) {
	src := buildLargeCBOR(50)
	b.ResetTimer()
	for range b.N {
		c := NewCursor(src, DecodeOpts{})
		c.EnterMap()              //nolint:errcheck
		c.FindMapKey("key-0049") //nolint:errcheck
		c.Decode()               //nolint:errcheck
	}
}
