// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func TestArenaDecodeArray(t *testing.T) {
	arr := cbor.MakeArray(cbor.Uint(1), cbor.Uint(2), cbor.Uint(3))
	src, _ := Encode(nil, arr, EncodeOpts{})

	arena := NewArena(64, 16)
	v, _, err := Decode(src, DecodeOpts{Arena: arena})
	if err != nil {
		t.Fatal(err)
	}
	items := v.Array()
	if len(items) != 3 {
		t.Fatalf("len = %d, want 3", len(items))
	}
	if items[0].UintVal() != 1 || items[2].UintVal() != 3 {
		t.Fatalf("values wrong: %v", items)
	}
}

func TestArenaDecodeMap(t *testing.T) {
	m := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("a"), Value: cbor.Uint(1)},
		cbor.MapEntry{Key: cbor.Text("b"), Value: cbor.Uint(2)},
	)
	src, _ := Encode(nil, m, EncodeOpts{})

	arena := NewArena(16, 16)
	v, _, err := Decode(src, DecodeOpts{Arena: arena})
	if err != nil {
		t.Fatal(err)
	}
	pairs := v.Map()
	if len(pairs) != 2 {
		t.Fatalf("len = %d, want 2", len(pairs))
	}
}

func TestArenaReset(t *testing.T) {
	arr := cbor.MakeArray(cbor.Uint(10), cbor.Uint(20))
	src, _ := Encode(nil, arr, EncodeOpts{})

	arena := NewArena(64, 16)

	v1, _, err := Decode(src, DecodeOpts{Arena: arena})
	if err != nil {
		t.Fatal(err)
	}
	if v1.Array()[0].UintVal() != 10 {
		t.Fatal("first decode wrong")
	}

	arena.Reset()

	v2, _, err := Decode(src, DecodeOpts{Arena: arena})
	if err != nil {
		t.Fatal(err)
	}
	if v2.Array()[0].UintVal() != 10 {
		t.Fatal("second decode wrong after reset")
	}
}

func TestArenaGrowth(t *testing.T) {
	items := make([]cbor.Value, 200)
	for i := range items {
		items[i] = cbor.Uint(uint64(i))
	}
	src, _ := Encode(nil, cbor.MakeArrayFromSlice(items), EncodeOpts{})

	arena := NewArena(4, 4)
	v, _, err := Decode(src, DecodeOpts{Arena: arena})
	if err != nil {
		t.Fatalf("arena growth failed: %v", err)
	}
	if len(v.Array()) != 200 {
		t.Fatalf("got %d items, want 200", len(v.Array()))
	}
}

func TestArenaNestedContainers(t *testing.T) {
	nested := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("arr"), Value: cbor.MakeArray(cbor.Uint(1), cbor.Uint(2))},
		cbor.MapEntry{Key: cbor.Text("inner"), Value: cbor.MakeMap(
			cbor.MapEntry{Key: cbor.Text("x"), Value: cbor.Uint(99)},
		)},
	)
	src, _ := Encode(nil, nested, EncodeOpts{})

	arena := NewArena(32, 16)
	v, _, err := Decode(src, DecodeOpts{Arena: arena})
	if err != nil {
		t.Fatal(err)
	}
	pairs := v.Map()
	if len(pairs) != 2 {
		t.Fatalf("outer map len = %d", len(pairs))
	}
	innerArr := pairs[0].Value.Array()
	if len(innerArr) != 2 || innerArr[1].UintVal() != 2 {
		t.Fatalf("inner array wrong: %v", innerArr)
	}
}

func BenchmarkDecodeScalarsArena(b *testing.B) {
	items := make([]cbor.Value, 1000)
	for i := range items {
		items[i] = cbor.Uint(uint64(i))
	}
	src, _ := Encode(nil, cbor.MakeArrayFromSlice(items), EncodeOpts{})
	arena := NewArena(1024, 0)
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for range b.N {
		arena.Reset()
		Decode(src, DecodeOpts{Arena: arena}) //nolint:errcheck
	}
}

func BenchmarkDecodeNestedMapArena(b *testing.B) {
	inner := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("x"), Value: cbor.Uint(1)},
		cbor.MapEntry{Key: cbor.Text("y"), Value: cbor.Uint(2)},
	)
	mid := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("alpha"), Value: inner},
		cbor.MapEntry{Key: cbor.Text("beta"), Value: inner},
		cbor.MapEntry{Key: cbor.Text("gamma"), Value: cbor.MakeArray(cbor.Uint(1), cbor.Uint(2), cbor.Uint(3))},
	)
	outer := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("level1a"), Value: mid},
		cbor.MapEntry{Key: cbor.Text("level1b"), Value: mid},
		cbor.MapEntry{Key: cbor.Text("level1c"), Value: cbor.Bytes([]byte{0xde, 0xad, 0xbe, 0xef})},
	)
	src, _ := Encode(nil, outer, EncodeOpts{})
	arena := NewArena(64, 32)
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for range b.N {
		arena.Reset()
		Decode(src, DecodeOpts{Arena: arena}) //nolint:errcheck
	}
}
