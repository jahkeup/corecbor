// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func TestZeroCopyBytes(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
	src, _ := Encode(nil, cbor.Bytes(payload), EncodeOpts{})

	v, _, err := Decode(src, DecodeOpts{ZeroCopy: true})
	if err != nil {
		t.Fatal(err)
	}
	got := v.BytesVal()
	if len(got) != len(payload) {
		t.Fatalf("len = %d, want %d", len(got), len(payload))
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("byte %d: got %02x, want %02x", i, got[i], payload[i])
		}
	}
}

func TestZeroCopyBytesAliasesSrc(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	src, _ := Encode(nil, cbor.Bytes(payload), EncodeOpts{})

	v, _, _ := Decode(src, DecodeOpts{ZeroCopy: true})
	got := v.BytesVal()

	src[len(src)-1] = 0xFF
	if got[len(got)-1] != 0xFF {
		t.Fatal("zero-copy bytes should alias src — mutation not visible")
	}
}

func TestZeroCopyText(t *testing.T) {
	src, _ := Encode(nil, cbor.Text("hello world"), EncodeOpts{})

	v, _, err := Decode(src, DecodeOpts{ZeroCopy: true})
	if err != nil {
		t.Fatal(err)
	}
	if v.TextVal() != "hello world" {
		t.Fatalf("got %q, want %q", v.TextVal(), "hello world")
	}
}

func TestZeroCopyTextAliasesSrc(t *testing.T) {
	src, _ := Encode(nil, cbor.Text("abc"), EncodeOpts{})

	v, _, _ := Decode(src, DecodeOpts{ZeroCopy: true})
	s := v.TextVal()

	src[len(src)-1] = 'Z'
	if s[len(s)-1] != 'Z' {
		t.Fatal("zero-copy text should alias src — mutation not visible")
	}
}

func TestZeroCopyWithArena(t *testing.T) {
	arr := cbor.MakeArray(
		cbor.Bytes([]byte{0x01}),
		cbor.Text("key"),
		cbor.Uint(42),
	)
	src, _ := Encode(nil, arr, EncodeOpts{})

	arena := NewArena(16, 0)
	v, _, err := Decode(src, DecodeOpts{ZeroCopy: true, Arena: arena})
	if err != nil {
		t.Fatal(err)
	}
	items := v.Array()
	if len(items) != 3 {
		t.Fatalf("len = %d", len(items))
	}
	if items[1].TextVal() != "key" {
		t.Fatalf("text = %q", items[1].TextVal())
	}
}

func TestNonZeroCopyBytes(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	src, _ := Encode(nil, cbor.Bytes(payload), EncodeOpts{})

	v, _, _ := Decode(src, DecodeOpts{ZeroCopy: false})
	got := v.BytesVal()

	src[len(src)-1] = 0xFF
	if got[len(got)-1] == 0xFF {
		t.Fatal("non-zero-copy should be independent of src")
	}
}

func BenchmarkDecodeZeroCopy(b *testing.B) {
	m := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("name"), Value: cbor.Text("alice")},
		cbor.MapEntry{Key: cbor.Text("data"), Value: cbor.Bytes(make([]byte, 64))},
		cbor.MapEntry{Key: cbor.Text("id"), Value: cbor.Uint(12345)},
	)
	src, _ := Encode(nil, m, EncodeOpts{})
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for range b.N {
		Decode(src, DecodeOpts{ZeroCopy: true}) //nolint:errcheck
	}
}

func BenchmarkDecodeZeroCopyArena(b *testing.B) {
	m := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("name"), Value: cbor.Text("alice")},
		cbor.MapEntry{Key: cbor.Text("data"), Value: cbor.Bytes(make([]byte, 64))},
		cbor.MapEntry{Key: cbor.Text("id"), Value: cbor.Uint(12345)},
	)
	src, _ := Encode(nil, m, EncodeOpts{})
	arena := NewArena(16, 8)
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for range b.N {
		arena.Reset()
		Decode(src, DecodeOpts{ZeroCopy: true, Arena: arena}) //nolint:errcheck
	}
}

func BenchmarkDecodeDefault(b *testing.B) {
	m := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("name"), Value: cbor.Text("alice")},
		cbor.MapEntry{Key: cbor.Text("data"), Value: cbor.Bytes(make([]byte, 64))},
		cbor.MapEntry{Key: cbor.Text("id"), Value: cbor.Uint(12345)},
	)
	src, _ := Encode(nil, m, EncodeOpts{})
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for range b.N {
		Decode(src, DecodeOpts{}) //nolint:errcheck
	}
}
