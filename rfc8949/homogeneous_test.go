// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func TestDecodeUintArray(t *testing.T) {
	arr := cbor.MakeArray(cbor.Uint(0), cbor.Uint(100), cbor.Uint(65536), cbor.Uint(0xffffffff))
	src, _ := Encode(nil, arr, EncodeOpts{})
	result, n, err := DecodeUintArray(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	expected := []uint64{0, 100, 65536, 0xffffffff}
	for i, v := range result {
		if v != expected[i] {
			t.Fatalf("result[%d] = %d, want %d", i, v, expected[i])
		}
	}
}

func TestDecodeUintArrayRejectsNonUint(t *testing.T) {
	arr := cbor.MakeArray(cbor.Uint(1), cbor.Text("oops"), cbor.Uint(3))
	src, _ := Encode(nil, arr, EncodeOpts{})
	_, _, err := DecodeUintArray(src, DecodeOpts{})
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("expected ErrTypeMismatch, got: %v", err)
	}
}

func TestDecodeFloat64Array(t *testing.T) {
	arr := cbor.MakeArray(cbor.Float64(1.5), cbor.Float64(2.7), cbor.Float32(3.0))
	src, _ := Encode(nil, arr, EncodeOpts{})
	result, _, err := DecodeFloat64Array(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 3 {
		t.Fatalf("len = %d, want 3", len(result))
	}
	if result[0] != 1.5 || result[2] != 3.0 {
		t.Fatalf("unexpected values: %v", result)
	}
}

func TestDecodeTextArray(t *testing.T) {
	arr := cbor.MakeArray(cbor.Text("hello"), cbor.Text("world"))
	src, _ := Encode(nil, arr, EncodeOpts{})
	result, _, err := DecodeTextArray(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if result[0] != "hello" || result[1] != "world" {
		t.Fatalf("unexpected: %v", result)
	}
}

func buildUintArrayCBOR(n int) []byte {
	arr := make([]cbor.Value, n)
	for i := range n {
		arr[i] = cbor.Uint(uint64(i))
	}
	src, _ := Encode(nil, cbor.MakeArrayFromSlice(arr), EncodeOpts{})
	return src
}

func BenchmarkDecodeUintArray(b *testing.B) {
	src := buildUintArrayCBOR(1000)
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for range b.N {
		DecodeUintArray(src, DecodeOpts{}) //nolint:errcheck
	}
}

func BenchmarkDecodeGenericScalars(b *testing.B) {
	src := buildUintArrayCBOR(1000)
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for range b.N {
		Decode(src, DecodeOpts{}) //nolint:errcheck
	}
}
