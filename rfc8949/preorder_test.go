// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"bytes"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func TestPrecomputeMapOrderEquivalence(t *testing.T) {
	m := []cbor.MapEntry{
		{Key: cbor.Text("zebra"), Value: cbor.Uint(1)},
		{Key: cbor.Text("alpha"), Value: cbor.Uint(2)},
		{Key: cbor.Text("middle"), Value: cbor.Uint(3)},
	}
	keys := []cbor.Value{cbor.Text("zebra"), cbor.Text("alpha"), cbor.Text("middle")}
	opts := EncodeOpts{Deterministic: true, SortMode: SortBytewiseLex}

	order, err := PrecomputeMapOrder(keys, SortBytewiseLex, opts)
	if err != nil {
		t.Fatal(err)
	}

	preordered, err := EncodeMapPreordered(nil, m, order, opts)
	if err != nil {
		t.Fatalf("preordered encode: %v", err)
	}

	standard, err := Encode(nil, cbor.MakeMapFromSlice(m), opts)
	if err != nil {
		t.Fatalf("standard encode: %v", err)
	}

	if !bytes.Equal(preordered, standard) {
		t.Errorf("output mismatch:\n  preordered: %x\n  standard:   %x", preordered, standard)
	}
}

func TestPrecomputeMapOrderLengthFirst(t *testing.T) {
	m := []cbor.MapEntry{
		{Key: cbor.Text("bb"), Value: cbor.Uint(1)},
		{Key: cbor.Text("a"), Value: cbor.Uint(2)},
		{Key: cbor.Text("ccc"), Value: cbor.Uint(3)},
	}
	keys := []cbor.Value{cbor.Text("bb"), cbor.Text("a"), cbor.Text("ccc")}
	opts := EncodeOpts{Deterministic: true, SortMode: SortLengthFirst}

	order, err := PrecomputeMapOrder(keys, SortLengthFirst, opts)
	if err != nil {
		t.Fatal(err)
	}

	preordered, err := EncodeMapPreordered(nil, m, order, opts)
	if err != nil {
		t.Fatalf("preordered encode: %v", err)
	}

	standard, err := Encode(nil, cbor.MakeMapFromSlice(m), opts)
	if err != nil {
		t.Fatalf("standard encode: %v", err)
	}

	if !bytes.Equal(preordered, standard) {
		t.Errorf("length-first mismatch:\n  preordered: %x\n  standard:   %x", preordered, standard)
	}
}

func TestPrecomputeMapOrderMixedKeyTypes(t *testing.T) {
	m := []cbor.MapEntry{
		{Key: cbor.Uint(10), Value: cbor.Text("ten")},
		{Key: cbor.Text("z"), Value: cbor.Text("zed")},
		{Key: cbor.Uint(1), Value: cbor.Text("one")},
		{Key: cbor.Bytes([]byte{0xff}), Value: cbor.Text("ff")},
	}
	keys := []cbor.Value{cbor.Uint(10), cbor.Text("z"), cbor.Uint(1), cbor.Bytes([]byte{0xff})}
	opts := EncodeOpts{Deterministic: true, SortMode: SortBytewiseLex}

	order, err := PrecomputeMapOrder(keys, SortBytewiseLex, opts)
	if err != nil {
		t.Fatal(err)
	}

	preordered, err := EncodeMapPreordered(nil, m, order, opts)
	if err != nil {
		t.Fatalf("preordered encode: %v", err)
	}

	standard, err := Encode(nil, cbor.MakeMapFromSlice(m), opts)
	if err != nil {
		t.Fatalf("standard encode: %v", err)
	}

	if !bytes.Equal(preordered, standard) {
		t.Errorf("mixed-type mismatch:\n  preordered: %x\n  standard:   %x", preordered, standard)
	}
}

func TestPrecomputeMapOrderSingleKey(t *testing.T) {
	m := []cbor.MapEntry{{Key: cbor.Text("only"), Value: cbor.Uint(42)}}
	keys := []cbor.Value{cbor.Text("only")}
	opts := EncodeOpts{Deterministic: true}

	order, err := PrecomputeMapOrder(keys, SortBytewiseLex, opts)
	if err != nil {
		t.Fatal(err)
	}

	preordered, err := EncodeMapPreordered(nil, m, order, opts)
	if err != nil {
		t.Fatal(err)
	}

	standard, err := Encode(nil, cbor.MakeMapFromSlice(m), opts)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(preordered, standard) {
		t.Errorf("single-key mismatch:\n  preordered: %x\n  standard:   %x", preordered, standard)
	}
}

func TestPrecomputeMapOrderEmpty(t *testing.T) {
	m := []cbor.MapEntry{}
	order, err := PrecomputeMapOrder(nil, SortBytewiseLex, EncodeOpts{Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}

	preordered, err := EncodeMapPreordered(nil, m, order, EncodeOpts{Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}

	standard, err := Encode(nil, cbor.MakeMap(), EncodeOpts{Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(preordered, standard) {
		t.Errorf("empty mismatch:\n  preordered: %x\n  standard:   %x", preordered, standard)
	}
}

func BenchmarkEncodeMapPreordered(b *testing.B) {
	m := []cbor.MapEntry{
		{Key: cbor.Text("alg"), Value: cbor.NegInt(6)},
		{Key: cbor.Text("kid"), Value: cbor.Bytes([]byte{0x01, 0x02, 0x03, 0x04})},
		{Key: cbor.Text("iv"), Value: cbor.Bytes(make([]byte, 12))},
	}
	keys := []cbor.Value{cbor.Text("alg"), cbor.Text("kid"), cbor.Text("iv")}
	opts := EncodeOpts{Deterministic: true, SortMode: SortBytewiseLex}

	order, err := PrecomputeMapOrder(keys, SortBytewiseLex, opts)
	if err != nil {
		b.Fatal(err)
	}

	buf, _ := EncodeMapPreordered(nil, m, order, opts)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for range b.N {
		EncodeMapPreordered(buf[:0], m, order, opts) //nolint:errcheck
	}
}

func BenchmarkEncodeMapDeterministic(b *testing.B) {
	m := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("alg"), Value: cbor.NegInt(6)},
		cbor.MapEntry{Key: cbor.Text("kid"), Value: cbor.Bytes([]byte{0x01, 0x02, 0x03, 0x04})},
		cbor.MapEntry{Key: cbor.Text("iv"), Value: cbor.Bytes(make([]byte, 12))},
	)
	opts := EncodeOpts{Deterministic: true, SortMode: SortBytewiseLex}

	buf, _ := Encode(nil, m, opts)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for range b.N {
		Encode(buf[:0], m, opts) //nolint:errcheck
	}
}
