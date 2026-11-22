// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Default-path benchmark coverage (proposal 036 item 17). Each benchmark
// uses only default options, so a regression on a path real callers hit
// without opting in to anything shows up here.

func mustEncode(b *testing.B, mode Mode, v Value) []byte {
	b.Helper()
	data, err := New(mode).Encode(nil, v)
	if err != nil {
		b.Fatal(err)
	}
	return data
}

func benchDecode(b *testing.B, data []byte) {
	b.Helper()
	dec := NewDecoder()
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := dec.Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}

func benchEncode(b *testing.B, mode Mode, v Value) {
	b.Helper()
	enc := New(mode)
	buf, err := enc.Encode(nil, v)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := enc.Encode(buf[:0], v); err != nil {
			b.Fatal(err)
		}
	}
}

// --- forgiving decode ---

func BenchmarkDecodeForgivingLargeMap100(b *testing.B) {
	benchDecode(b, mustEncode(b, ModeCoreDeterministic, buildLargeMap(100)))
}

func BenchmarkDecodeForgivingLargeMap1000(b *testing.B) {
	benchDecode(b, mustEncode(b, ModeCoreDeterministic, buildLargeMap(1000)))
}

func BenchmarkDecodeNestedMapForgiving(b *testing.B) {
	benchDecode(b, mustEncode(b, ModeCoreDeterministic, buildNestedMap()))
}

func buildLongStrings(n, size int, asBytes bool) Value {
	items := make([]Value, n)
	for i := range items {
		s := strings.Repeat(string(rune('a'+i%26)), size)
		if asBytes {
			items[i] = Bytes([]byte(s))
		} else {
			items[i] = Text(s)
		}
	}
	return MakeArrayFromSlice(items)
}

func BenchmarkDecodeLongText(b *testing.B) {
	benchDecode(b, mustEncode(b, ModeCoreDeterministic, buildLongStrings(64, 256, false)))
}

func BenchmarkDecodeLongBytes(b *testing.B) {
	benchDecode(b, mustEncode(b, ModeCoreDeterministic, buildLongStrings(64, 256, true)))
}

func buildTagged() Value {
	items := make([]Value, 0, 300)
	for i := range 100 {
		items = append(items,
			TimeTo(time.Unix(int64(1_700_000_000+i), 0)),
			BigIntTo(new(big.Int).Lsh(big.NewInt(int64(i+1)), 80)),
			MakeTag(TagEncodedCBOR, Bytes([]byte{0x82, 0x01, 0x02})),
		)
	}
	return MakeArrayFromSlice(items)
}

func BenchmarkDecodeTags(b *testing.B) {
	benchDecode(b, mustEncode(b, ModeCoreDeterministic, buildTagged()))
}

func buildMixedArray() Value {
	items := make([]Value, 1000)
	for i := range items {
		switch i % 6 {
		case 0:
			items[i] = Uint(uint64(i) * 1000)
		case 1:
			items[i] = NegInt(uint64(i))
		case 2:
			items[i] = Float64(float64(i) + 0.5)
		case 3:
			items[i] = Text("t")
		case 4:
			items[i] = Bool(i%2 == 0)
		default:
			items[i] = Null()
		}
	}
	return MakeArrayFromSlice(items)
}

func BenchmarkDecodeMixedArray(b *testing.B) {
	benchDecode(b, mustEncode(b, ModeCoreDeterministic, buildMixedArray()))
}

// --- encode ---

func BenchmarkEncodeNestedMapPermissive(b *testing.B) {
	benchEncode(b, ModePermissive, buildNestedMap())
}

func BenchmarkEncodeLargeMap100Deterministic(b *testing.B) {
	benchEncode(b, ModeCoreDeterministic, buildLargeMap(100))
}

func BenchmarkEncodeLargeMap100Permissive(b *testing.B) {
	benchEncode(b, ModePermissive, buildLargeMap(100))
}

func BenchmarkEncodeMixedArray(b *testing.B) {
	benchEncode(b, ModeCoreDeterministic, buildMixedArray())
}

func BenchmarkEncodeTo(b *testing.B) {
	enc := New(ModeCoreDeterministic)
	v := buildNestedMap()
	b.ReportAllocs()
	for b.Loop() {
		if err := enc.EncodeTo(io.Discard, v); err != nil {
			b.Fatal(err)
		}
	}
}

// --- reflection ---

func stringIntMap(n int) map[string]int {
	m := make(map[string]int, n)
	for i := range n {
		m[fmt.Sprintf("field-%02d", i)] = i
	}
	return m
}

func BenchmarkMarshalMap(b *testing.B) {
	m := stringIntMap(50)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Marshal(m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshalMap(b *testing.B) {
	data, err := Marshal(stringIntMap(50))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		var m map[string]int
		if err := Unmarshal(data, &m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshalAny(b *testing.B) {
	data := mustEncode(b, ModeCoreDeterministic, buildNestedMap())
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		var v any
		if err := Unmarshal(data, &v); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshalSlice(b *testing.B) {
	data := mustEncode(b, ModeCoreDeterministic, buildScalarArray())
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		var s []uint64
		if err := Unmarshal(data, &s); err != nil {
			b.Fatal(err)
		}
	}
}

// --- streaming ---

func BenchmarkDecodeFrom(b *testing.B) {
	data := mustEncode(b, ModeCoreDeterministic, buildNestedMap())
	dec := NewDecoder()
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := dec.DecodeFrom(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamDecodeSequence(b *testing.B) {
	item := mustEncode(b, ModeCoreDeterministic, buildNestedMap())
	seq := bytes.Repeat(item, 100)
	dec := NewDecoder()
	b.SetBytes(int64(len(seq)))
	b.ReportAllocs()
	for b.Loop() {
		s := dec.Stream(bytes.NewReader(seq))
		n := 0
		for s.Next() {
			n++
		}
		if err := s.Err(); err != nil || n != 100 {
			b.Fatalf("n=%d err=%v", n, err)
		}
	}
}
