// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"fmt"
	"testing"
)

func buildScalarArray() Value {
	arr := make([]Value, 1000)
	for i := range arr {
		arr[i] = Uint(uint64(i))
	}
	return MakeArrayFromSlice(arr)
}

func buildNestedMap() Value {
	inner := MakeMap(
		MapEntry{Key: Text("x"), Value: Uint(1)},
		MapEntry{Key: Text("y"), Value: Uint(2)},
	)
	mid := MakeMap(
		MapEntry{Key: Text("alpha"), Value: inner},
		MapEntry{Key: Text("beta"), Value: inner},
		MapEntry{Key: Text("gamma"), Value: MakeArray(Uint(1), Uint(2), Uint(3))},
	)
	outer := MakeMap(
		MapEntry{Key: Text("level1a"), Value: mid},
		MapEntry{Key: Text("level1b"), Value: mid},
		MapEntry{Key: Text("level1c"), Value: Bytes([]byte{0xde, 0xad, 0xbe, 0xef})},
	)
	return outer
}

func BenchmarkEncodeScalars(b *testing.B) {
	enc := New(ModeCoreDeterministic)
	v := buildScalarArray()
	buf, _ := enc.Encode(nil, v)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for range b.N {
		enc.Encode(buf[:0], v) //nolint:errcheck
	}
}

func BenchmarkEncodeNestedMap(b *testing.B) {
	enc := New(ModeCoreDeterministic)
	v := buildNestedMap()
	buf, _ := enc.Encode(nil, v)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for range b.N {
		enc.Encode(buf[:0], v) //nolint:errcheck
	}
}

func BenchmarkDecodeScalars(b *testing.B) {
	enc := New(ModeCoreDeterministic)
	v := buildScalarArray()
	data, _ := enc.Encode(nil, v)
	b.SetBytes(int64(len(data)))
	dec := NewDecoder()
	b.ResetTimer()
	for range b.N {
		dec.Decode(data) //nolint:errcheck
	}
}

func BenchmarkDecodeNestedMapStrict(b *testing.B) {
	enc := New(ModeCoreDeterministic)
	v := buildNestedMap()
	data, _ := enc.Encode(nil, v)
	b.SetBytes(int64(len(data)))
	dec := StrictDecoder()
	b.ResetTimer()
	for range b.N {
		dec.Decode(data) //nolint:errcheck
	}
}

func buildLargeMap(n int) Value {
	m := make([]MapEntry, n)
	for i := range n {
		m[i] = MapEntry{
			Key:   Text(fmt.Sprintf("key-%04d", i)),
			Value: Uint(uint64(i)),
		}
	}
	return MakeMapFromSlice(m)
}

func BenchmarkDecodeStrictLargeMap100(b *testing.B) {
	enc := New(ModeCoreDeterministic)
	v := buildLargeMap(100)
	data, _ := enc.Encode(nil, v)
	b.SetBytes(int64(len(data)))
	dec := StrictDecoder()
	b.ResetTimer()
	for range b.N {
		dec.Decode(data) //nolint:errcheck
	}
}

func BenchmarkDecodeStrictLargeMap1000(b *testing.B) {
	enc := New(ModeCoreDeterministic)
	v := buildLargeMap(1000)
	data, _ := enc.Encode(nil, v)
	b.SetBytes(int64(len(data)))
	dec := StrictDecoder()
	b.ResetTimer()
	for range b.N {
		dec.Decode(data) //nolint:errcheck
	}
}

func TestWithoutInternalArena(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	v := MakeArray(Uint(1), Uint(2), Text("hello"))
	data, _ := enc.Encode(nil, v)

	dec := NewDecoder(WithoutInternalArena())
	got, err := dec.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(got.Items))
	}
	if got.Items[2].Str != "hello" {
		t.Fatalf("expected hello, got %q", got.Items[2].Str)
	}
}

func TestInternalArenaResetBetweenCalls(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	data1, _ := enc.Encode(nil, MakeArray(Uint(1), Uint(2)))
	data2, _ := enc.Encode(nil, MakeArray(Uint(3), Uint(4)))

	dec := NewDecoder()

	v1, err := dec.Decode(data1)
	if err != nil {
		t.Fatal(err)
	}
	if v1.Items[0].Num != 1 {
		t.Fatalf("v1[0] = %d, want 1", v1.Items[0].Num)
	}

	v2, err := dec.Decode(data2)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Items[0].Num != 3 {
		t.Fatalf("v2[0] = %d, want 3", v2.Items[0].Num)
	}
	if v2.Items[1].Num != 4 {
		t.Fatalf("v2[1] = %d, want 4", v2.Items[1].Num)
	}
}

func TestClonePreservesValueAcrossDecodes(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	data1, _ := enc.Encode(nil, MakeArray(Text("persist"), Uint(99)))
	data2, _ := enc.Encode(nil, MakeArray(Text("other"), Uint(0)))

	dec := NewDecoder()

	v1, err := dec.Decode(data1)
	if err != nil {
		t.Fatal(err)
	}
	cloned := v1.Clone()

	_, err = dec.Decode(data2)
	if err != nil {
		t.Fatal(err)
	}

	if cloned.Items[0].Str != "persist" {
		t.Fatalf("cloned[0] = %q, want persist", cloned.Items[0].Str)
	}
	if cloned.Items[1].Num != 99 {
		t.Fatalf("cloned[1] = %d, want 99", cloned.Items[1].Num)
	}
}
