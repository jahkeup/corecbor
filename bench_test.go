// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import "testing"

func buildScalarArray() Value {
	arr := make([]Value, 1000)
	for i := range arr {
		arr[i] = Uint(uint64(i))
	}
	return MakeArray(arr...)
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
