package corecbor

import "testing"

func buildScalarArray() Value {
	arr := make(Array, 1000)
	for i := range arr {
		arr[i] = Uint(uint64(i))
	}
	return arr
}

func buildNestedMap() Value {
	inner := Map{
		{Text("x"), Uint(1)},
		{Text("y"), Uint(2)},
	}
	mid := Map{
		{Text("alpha"), inner},
		{Text("beta"), inner},
		{Text("gamma"), Array{Uint(1), Uint(2), Uint(3)}},
	}
	outer := Map{
		{Text("level1a"), mid},
		{Text("level1b"), mid},
		{Text("level1c"), Bytes([]byte{0xde, 0xad, 0xbe, 0xef})},
	}
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
