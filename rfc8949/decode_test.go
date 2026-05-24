// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/wire"
)

func mustEncode(t *testing.T, v cbor.Value) []byte {
	t.Helper()
	b, err := Encode(nil, v, EncodeOpts{})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

func TestDecodeUint(t *testing.T) {
	tests := []struct {
		name string
		val  uint64
	}{
		{"zero", 0}, {"one", 1}, {"23", 23}, {"24", 24},
		{"255", 255}, {"256", 256}, {"65535", 65535}, {"65536", 65536},
		{"max32", 0xffffffff}, {"max64", math.MaxUint64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := mustEncode(t, cbor.Uint(tt.val))
			got, n, err := Decode(src, DecodeOpts{})
			if err != nil {
				t.Fatal(err)
			}
			if n != len(src) {
				t.Fatalf("consumed %d, want %d", n, len(src))
			}
			if got.Kind() != cbor.KindUint || got.UintVal() != tt.val {
				t.Fatalf("got %v, want Uint(%d)", got, tt.val)
			}
		})
	}
}

func TestDecodeNegInt(t *testing.T) {
	tests := []struct {
		name string
		val  uint64
	}{
		{"neg1", 0}, {"neg24", 23}, {"neg25", 24},
		{"neg256", 255}, {"neg65536", 65535}, {"max", math.MaxUint64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := mustEncode(t, cbor.NegInt(tt.val))
			got, n, err := Decode(src, DecodeOpts{})
			if err != nil {
				t.Fatal(err)
			}
			if n != len(src) {
				t.Fatalf("consumed %d, want %d", n, len(src))
			}
			if got.Kind() != cbor.KindNegInt || got.NegIntVal() != tt.val {
				t.Fatalf("got %v, want NegInt(%d)", got, tt.val)
			}
		})
	}
}

func TestDecodeBytes(t *testing.T) {
	tests := []struct {
		name string
		val  []byte
	}{
		{"empty", []byte{}},
		{"one", []byte{0x42}},
		{"multi", []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := mustEncode(t, cbor.Bytes(tt.val))
			got, n, err := Decode(src, DecodeOpts{})
			if err != nil {
				t.Fatal(err)
			}
			if n != len(src) {
				t.Fatalf("consumed %d, want %d", n, len(src))
			}
			if got.Kind() != cbor.KindBytes {
				t.Fatalf("kind = %d, want KindBytes", got.Kind())
			}
			gb := got.BytesVal()
			if len(gb) != len(tt.val) {
				t.Fatalf("len got %d, want %d", len(gb), len(tt.val))
			}
			for i := range gb {
				if gb[i] != tt.val[i] {
					t.Fatalf("byte %d: got %x, want %x", i, gb[i], tt.val[i])
				}
			}
		})
	}
}

func TestDecodeText(t *testing.T) {
	tests := []struct {
		name string
		val  string
	}{
		{"empty", ""}, {"hello", "hello"}, {"unicode", "日本語"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := mustEncode(t, cbor.Text(tt.val))
			got, n, err := Decode(src, DecodeOpts{})
			if err != nil {
				t.Fatal(err)
			}
			if n != len(src) {
				t.Fatalf("consumed %d, want %d", n, len(src))
			}
			if got.Kind() != cbor.KindText || got.TextVal() != tt.val {
				t.Fatalf("got %v, want Text(%q)", got, tt.val)
			}
		})
	}
}

func TestDecodeArray(t *testing.T) {
	tests := []struct {
		name string
		val  cbor.Value
		len  int
	}{
		{"empty", cbor.MakeArray(), 0},
		{"one", cbor.MakeArray(cbor.Uint(1)), 1},
		{"mixed", cbor.MakeArray(cbor.Uint(1), cbor.Text("two"), cbor.Bool(true)), 3},
		{"nested", cbor.MakeArray(cbor.MakeArray(cbor.Uint(1), cbor.Uint(2))), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := mustEncode(t, tt.val)
			got, n, err := Decode(src, DecodeOpts{})
			if err != nil {
				t.Fatal(err)
			}
			if n != len(src) {
				t.Fatalf("consumed %d, want %d", n, len(src))
			}
			if got.Kind() != cbor.KindArray {
				t.Fatalf("kind = %d, want KindArray", got.Kind())
			}
			if len(got.Array()) != tt.len {
				t.Fatalf("len got %d, want %d", len(got.Array()), tt.len)
			}
		})
	}
}

func TestDecodeMap(t *testing.T) {
	tests := []struct {
		name string
		val  cbor.Value
		len  int
	}{
		{"empty", cbor.MakeMap(), 0},
		{"one", cbor.MakeMap(cbor.MapEntry{Key: cbor.Text("a"), Value: cbor.Uint(1)}), 1},
		{"two", cbor.MakeMap(
			cbor.MapEntry{Key: cbor.Text("a"), Value: cbor.Uint(1)},
			cbor.MapEntry{Key: cbor.Text("b"), Value: cbor.Uint(2)},
		), 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := mustEncode(t, tt.val)
			got, n, err := Decode(src, DecodeOpts{})
			if err != nil {
				t.Fatal(err)
			}
			if n != len(src) {
				t.Fatalf("consumed %d, want %d", n, len(src))
			}
			if got.Kind() != cbor.KindMap {
				t.Fatalf("kind = %d, want KindMap", got.Kind())
			}
			if len(got.Map()) != tt.len {
				t.Fatalf("len got %d, want %d", len(got.Map()), tt.len)
			}
		})
	}
}

func TestDecodeIndefiniteByteString(t *testing.T) {
	src := []byte{0x5f, 0x42, 0x01, 0x02, 0x43, 0x03, 0x04, 0x05, 0xff}
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	if got.Kind() != cbor.KindBytes {
		t.Fatalf("kind = %d, want KindBytes", got.Kind())
	}
	gb := got.BytesVal()
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if len(gb) != len(want) {
		t.Fatalf("len got %d, want %d", len(gb), len(want))
	}
	for i := range gb {
		if gb[i] != want[i] {
			t.Fatalf("byte %d: got %x, want %x", i, gb[i], want[i])
		}
	}
}

func TestDecodeIndefiniteTextString(t *testing.T) {
	src := []byte{0x7f, 0x65, 'h', 'e', 'l', 'l', 'o', 0x65, 'w', 'o', 'r', 'l', 'd', 0xff}
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	if got.Kind() != cbor.KindText || got.TextVal() != "helloworld" {
		t.Fatalf("got %v, want Text(helloworld)", got)
	}
}

func TestDecodeIndefiniteArray(t *testing.T) {
	src := []byte{0x9f, 0x01, 0x02, 0x03, 0xff}
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	ga := got.Array()
	if len(ga) != 3 {
		t.Fatalf("len got %d, want 3", len(ga))
	}
	for i, wantVal := range []uint64{1, 2, 3} {
		if ga[i].Kind() != cbor.KindUint || ga[i].UintVal() != wantVal {
			t.Fatalf("elem %d: got %v, want Uint(%d)", i, ga[i], wantVal)
		}
	}
}

func TestDecodeIndefiniteMap(t *testing.T) {
	src := []byte{0xbf, 0x61, 'a', 0x01, 0x61, 'b', 0x02, 0xff}
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	if got.Kind() != cbor.KindMap || len(got.Map()) != 2 {
		t.Fatalf("got kind=%d len=%d, want map with 2 entries", got.Kind(), len(got.Map()))
	}
}

func TestDecodeFloat16(t *testing.T) {
	src := []byte{0xf9, 0x3c, 0x00}
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("consumed %d, want 3", n)
	}
	if got.Kind() != cbor.KindFloat64 || got.Float64Val() != 1.0 {
		t.Fatalf("got %v, want Float64(1.0)", got)
	}
}

func TestDecodeFloat32(t *testing.T) {
	src := mustEncode(t, cbor.Float32(3.14))
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	if got.Kind() != cbor.KindFloat32 || got.Float32Val() != 3.14 {
		t.Fatalf("got %v, want Float32(3.14)", got)
	}
}

func TestDecodeFloat64(t *testing.T) {
	src := mustEncode(t, cbor.Float64(3.141592653589793))
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	if got.Kind() != cbor.KindFloat64 || got.Float64Val() != 3.141592653589793 {
		t.Fatalf("got %v, want Float64(3.141592653589793)", got)
	}
}

func TestDecodeTag(t *testing.T) {
	src := mustEncode(t, cbor.MakeTag(1, cbor.Uint(1234567890)))
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	if got.Kind() != cbor.KindTag || got.TagID() != 1 {
		t.Fatalf("tag ID got %d, want 1", got.TagID())
	}
	inner := got.TagInner()
	if inner.Kind() != cbor.KindUint || inner.UintVal() != 1234567890 {
		t.Fatalf("inner got %v, want Uint(1234567890)", inner)
	}
}

func TestDecodeSelfDescribeStrip(t *testing.T) {
	src := mustEncode(t, cbor.MakeTag(55799, cbor.Uint(42)))
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	if got.Kind() != cbor.KindUint || got.UintVal() != 42 {
		t.Fatalf("got %v, want Uint(42) (self-describe stripped)", got)
	}
}

func TestDecodeRejectIndefiniteLength(t *testing.T) {
	src := []byte{0x9f, 0x01, 0xff}
	_, _, err := Decode(src, DecodeOpts{RejectIndefiniteLength: true})
	if !errors.Is(err, cbor.ErrIndefiniteLength) {
		t.Fatalf("got err=%v, want ErrIndefiniteLength", err)
	}
}

func TestDecodeRejectNonShortest(t *testing.T) {
	src := []byte{0x18, 0x00}
	_, _, err := Decode(src, DecodeOpts{RejectNonShortest: true})
	if !errors.Is(err, cbor.ErrNonShortest) {
		t.Fatalf("got err=%v, want ErrNonShortest", err)
	}
}

func TestDecodeRejectDuplicateMapKeys(t *testing.T) {
	src := []byte{0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02}
	_, _, err := Decode(src, DecodeOpts{RejectDuplicateMapKeys: true})
	if !errors.Is(err, cbor.ErrDuplicateMapKey) {
		t.Fatalf("got err=%v, want ErrDuplicateMapKey", err)
	}
}

func TestDecodeRejectInvalidUTF8(t *testing.T) {
	src := []byte{0x62, 0xff, 0xfe}
	_, _, err := Decode(src, DecodeOpts{RejectInvalidUTF8: true})
	if !errors.Is(err, cbor.ErrInvalidUTF8) {
		t.Fatalf("got err=%v, want ErrInvalidUTF8", err)
	}
	_, _, err = Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatalf("forgiving mode should accept invalid UTF-8, got %v", err)
	}
}

func TestDecodeRejectNonFiniteFloats(t *testing.T) {
	src := []byte{0xf9, 0x7e, 0x00}
	_, _, err := Decode(src, DecodeOpts{RejectNonFiniteFloats: true})
	if !errors.Is(err, cbor.ErrNonFiniteFloat) {
		t.Fatalf("got err=%v, want ErrNonFiniteFloat", err)
	}
	src = []byte{0xf9, 0x7c, 0x00}
	_, _, err = Decode(src, DecodeOpts{RejectNonFiniteFloats: true})
	if !errors.Is(err, cbor.ErrNonFiniteFloat) {
		t.Fatalf("got err=%v, want ErrNonFiniteFloat for +Inf", err)
	}
}

func TestDecodeRejectNullMapKeys(t *testing.T) {
	src := []byte{0xa1, 0xf6, 0x01}
	_, _, err := Decode(src, DecodeOpts{RejectNullMapKeys: true})
	if !errors.Is(err, cbor.ErrNullMapKey) {
		t.Fatalf("got err=%v, want ErrNullMapKey", err)
	}
}

func TestDecodeMaxNestingDepth(t *testing.T) {
	depth := 5
	src := make([]byte, 0, depth*2)
	for range depth {
		src = append(src, 0x81)
	}
	src = append(src, 0x00)
	_, _, err := Decode(src, DecodeOpts{MaxNestingDepth: 3})
	if !errors.Is(err, cbor.ErrMaxNestingDepth) {
		t.Fatalf("got err=%v, want ErrMaxNestingDepth", err)
	}
	_, _, err = Decode(src, DecodeOpts{MaxNestingDepth: 10})
	if err != nil {
		t.Fatalf("expected success with depth=10, got %v", err)
	}
}

func TestDecodeMaxArrayLength(t *testing.T) {
	src := wire.AppendHead(nil, wire.MajorArray, 1000)
	for range 1000 {
		src = append(src, 0x00)
	}
	_, _, err := Decode(src, DecodeOpts{MaxArrayLength: 100})
	if !errors.Is(err, cbor.ErrMaxArrayLength) {
		t.Fatalf("got err=%v, want ErrMaxArrayLength", err)
	}
}

func TestDecodeMaxByteStringLength(t *testing.T) {
	src := wire.AppendHead(nil, wire.MajorBytes, 1000)
	src = append(src, make([]byte, 1000)...)
	_, _, err := Decode(src, DecodeOpts{MaxByteStringLength: 100})
	if !errors.Is(err, cbor.ErrMaxByteStringLength) {
		t.Fatalf("got err=%v, want ErrMaxByteStringLength", err)
	}
}

func TestDecodeTruncated(t *testing.T) {
	tests := []struct {
		name string
		src  []byte
	}{
		{"empty", nil},
		{"uint_missing_arg", []byte{0x18}},
		{"bytes_missing_data", []byte{0x43, 0x01, 0x02}},
		{"array_missing_elem", []byte{0x82, 0x01}},
		{"map_missing_value", []byte{0xa1, 0x61, 'a'}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Decode(tt.src, DecodeOpts{})
			if !errors.Is(err, cbor.ErrTruncated) {
				t.Fatalf("got err=%v, want ErrTruncated", err)
			}
		})
	}
}

func TestDecodeReservedAI(t *testing.T) {
	for _, ai := range []byte{28, 29, 30} {
		src := []byte{wire.MajorUint | ai}
		_, _, err := Decode(src, DecodeOpts{})
		if !errors.Is(err, cbor.ErrReservedAI) {
			t.Fatalf("AI=%d: got err=%v, want ErrReservedAI", ai, err)
		}
	}
}

func TestDecodeDuplicateMapKeysLastWins(t *testing.T) {
	src := []byte{0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02}
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	gm := got.Map()
	if len(gm) != 1 {
		t.Fatalf("map should have 1 entry (deduped), got %d", len(gm))
	}
	if gm[0].Value.Kind() != cbor.KindUint || gm[0].Value.UintVal() != 2 {
		t.Fatalf("last-write-wins: got value %v, want Uint(2)", gm[0].Value)
	}
}

func TestDecodeSimpleValues(t *testing.T) {
	got, _, err := Decode([]byte{0xe0}, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind() != cbor.KindSimple || got.SimpleVal() != 0 {
		t.Fatalf("got %v, want Simple(0)", got)
	}
	got, _, err = Decode([]byte{0xf3}, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind() != cbor.KindSimple || got.SimpleVal() != 19 {
		t.Fatalf("got %v, want Simple(19)", got)
	}
	got, _, err = Decode([]byte{0xf8, 0xff}, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind() != cbor.KindSimple || got.SimpleVal() != 255 {
		t.Fatalf("got %v, want Simple(255)", got)
	}
}

func TestDecodeBoolNullUndefined(t *testing.T) {
	tests := []struct {
		src  []byte
		kind cbor.Kind
	}{
		{[]byte{0xf4}, cbor.KindBool},
		{[]byte{0xf5}, cbor.KindBool},
		{[]byte{0xf6}, cbor.KindNull},
		{[]byte{0xf7}, cbor.KindUndefined},
	}
	for _, tt := range tests {
		got, _, err := Decode(tt.src, DecodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if got.Kind() != tt.kind {
			t.Fatalf("got kind %d, want %d", got.Kind(), tt.kind)
		}
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	values := []cbor.Value{
		cbor.Uint(42),
		cbor.NegInt(99),
		cbor.Bytes([]byte{0xde, 0xad, 0xbe, 0xef}),
		cbor.Text("hello world"),
		cbor.MakeArray(cbor.Uint(1), cbor.Uint(2), cbor.Uint(3)),
		cbor.MakeMap(
			cbor.MapEntry{Key: cbor.Text("x"), Value: cbor.Uint(10)},
			cbor.MapEntry{Key: cbor.Text("y"), Value: cbor.Uint(20)},
		),
		cbor.MakeTag(1, cbor.Uint(1000)),
		cbor.Bool(true),
		cbor.Bool(false),
		cbor.Null(),
		cbor.Undefined(),
		cbor.Float32(1.5),
		cbor.Float64(math.Pi),
	}
	for _, v := range values {
		src := mustEncode(t, v)
		got, n, err := Decode(src, DecodeOpts{})
		if err != nil {
			t.Fatalf("decode kind %d: %v", v.Kind(), err)
		}
		if n != len(src) {
			t.Fatalf("decode kind %d: consumed %d, want %d", v.Kind(), n, len(src))
		}
		reenc := mustEncode(t, got)
		if len(reenc) != len(src) {
			t.Fatalf("re-encode kind %d: len %d != %d", v.Kind(), len(reenc), len(src))
		}
		for i := range src {
			if src[i] != reenc[i] {
				t.Fatalf("re-encode kind %d: mismatch at byte %d", v.Kind(), i)
			}
		}
	}
}

func TestDecodeTrailingBytes(t *testing.T) {
	src := []byte{0x01, 0x02}
	_, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("consumed %d, want 1 (trailing byte at offset 1)", n)
	}
}

func TestDecodeDuplicateMapKeysLarge(t *testing.T) {
	pairs := make([]cbor.MapEntry, 50)
	for i := range 50 {
		pairs[i] = cbor.MapEntry{Key: cbor.Text(fmt.Sprintf("k%02d", i)), Value: cbor.Uint(uint64(i))}
	}
	src := mustEncode(t, cbor.MakeMapFromSlice(pairs))
	got, _, err := Decode(src, DecodeOpts{RejectDuplicateMapKeys: true})
	if err != nil {
		t.Fatalf("unique keys should not error: %v", err)
	}
	if len(got.Map()) != 50 {
		t.Fatalf("got %d entries, want 50", len(got.Map()))
	}
}

func TestDecodeDuplicateMapKeysLargeReject(t *testing.T) {
	pairs := make([]cbor.MapEntry, 21)
	for i := range 20 {
		pairs[i] = cbor.MapEntry{Key: cbor.Text(fmt.Sprintf("k%02d", i)), Value: cbor.Uint(uint64(i))}
	}
	pairs[20] = cbor.MapEntry{Key: cbor.Text("k00"), Value: cbor.Uint(999)}
	src := mustEncode(t, cbor.MakeMapFromSlice(pairs))
	_, _, err := Decode(src, DecodeOpts{RejectDuplicateMapKeys: true})
	if !errors.Is(err, cbor.ErrDuplicateMapKey) {
		t.Fatalf("expected ErrDuplicateMapKey, got: %v", err)
	}
}

func TestDecodeDuplicateMapKeysLargeLastWins(t *testing.T) {
	pairs := make([]cbor.MapEntry, 21)
	for i := range 20 {
		pairs[i] = cbor.MapEntry{Key: cbor.Text(fmt.Sprintf("k%02d", i)), Value: cbor.Uint(uint64(i))}
	}
	pairs[20] = cbor.MapEntry{Key: cbor.Text("k00"), Value: cbor.Uint(999)}
	src := mustEncode(t, cbor.MakeMapFromSlice(pairs))
	got, _, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatalf("last-write-wins should not error: %v", err)
	}
	gotMap := got.Map()
	if len(gotMap) != 20 {
		t.Fatalf("got %d entries, want 20 (duplicate merged)", len(gotMap))
	}
	for _, entry := range gotMap {
		if entry.Key.Kind() == cbor.KindText && entry.Key.TextVal() == "k00" {
			if entry.Value.Kind() != cbor.KindUint || entry.Value.UintVal() != 999 {
				t.Fatalf("k00 value = %v, want 999", entry.Value)
			}
			return
		}
	}
	t.Fatal("k00 not found in decoded map")
}

func TestDecodeDuplicateMapKeysHashCollision(t *testing.T) {
	pairs := make([]cbor.MapEntry, 100)
	for i := range 100 {
		pairs[i] = cbor.MapEntry{Key: cbor.Uint(uint64(i)), Value: cbor.Uint(uint64(i * 2))}
	}
	src := mustEncode(t, cbor.MakeMapFromSlice(pairs))
	got, _, err := Decode(src, DecodeOpts{RejectDuplicateMapKeys: true})
	if err != nil {
		t.Fatalf("no duplicates should not error: %v", err)
	}
	if len(got.Map()) != 100 {
		t.Fatalf("got %d entries, want 100", len(got.Map()))
	}
}

func BenchmarkMapInsertLinear(b *testing.B) {
	pairs := make([]cbor.MapEntry, 10)
	for i := range 10 {
		pairs[i] = cbor.MapEntry{Key: cbor.Text(fmt.Sprintf("k%d", i)), Value: cbor.Uint(uint64(i))}
	}
	src, err := Encode(nil, cbor.MakeMapFromSlice(pairs), EncodeOpts{})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		Decode(src, DecodeOpts{RejectDuplicateMapKeys: true}) //nolint:errcheck
	}
}

func BenchmarkMapInsertHash(b *testing.B) {
	pairs := make([]cbor.MapEntry, 100)
	for i := range 100 {
		pairs[i] = cbor.MapEntry{Key: cbor.Text(fmt.Sprintf("key-%03d", i)), Value: cbor.Uint(uint64(i))}
	}
	src, err := Encode(nil, cbor.MakeMapFromSlice(pairs), EncodeOpts{})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		Decode(src, DecodeOpts{RejectDuplicateMapKeys: true}) //nolint:errcheck
	}
}
