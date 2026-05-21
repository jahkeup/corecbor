package rfc8949

import (
	"errors"
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
		val  cbor.Uint
	}{
		{"zero", cbor.Uint(0)},
		{"one", cbor.Uint(1)},
		{"23", cbor.Uint(23)},
		{"24", cbor.Uint(24)},
		{"255", cbor.Uint(255)},
		{"256", cbor.Uint(256)},
		{"65535", cbor.Uint(65535)},
		{"65536", cbor.Uint(65536)},
		{"max32", cbor.Uint(0xffffffff)},
		{"max64", cbor.Uint(math.MaxUint64)},
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
			if got != tt.val {
				t.Fatalf("got %v, want %v", got, tt.val)
			}
		})
	}
}

func TestDecodeNegInt(t *testing.T) {
	tests := []struct {
		name string
		val  cbor.NegInt
	}{
		{"neg1", cbor.NegInt(0)},
		{"neg24", cbor.NegInt(23)},
		{"neg25", cbor.NegInt(24)},
		{"neg256", cbor.NegInt(255)},
		{"neg65536", cbor.NegInt(65535)},
		{"max", cbor.NegInt(math.MaxUint64)},
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
			if got != tt.val {
				t.Fatalf("got %v, want %v", got, tt.val)
			}
		})
	}
}

func TestDecodeBytes(t *testing.T) {
	tests := []struct {
		name string
		val  cbor.Bytes
	}{
		{"empty", cbor.Bytes{}},
		{"one", cbor.Bytes{0x42}},
		{"multi", cbor.Bytes{0x01, 0x02, 0x03, 0x04, 0x05}},
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
			gb := got.(cbor.Bytes)
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
		val  cbor.Text
	}{
		{"empty", cbor.Text("")},
		{"hello", cbor.Text("hello")},
		{"unicode", cbor.Text("日本語")},
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
			if got != tt.val {
				t.Fatalf("got %v, want %v", got, tt.val)
			}
		})
	}
}

func TestDecodeArray(t *testing.T) {
	tests := []struct {
		name string
		val  cbor.Array
	}{
		{"empty", cbor.Array{}},
		{"one", cbor.Array{cbor.Uint(1)}},
		{"mixed", cbor.Array{cbor.Uint(1), cbor.Text("two"), cbor.Bool(true)}},
		{"nested", cbor.Array{cbor.Array{cbor.Uint(1), cbor.Uint(2)}}},
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
			ga := got.(cbor.Array)
			if len(ga) != len(tt.val) {
				t.Fatalf("len got %d, want %d", len(ga), len(tt.val))
			}
		})
	}
}

func TestDecodeMap(t *testing.T) {
	tests := []struct {
		name string
		val  cbor.Map
	}{
		{"empty", cbor.Map{}},
		{"one", cbor.Map{{Key: cbor.Text("a"), Value: cbor.Uint(1)}}},
		{"two", cbor.Map{
			{Key: cbor.Text("a"), Value: cbor.Uint(1)},
			{Key: cbor.Text("b"), Value: cbor.Uint(2)},
		}},
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
			gm := got.(cbor.Map)
			if len(gm) != len(tt.val) {
				t.Fatalf("len got %d, want %d", len(gm), len(tt.val))
			}
		})
	}
}

func TestDecodeIndefiniteByteString(t *testing.T) {
	// 0x5f 0x42 0x01 0x02 0x43 0x03 0x04 0x05 0xff
	// indefinite byte string: [0x01,0x02] ++ [0x03,0x04,0x05]
	src := []byte{0x5f, 0x42, 0x01, 0x02, 0x43, 0x03, 0x04, 0x05, 0xff}
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	gb := got.(cbor.Bytes)
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
	// 0x7f 0x65 "hello" 0x65 "world" 0xff
	src := []byte{0x7f, 0x65, 'h', 'e', 'l', 'l', 'o', 0x65, 'w', 'o', 'r', 'l', 'd', 0xff}
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	gt := got.(cbor.Text)
	if string(gt) != "helloworld" {
		t.Fatalf("got %q, want %q", gt, "helloworld")
	}
}

func TestDecodeIndefiniteArray(t *testing.T) {
	// 0x9f 0x01 0x02 0x03 0xff → [1, 2, 3]
	src := []byte{0x9f, 0x01, 0x02, 0x03, 0xff}
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	ga := got.(cbor.Array)
	if len(ga) != 3 {
		t.Fatalf("len got %d, want 3", len(ga))
	}
	for i, want := range []cbor.Uint{0, 1, 2} {
		if ga[i] != cbor.Uint(want+1) {
			t.Fatalf("elem %d: got %v, want %v", i, ga[i], want+1)
		}
	}
}

func TestDecodeIndefiniteMap(t *testing.T) {
	// 0xbf 0x61 "a" 0x01 0x61 "b" 0x02 0xff → {"a":1, "b":2}
	src := []byte{0xbf, 0x61, 'a', 0x01, 0x61, 'b', 0x02, 0xff}
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	gm := got.(cbor.Map)
	if len(gm) != 2 {
		t.Fatalf("len got %d, want 2", len(gm))
	}
}

func TestDecodeFloat16(t *testing.T) {
	// 0xf9 0x3c 0x00 = 1.0 in half precision
	src := []byte{0xf9, 0x3c, 0x00}
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("consumed %d, want 3", n)
	}
	gf := got.(cbor.Float64)
	if float64(gf) != 1.0 {
		t.Fatalf("got %v, want 1.0", gf)
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
	gf := got.(cbor.Float32)
	if float32(gf) != 3.14 {
		t.Fatalf("got %v, want 3.14", gf)
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
	gf := got.(cbor.Float64)
	if float64(gf) != 3.141592653589793 {
		t.Fatalf("got %v, want 3.141592653589793", gf)
	}
}

func TestDecodeTag(t *testing.T) {
	src := mustEncode(t, cbor.Tag{ID: 1, Inner: cbor.Uint(1234567890)})
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	gt := got.(cbor.Tag)
	if gt.ID != 1 {
		t.Fatalf("tag ID got %d, want 1", gt.ID)
	}
	if gt.Inner != cbor.Uint(1234567890) {
		t.Fatalf("inner got %v, want Uint(1234567890)", gt.Inner)
	}
}

func TestDecodeSelfDescribeStrip(t *testing.T) {
	// Tag 55799 wrapping Uint(42)
	src := mustEncode(t, cbor.Tag{ID: 55799, Inner: cbor.Uint(42)})
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	if got != cbor.Uint(42) {
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
	// Uint 0 encoded as 2-byte: 0x18 0x00 (non-shortest)
	src := []byte{0x18, 0x00}
	_, _, err := Decode(src, DecodeOpts{RejectNonShortest: true})
	if !errors.Is(err, cbor.ErrNonShortest) {
		t.Fatalf("got err=%v, want ErrNonShortest", err)
	}
}

func TestDecodeRejectDuplicateMapKeys(t *testing.T) {
	// Map with key "a" twice: {a:1, a:2}
	src := []byte{
		0xa2,
		0x61, 'a', 0x01,
		0x61, 'a', 0x02,
	}
	_, _, err := Decode(src, DecodeOpts{RejectDuplicateMapKeys: true})
	if !errors.Is(err, cbor.ErrDuplicateMapKey) {
		t.Fatalf("got err=%v, want ErrDuplicateMapKey", err)
	}
}

func TestDecodeRejectInvalidUTF8(t *testing.T) {
	// Text string with invalid UTF-8: 0x62 followed by 0xff 0xfe
	src := []byte{0x62, 0xff, 0xfe}
	_, _, err := Decode(src, DecodeOpts{RejectInvalidUTF8: true})
	if !errors.Is(err, cbor.ErrInvalidUTF8) {
		t.Fatalf("got err=%v, want ErrInvalidUTF8", err)
	}

	// Forgiving mode accepts it
	_, _, err = Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatalf("forgiving mode should accept invalid UTF-8, got %v", err)
	}
}

func TestDecodeRejectNonFiniteFloats(t *testing.T) {
	// Float16 NaN: 0xf9 0x7e 0x00
	src := []byte{0xf9, 0x7e, 0x00}
	_, _, err := Decode(src, DecodeOpts{RejectNonFiniteFloats: true})
	if !errors.Is(err, cbor.ErrNonFiniteFloat) {
		t.Fatalf("got err=%v, want ErrNonFiniteFloat", err)
	}

	// Float16 +Inf: 0xf9 0x7c 0x00
	src = []byte{0xf9, 0x7c, 0x00}
	_, _, err = Decode(src, DecodeOpts{RejectNonFiniteFloats: true})
	if !errors.Is(err, cbor.ErrNonFiniteFloat) {
		t.Fatalf("got err=%v, want ErrNonFiniteFloat for +Inf", err)
	}
}

func TestDecodeRejectNullMapKeys(t *testing.T) {
	// Map {null: 1}
	src := []byte{0xa1, 0xf6, 0x01}
	_, _, err := Decode(src, DecodeOpts{RejectNullMapKeys: true})
	if !errors.Is(err, cbor.ErrNullMapKey) {
		t.Fatalf("got err=%v, want ErrNullMapKey", err)
	}
}

func TestDecodeMaxNestingDepth(t *testing.T) {
	// Build deeply nested arrays: [[[[...]]]]
	depth := 5
	src := make([]byte, 0, depth*2)
	for range depth {
		src = append(src, 0x81) // array of length 1
	}
	src = append(src, 0x00) // uint 0 at the bottom

	_, _, err := Decode(src, DecodeOpts{MaxNestingDepth: 3})
	if !errors.Is(err, cbor.ErrMaxNestingDepth) {
		t.Fatalf("got err=%v, want ErrMaxNestingDepth", err)
	}

	// Should succeed with enough depth
	_, _, err = Decode(src, DecodeOpts{MaxNestingDepth: 10})
	if err != nil {
		t.Fatalf("expected success with depth=10, got %v", err)
	}
}

func TestDecodeMaxArrayLength(t *testing.T) {
	// Array declaring 1000 elements
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
	// Byte string declaring 1000 bytes
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
	// AI 28 = 0x1c, AI 29 = 0x1d, AI 30 = 0x1e (in major type 0)
	for _, ai := range []byte{28, 29, 30} {
		src := []byte{wire.MajorUint | ai}
		_, _, err := Decode(src, DecodeOpts{})
		if !errors.Is(err, cbor.ErrReservedAI) {
			t.Fatalf("AI=%d: got err=%v, want ErrReservedAI", ai, err)
		}
	}
}

func TestDecodeDuplicateMapKeysLastWins(t *testing.T) {
	// Map with key "a" twice: {a:1, a:2} — last wins in forgiving mode
	src := []byte{
		0xa2,
		0x61, 'a', 0x01,
		0x61, 'a', 0x02,
	}
	got, n, err := Decode(src, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(src) {
		t.Fatalf("consumed %d, want %d", n, len(src))
	}
	gm := got.(cbor.Map)
	if len(gm) != 1 {
		t.Fatalf("map should have 1 entry (deduped), got %d", len(gm))
	}
	if gm[0].Value != cbor.Uint(2) {
		t.Fatalf("last-write-wins: got value %v, want Uint(2)", gm[0].Value)
	}
}

func TestDecodeSimpleValues(t *testing.T) {
	// Simple 0: 0xe0
	got, _, err := Decode([]byte{0xe0}, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if got != cbor.Simple(0) {
		t.Fatalf("got %v, want Simple(0)", got)
	}

	// Simple 19: 0xf3
	got, _, err = Decode([]byte{0xf3}, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if got != cbor.Simple(19) {
		t.Fatalf("got %v, want Simple(19)", got)
	}

	// Simple 255: 0xf8 0xff
	got, _, err = Decode([]byte{0xf8, 0xff}, DecodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if got != cbor.Simple(255) {
		t.Fatalf("got %v, want Simple(255)", got)
	}
}

func TestDecodeBoolNullUndefined(t *testing.T) {
	tests := []struct {
		src  []byte
		want cbor.Value
	}{
		{[]byte{0xf4}, cbor.Bool(false)},
		{[]byte{0xf5}, cbor.Bool(true)},
		{[]byte{0xf6}, cbor.Null{}},
		{[]byte{0xf7}, cbor.Undefined{}},
	}
	for _, tt := range tests {
		got, _, err := Decode(tt.src, DecodeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Fatalf("got %v, want %v", got, tt.want)
		}
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	values := []cbor.Value{
		cbor.Uint(42),
		cbor.NegInt(99),
		cbor.Bytes{0xde, 0xad, 0xbe, 0xef},
		cbor.Text("hello world"),
		cbor.Array{cbor.Uint(1), cbor.Uint(2), cbor.Uint(3)},
		cbor.Map{
			{Key: cbor.Text("x"), Value: cbor.Uint(10)},
			{Key: cbor.Text("y"), Value: cbor.Uint(20)},
		},
		cbor.Tag{ID: 1, Inner: cbor.Uint(1000)},
		cbor.Bool(true),
		cbor.Bool(false),
		cbor.Null{},
		cbor.Undefined{},
		cbor.Float32(1.5),
		cbor.Float64(math.Pi),
	}
	for _, v := range values {
		src := mustEncode(t, v)
		got, n, err := Decode(src, DecodeOpts{})
		if err != nil {
			t.Fatalf("decode %T: %v", v, err)
		}
		if n != len(src) {
			t.Fatalf("decode %T: consumed %d, want %d", v, n, len(src))
		}
		reenc := mustEncode(t, got)
		if len(reenc) != len(src) {
			t.Fatalf("re-encode %T: len %d != %d", v, len(reenc), len(src))
		}
		for i := range src {
			if src[i] != reenc[i] {
				t.Fatalf("re-encode %T: mismatch at byte %d", v, i)
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
