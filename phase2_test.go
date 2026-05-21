package corecbor

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func hexb(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestEncodeCanonicalSort(t *testing.T) {
	// RFC 8949 §4.2.3 example: length-first sort order.
	// Keys: 10 (0x0a), "z" (0x617a), "aa" (0x626161), [32] (0x8120),
	//        {100: ...} would be complex; using subset of spec examples.
	// Expected order by encoded key length, then lex:
	// 0x0a (1 byte) < 0x20 (1 byte, 0x20>0x0a) < 0xf4 (1 byte) <
	// 0x1864 (2 bytes) < 0x617a (2 bytes) < 0x8120 (2 bytes) <
	// 0x626161 (3 bytes) < 0x811864 (3 bytes)
	enc := New(ModeCanonical)

	m := cbor.Map{
		{Key: cbor.Text("aa"), Value: cbor.Uint(7)},            // encoded key: 0x626161 (3 bytes)
		{Key: cbor.Text("z"), Value: cbor.Uint(6)},             // encoded key: 0x617a (2 bytes)
		{Key: cbor.Uint(100), Value: cbor.Uint(5)},             // encoded key: 0x1864 (2 bytes)
		{Key: cbor.Bool(false), Value: cbor.Uint(4)},           // encoded key: 0xf4 (1 byte)
		{Key: cbor.NegInt(0), Value: cbor.Uint(3)},             // encoded key: 0x20 (1 byte)
		{Key: cbor.Uint(10), Value: cbor.Uint(2)},              // encoded key: 0x0a (1 byte)
		{Key: cbor.Array{cbor.Uint(100)}, Value: cbor.Uint(9)}, // encoded key: 0x811864 (3 bytes)
		{Key: cbor.Array{cbor.NegInt(0)}, Value: cbor.Uint(8)}, // encoded key: 0x8120 (2 bytes)
	}

	got, err := enc.Encode(nil, m)
	if err != nil {
		t.Fatal(err)
	}

	// Expected sorted order of keys:
	// 1-byte: 0x0a, 0x20, 0xf4
	// 2-byte: 0x1864, 0x617a, 0x8120
	// 3-byte: 0x626161, 0x811864
	var want []byte
	want = append(want, hexb("a8")...)     // map(8)
	want = append(want, hexb("0a")...)     // Uint(10)
	want = append(want, hexb("02")...)     // → 2
	want = append(want, hexb("20")...)     // NegInt(0)
	want = append(want, hexb("03")...)     // → 3
	want = append(want, hexb("f4")...)     // Bool(false)
	want = append(want, hexb("04")...)     // → 4
	want = append(want, hexb("1864")...)   // Uint(100)
	want = append(want, hexb("05")...)     // → 5
	want = append(want, hexb("617a")...)   // Text("z")
	want = append(want, hexb("06")...)     // → 6
	want = append(want, hexb("8120")...)   // Array{NegInt(0)}
	want = append(want, hexb("08")...)     // → 8
	want = append(want, hexb("626161")...) // Text("aa")
	want = append(want, hexb("07")...)     // → 7
	want = append(want, hexb("811864")...) // Array{Uint(100)}
	want = append(want, hexb("09")...)     // → 9

	if !bytes.Equal(got, want) {
		t.Errorf("canonical sort:\ngot  %x\nwant %x", got, want)
	}
}

func TestEncodeCTAP2Float64Only(t *testing.T) {
	enc := New(ModeCTAP2, AllowNonFiniteFloats())

	tests := []struct {
		name string
		val  cbor.Value
		want string
	}{
		{"float32(1.5)", cbor.Float32(1.5), "fb3ff8000000000000"},
		{"float64(1.5)", cbor.Float64(1.5), "fb3ff8000000000000"},
		{"float32(0)", cbor.Float32(0), "fb0000000000000000"},
		{"float64(0)", cbor.Float64(0), "fb0000000000000000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := enc.Encode(nil, tt.val)
			if err != nil {
				t.Fatal(err)
			}
			if want := hexb(tt.want); !bytes.Equal(got, want) {
				t.Errorf("got %x, want %s", got, tt.want)
			}
		})
	}
}

func TestEncodeTo(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	val := cbor.Array{cbor.Uint(1), cbor.Uint(2), cbor.Uint(3)}

	batchOut, err := enc.Encode(nil, val)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err = enc.EncodeTo(&buf, val)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf.Bytes(), batchOut) {
		t.Errorf("EncodeTo mismatch:\ngot  %x\nwant %x", buf.Bytes(), batchOut)
	}
}

func TestStreamEncoder_Array(t *testing.T) {
	enc := New(ModePermissive)
	var buf bytes.Buffer
	s := enc.Stream(&buf)

	if err := s.BeginArray(3); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteValue(cbor.Uint(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteValue(cbor.Uint(2)); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteValue(cbor.Uint(3)); err != nil {
		t.Fatal(err)
	}
	if err := s.EndContainer(); err != nil {
		t.Fatal(err)
	}

	want := hexb("83010203")
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("StreamEncoder array:\ngot  %x\nwant %x", buf.Bytes(), want)
	}
}

func TestStreamEncoder_Map(t *testing.T) {
	enc := New(ModePermissive)
	var buf bytes.Buffer
	s := enc.Stream(&buf)

	if err := s.BeginMap(2); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteValue(cbor.Uint(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteValue(cbor.Uint(2)); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteValue(cbor.Uint(3)); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteValue(cbor.Uint(4)); err != nil {
		t.Fatal(err)
	}
	if err := s.EndContainer(); err != nil {
		t.Fatal(err)
	}

	want := hexb("a201020304")
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("StreamEncoder map:\ngot  %x\nwant %x", buf.Bytes(), want)
	}
}

func TestStreamEncoder_IndefiniteRejectsInDeterministic(t *testing.T) {
	enc := New(ModeCoreDeterministic)
	var buf bytes.Buffer
	s := enc.Stream(&buf)

	if err := s.BeginArray(-1); err == nil {
		t.Fatal("expected error for indefinite in deterministic mode")
	}
	if err := s.BeginMap(-1); err == nil {
		t.Fatal("expected error for indefinite in deterministic mode")
	}
}

func TestStreamEncoder_IndefinitePermissive(t *testing.T) {
	enc := New(ModePermissive)
	var buf bytes.Buffer
	s := enc.Stream(&buf)

	if err := s.BeginArray(-1); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteValue(cbor.Uint(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteValue(cbor.Uint(2)); err != nil {
		t.Fatal(err)
	}
	if err := s.EndContainer(); err != nil {
		t.Fatal(err)
	}

	// indefinite array: 0x9f 01 02 0xff
	want := hexb("9f0102ff")
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("indefinite array:\ngot  %x\nwant %x", buf.Bytes(), want)
	}
}

func TestDecodeFrom(t *testing.T) {
	data := hexb("83010203")
	r := bytes.NewReader(data)

	dec := NewDecoder()
	v, err := dec.DecodeFrom(r)
	if err != nil {
		t.Fatal(err)
	}

	arr, ok := v.(cbor.Array)
	if !ok {
		t.Fatalf("expected Array, got %T", v)
	}
	if len(arr) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(arr))
	}
	for i, expected := range []uint64{1, 2, 3} {
		if uint64(arr[i].(cbor.Uint)) != expected {
			t.Errorf("arr[%d] = %v, want %d", i, arr[i], expected)
		}
	}
}

func TestStreamDecoder(t *testing.T) {
	// Concatenate multiple CBOR values
	data := append(hexb("01"), hexb("02")...)  // Uint(1), Uint(2)
	data = append(data, hexb("83030405")...)   // Array [3,4,5]
	data = append(data, hexb("6449455446")...) // Text("IETF")

	dec := NewDecoder()
	stream := dec.Stream(bytes.NewReader(data))

	var values []cbor.Value
	for stream.Next() {
		values = append(values, stream.Value())
	}
	if err := stream.Err(); err != nil {
		t.Fatal(err)
	}

	if len(values) != 4 {
		t.Fatalf("expected 4 values, got %d", len(values))
	}
	if v := values[0].(cbor.Uint); v != 1 {
		t.Errorf("values[0] = %v, want 1", v)
	}
	if v := values[1].(cbor.Uint); v != 2 {
		t.Errorf("values[1] = %v, want 2", v)
	}
	arr := values[2].(cbor.Array)
	if len(arr) != 3 {
		t.Errorf("values[2] array length = %d, want 3", len(arr))
	}
	if v := values[3].(cbor.Text); v != "IETF" {
		t.Errorf("values[3] = %v, want IETF", v)
	}
}

func TestStreamDecoder_Empty(t *testing.T) {
	dec := NewDecoder()
	stream := dec.Stream(bytes.NewReader(nil))
	if stream.Next() {
		t.Fatal("expected no values from empty reader")
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeFrom_SingleByte(t *testing.T) {
	// Use a reader that delivers one byte at a time
	data := hexb("1903e8") // Uint(1000)
	r := &slowReader{data: data}

	dec := NewDecoder()
	v, err := dec.DecodeFrom(r)
	if err != nil {
		t.Fatal(err)
	}
	if u := v.(cbor.Uint); u != 1000 {
		t.Errorf("got %v, want 1000", u)
	}
}

type slowReader struct {
	data []byte
	pos  int
}

func (sr *slowReader) Read(p []byte) (int, error) {
	if sr.pos >= len(sr.data) {
		return 0, io.EOF
	}
	p[0] = sr.data[sr.pos]
	sr.pos++
	return 1, nil
}
