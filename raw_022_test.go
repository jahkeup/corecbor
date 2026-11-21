// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/jahkeup/corecbor/rfc8949"
)

// Proposal 022: raw byte preservation.

func TestDecodePrefix(t *testing.T) {
	dec := NewDecoder()
	src := mustHex(t, "a2616201616102"+"01ff")
	v, rest, err := dec.DecodePrefix(src)
	if err != nil {
		t.Fatal(err)
	}
	if DiagnosticValue(v) != `{"b": 1, "a": 2}` || !bytes.Equal(rest, src[7:]) {
		t.Fatalf("DecodePrefix = %s, rest %x", DiagnosticValue(v), rest)
	}
	if _, _, err := dec.DecodePrefix(nil); !errors.Is(err, ErrTruncated) {
		t.Fatalf("DecodePrefix(nil) err = %v", err)
	}
	if _, _, err := dec.DecodePrefix(mustHex(t, "82")); !errors.Is(err, ErrTruncated) {
		t.Fatalf("DecodePrefix(82) err = %v", err)
	}
}

func TestDecodeRaw(t *testing.T) {
	src := mustHex(t, "a2616201616102")
	v, raw, err := NewDecoder().DecodeRaw(src)
	if err != nil || !bytes.Equal(raw, src) || v.Kind != KindMap {
		t.Fatalf("DecodeRaw = %v, %x, %v", v.Kind, raw, err)
	}
	if _, _, err := NewDecoder().DecodeRaw(mustHex(t, "0101")); !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("trailing: err = %v", err)
	}
}

func TestCursorRawBytes(t *testing.T) {
	// [h'0102', {"a": 1}, (_ h'01', h'02')]
	src := mustHex(t, "83420102a1616101"+"5f41014102ff")
	c := NewDecoder().Cursor(src)
	if _, err := c.EnterArray(); err != nil {
		t.Fatal(err)
	}
	b, err := c.Bytes()
	if err != nil || !bytes.Equal(b, []byte{1, 2}) {
		t.Fatalf("Bytes = %x, %v", b, err)
	}
	if &b[0] != &src[2] {
		t.Fatal("Bytes copied instead of aliasing src")
	}
	raw, err := c.Raw()
	if err != nil || hex.EncodeToString(raw) != "a1616101" {
		t.Fatalf("Raw = %x, %v", raw, err)
	}
	if _, err := c.Bytes(); !errors.Is(err, rfc8949.ErrTypeMismatch) {
		t.Fatalf("Bytes on a map: err = %v", err)
	}
	v, raw, err := c.DecodeRaw()
	if err != nil || hex.EncodeToString(raw) != "a1616101" || v.Kind != KindMap {
		t.Fatalf("DecodeRaw = %v, %x, %v", v.Kind, raw, err)
	}
	if _, err := c.Bytes(); !errors.Is(err, ErrIndefiniteLength) {
		t.Fatalf("Bytes on indefinite: err = %v", err)
	}
}

// Cursor.Skip applies the same structural rules as Decode.
func TestCursorSkipWellFormedness(t *testing.T) {
	cases := map[string]struct {
		hex string
		err error
	}{
		"stray-break":           {"ff", ErrUnexpectedBreak},
		"break-in-array":        {"81ff", ErrUnexpectedBreak},
		"break-as-map-value":    {"bf01ff", ErrUnexpectedBreak},
		"reserved-ai-28":        {"1c", ErrReservedAI},
		"uint-ai-31":            {"1f", ErrReservedAI},
		"tag-ai-31":             {"df01", ErrReservedAI},
		"simple-below-32":       {"f818", ErrNonShortest},
		"array-claims-too-many": {"9bffffffffffffffff", ErrMaxArrayLength},
		"map-overlapping":       {"8282" + "0000", ErrTruncated},
		"bytes-too-long":        {"5bffffffffffffffff", ErrMaxByteStringLength},
		"chunk-wrong-major":     {"5f6161ff", ErrTruncated},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			src := mustHex(t, tc.hex)
			_, decErr := NewDecoder().Decode(src)
			_, skipErr := rfc8949.NewCursor(src, rfc8949.DecodeOpts{}).Skip()
			if !errors.Is(skipErr, tc.err) {
				t.Fatalf("Skip err = %v, want %v", skipErr, tc.err)
			}
			if !errors.Is(decErr, tc.err) {
				t.Fatalf("Decode err = %v, want %v (test expectation out of date)", decErr, tc.err)
			}
		})
	}

	// Nesting is bounded.
	deep := append(bytes.Repeat([]byte{0x81}, 300), 0x00)
	if _, err := rfc8949.NewCursor(deep, rfc8949.DecodeOpts{}).Skip(); !errors.Is(err, ErrMaxNestingDepth) {
		t.Fatalf("deep Skip err = %v", err)
	}
}

// recorder is an Unmarshaler that keeps the bytes it was given.
type recorder struct{ got []byte }

func (r *recorder) UnmarshalCBOR(b []byte) error {
	r.got = append([]byte(nil), b...)
	return nil
}

type recKey string

func (k *recKey) UnmarshalCBOR(b []byte) error {
	*k = recKey(hex.EncodeToString(b))
	return nil
}

func TestUnmarshalerReceivesOriginalBytes(t *testing.T) {
	// Non-canonical items: unsorted map, non-shortest int, indefinite
	// array, 16-bit float that Core Deterministic would shorten.
	const item = "a2616201616102" // {"b": 1, "a": 2}
	const nonShortest = "1800"
	const indef = "9f0102ff"

	type Embedded struct {
		E recorder `cbor:"e"`
	}
	type S struct {
		Embedded
		R   recorder            `cbor:"r"`
		P   *recorder           `cbor:"p"`
		L   []recorder          `cbor:"l"`
		M   map[string]recorder `cbor:"m"`
		K   map[recKey]int      `cbor:"k"`
		T   recorder            `cbor:"t,tag=42"`
		Raw RawMessage          `cbor:"raw"`
	}
	src := mustHex(t, "a8"+
		"6165"+item+
		"6172"+nonShortest+
		"6170"+indef+
		"616c"+"82"+item+nonShortest+
		"616d"+"a1617a"+indef+
		"616b"+"a1"+nonShortest+"01"+
		"6174"+"d82a"+item+
		"63726177"+item)
	var s S
	if err := Unmarshal(src, &s); err != nil {
		t.Fatal(err)
	}
	check := func(name string, got []byte, want string) {
		t.Helper()
		if hex.EncodeToString(got) != want {
			t.Errorf("%s got %x, want %s", name, got, want)
		}
	}
	check("embedded", s.E.got, item)
	check("field", s.R.got, nonShortest)
	check("pointer", s.P.got, indef)
	check("slice[0]", s.L[0].got, item)
	check("slice[1]", s.L[1].got, nonShortest)
	check("map value", s.M["z"].got, indef)
	check("tag=42 content", s.T.got, item)
	check("RawMessage", s.Raw, item)
	if _, ok := s.K[recKey(nonShortest)]; !ok {
		t.Errorf("map key Unmarshaler got %v, want key %s", s.K, nonShortest)
	}

	// Top level, with a leading self-describe tag stripped as Decode does.
	var top recorder
	if err := Unmarshal(mustHex(t, "d9d9f7"+item), &top); err != nil {
		t.Fatal(err)
	}
	check("top-level", top.got, item)
}

func TestUnmarshalerDuplicateKeysLastWins(t *testing.T) {
	var s struct {
		R recorder `cbor:"r"`
	}
	if err := Unmarshal(mustHex(t, "a2617201617202"), &s); err != nil { // {"r": 1, "r": 2}
		t.Fatal(err)
	}
	if hex.EncodeToString(s.R.got) != "02" {
		t.Fatalf("got %x, want 02", s.R.got)
	}
}

// Strictness knobs reject the input before any Unmarshaler runs.
func TestUnmarshalerStrictnessFirst(t *testing.T) {
	var s struct {
		R recorder `cbor:"r"`
	}
	err := StrictDecoder().Unmarshal(mustHex(t, "a161721800"), &s) // {"r": 0 (non-shortest)}
	if !errors.Is(err, ErrNonShortest) {
		t.Fatalf("err = %v, want ErrNonShortest", err)
	}
	if s.R.got != nil {
		t.Fatal("Unmarshaler ran on input the decoder rejected")
	}
}

func TestRawTagKeepsContentBytes(t *testing.T) {
	var rt RawTag
	if err := Unmarshal(mustHex(t, "d82aa2616201616102"), &rt); err != nil {
		t.Fatal(err)
	}
	if rt.ID != 42 || hex.EncodeToString(rt.Content) != "a2616201616102" {
		t.Fatalf("RawTag = %d %x", rt.ID, rt.Content)
	}
}

func TestMarshalerVerbatimPermissive(t *testing.T) {
	type S struct {
		R RawMessage `cbor:"r"`
		T RawTag     `cbor:"t"`
	}
	raw := mustHex(t, "a2616201616102") // unsorted
	v := S{R: raw, T: RawTag{ID: 42, Content: raw}}

	got, err := New(ModePermissive).Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	want := "a2" + "6172" + "a2616201616102" + "6174" + "d82a" + "a2616201616102"
	if hex.EncodeToString(got) != want {
		t.Fatalf("Permissive Marshal = %x, want %s", got, want)
	}

	// Deterministic modes still canonicalize (§2.1).
	got, err = New(ModeCoreDeterministic).Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	want = "a2" + "6172" + "a2616102616201" + "6174" + "d82a" + "a2616102616201"
	if hex.EncodeToString(got) != want {
		t.Fatalf("CoreDeterministic Marshal = %x, want %s", got, want)
	}

	// Invalid raw bytes are still rejected.
	if _, err := New(ModePermissive).Marshal(S{R: RawMessage{0x82, 0x01}}); err == nil {
		t.Fatal("Marshal of truncated RawMessage: want error")
	}
}

// A self-referential type that reaches an Unmarshaler only through a
// cycle is still detected.
func TestNeedsRawCycle(t *testing.T) {
	type B struct {
		Next *B       `cbor:"n"`
		R    recorder `cbor:"r"`
	}
	type A struct {
		B *B `cbor:"b"`
	}
	if !needsRaw(reflectTypeOf[A]()) {
		t.Fatal("needsRaw(A) = false")
	}
	type C struct {
		Next *C  `cbor:"n"`
		N    int `cbor:"i"`
	}
	if needsRaw(reflectTypeOf[C]()) {
		t.Fatal("needsRaw(C) = true")
	}
}

func reflectTypeOf[T any]() reflect.Type { return reflect.TypeFor[T]() }

// The decoder buckets large maps (> 16 entries) by encoded key bytes,
// so a duplicate key written once definite and once chunked isn't
// merged there; the raw walk must still give the right result (the
// later value wins) by falling back to decoding spans itself.
func TestUnmarshalerLargeMapMisalignedDuplicates(t *testing.T) {
	var b []byte
	b = append(b, 0xb8, 18) // map(18)
	b = append(b, 0x61, 'r', 0x01)
	for i := range 16 {
		b = append(b, 0x62, 'k', byte('a'+i), byte(i))
	}
	b = append(b, 0x7f, 0x61, 'r', 0xff, 0x02) // (_ "r"): 2
	var s struct {
		R recorder `cbor:"r"`
		K int      `cbor:"kc"`
	}
	if err := Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(s.R.got) != "02" || s.K != 2 {
		t.Fatalf("R=%x K=%d, want R=02 K=2", s.R.got, s.K)
	}
}
