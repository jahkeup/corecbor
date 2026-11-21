// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"testing"
	"testing/iotest"

	"github.com/jahkeup/corecbor/rfc8949"
)

// streamOps runs ops against a fresh StreamEncoder in mode and returns
// the bytes written and the first error.
func streamOps(mode Mode, ops ...func(*StreamEncoder) error) ([]byte, error) {
	var buf bytes.Buffer
	s := New(mode).Stream(&buf)
	for _, op := range ops {
		if err := op(s); err != nil {
			return buf.Bytes(), err
		}
	}
	return buf.Bytes(), nil
}

func beginArray(n int) func(*StreamEncoder) error {
	return func(s *StreamEncoder) error { return s.BeginArray(n) }
}

func beginMap(n int) func(*StreamEncoder) error {
	return func(s *StreamEncoder) error { return s.BeginMap(n) }
}

func end() func(*StreamEncoder) error {
	return func(s *StreamEncoder) error { return s.EndContainer() }
}

func wUint(v uint64) func(*StreamEncoder) error {
	return func(s *StreamEncoder) error { return s.WriteUint(v) }
}

func wText(t string) func(*StreamEncoder) error {
	return func(s *StreamEncoder) error { return s.WriteText(t) }
}

func wTag(id uint64) func(*StreamEncoder) error {
	return func(s *StreamEncoder) error { return s.WriteTag(id) }
}

// 021 D6: nested containers count as one item of their parent.
func TestStreamNestedContainersCountAgainstParent(t *testing.T) {
	got, err := streamOps(ModeCoreDeterministic,
		beginArray(1), beginArray(0), end(), beginArray(0))
	if !errors.Is(err, ErrContainerOverflow) {
		t.Fatalf("err = %v, want ErrContainerOverflow", err)
	}
	if want := "8180"; hex.EncodeToString(got) != want {
		t.Fatalf("wrote %x, want %s (nothing after the overflow)", got, want)
	}

	got, err = streamOps(ModeCoreDeterministic,
		beginArray(2), beginMap(1), wUint(1), wUint(2), end(), beginArray(0), end(), end())
	if err != nil {
		t.Fatal(err)
	}
	if want := "82a1010280"; hex.EncodeToString(got) != want {
		t.Fatalf("wrote %x, want %s", got, want)
	}
}

// 021 D6: a tag and its content are one item; a tag can't overflow or
// dangle.
func TestStreamTagCountsWithContent(t *testing.T) {
	got, err := streamOps(ModeCoreDeterministic, beginArray(1), wTag(1), wTag(2), wUint(0), end())
	if err != nil {
		t.Fatal(err)
	}
	if want := "81c1c200"; hex.EncodeToString(got) != want {
		t.Fatalf("wrote %x, want %s", got, want)
	}
	if _, err := streamOps(ModeCoreDeterministic, beginArray(0), wTag(1)); !errors.Is(err, ErrContainerOverflow) {
		t.Fatalf("tag into full array: err = %v, want ErrContainerOverflow", err)
	}
	if _, err := streamOps(ModeCoreDeterministic, beginArray(1), wTag(1), end()); !errors.Is(err, ErrContainerUnderflow) {
		t.Fatalf("dangling tag: err = %v, want ErrContainerUnderflow", err)
	}
}

func TestStreamIndefiniteMapEndsAfterValue(t *testing.T) {
	if _, err := streamOps(ModePermissive, beginMap(-1), wUint(1), end()); !errors.Is(err, ErrContainerUnderflow) {
		t.Fatalf("err = %v, want ErrContainerUnderflow", err)
	}
	got, err := streamOps(ModePermissive, beginMap(-1), wUint(1), wUint(2), end())
	if err != nil {
		t.Fatal(err)
	}
	if want := "bf0102ff"; hex.EncodeToString(got) != want {
		t.Fatalf("wrote %x, want %s", got, want)
	}
}

func TestStreamErrorTextsUnchanged(t *testing.T) {
	for err, want := range map[error]string{
		ErrContainerOverflow:  "corecbor: container overflow",
		ErrContainerUnderflow: "corecbor: container underflow",
		ErrNoOpenContainer:    "corecbor: no open container",
	} {
		if err.Error() != want {
			t.Errorf("%q, want %q", err.Error(), want)
		}
	}
	if _, err := streamOps(ModePermissive, end()); !errors.Is(err, ErrNoOpenContainer) {
		t.Fatalf("err = %v, want ErrNoOpenContainer", err)
	}
}

func TestStreamBeginMapLengthOverflow(t *testing.T) {
	if _, err := streamOps(ModePermissive, beginMap(math.MaxInt/2+1)); !errors.Is(err, ErrMaxArrayLength) {
		t.Fatalf("err = %v, want ErrMaxArrayLength", err)
	}
}

// 021 D6: deterministic modes verify key order instead of sorting.
func TestStreamDeterministicMapKeyOrder(t *testing.T) {
	deterministic := []Mode{ModeCoreDeterministic, ModeCanonical, ModeCTAP2}
	for _, mode := range deterministic {
		_, err := streamOps(mode, beginMap(2), wText("b"), wUint(1), wText("a"), wUint(2), end())
		if !errors.Is(err, ErrStreamMapOrder) || !errors.Is(err, ErrNotDeterministic) {
			t.Errorf("mode %d unsorted: err = %v, want ErrStreamMapOrder wrapping ErrNotDeterministic", mode, err)
		}
		_, err = streamOps(mode, beginMap(2), wText("a"), wUint(1), wText("a"), wUint(2), end())
		if !errors.Is(err, ErrStreamMapOrder) || !errors.Is(err, ErrDuplicateMapKey) {
			t.Errorf("mode %d duplicate: err = %v, want ErrStreamMapOrder wrapping ErrDuplicateMapKey", mode, err)
		}
	}
	if _, err := streamOps(ModePermissive, beginMap(2), wText("b"), wUint(1), wText("a"), wUint(2), end()); err != nil {
		t.Fatalf("permissive unsorted: %v", err)
	}

	// uint 100 (0x1864) sorts before "" (0x60) bytewise, after it
	// length-first.
	keysUintThenEmpty := []func(*StreamEncoder) error{beginMap(2), wUint(100), wUint(0), wText(""), wUint(0), end()}
	if _, err := streamOps(ModeCoreDeterministic, keysUintThenEmpty...); err != nil {
		t.Errorf("core deterministic: %v", err)
	}
	for _, mode := range []Mode{ModeCanonical, ModeCTAP2} {
		if _, err := streamOps(mode, keysUintThenEmpty...); !errors.Is(err, ErrStreamMapOrder) {
			t.Errorf("mode %d (length-first): err = %v, want ErrStreamMapOrder", mode, err)
		}
	}
}

// 021 D6: key bytes are captured across nested containers and tags.
func TestStreamDeterministicCompositeKeys(t *testing.T) {
	arrayKey := func(v uint64) []func(*StreamEncoder) error {
		return []func(*StreamEncoder) error{beginArray(1), wUint(v), end()}
	}
	ops := []func(*StreamEncoder) error{beginMap(2)}
	ops = append(ops, arrayKey(2)...)
	ops = append(ops, wUint(0))
	ops = append(ops, arrayKey(1)...)
	ops = append(ops, wUint(0), end())
	if _, err := streamOps(ModeCoreDeterministic, ops...); !errors.Is(err, ErrStreamMapOrder) {
		t.Fatalf("[2] then [1]: err = %v, want ErrStreamMapOrder", err)
	}

	// Key 1(5) is c105, which sorts after 00.
	_, err := streamOps(ModeCoreDeterministic, beginMap(2), wTag(1), wUint(5), wUint(0), wUint(0), wUint(0), end())
	if !errors.Is(err, ErrStreamMapOrder) {
		t.Fatalf("tagged key then 0: err = %v, want ErrStreamMapOrder", err)
	}
	// A tag at a value position is not part of the key.
	got, err := streamOps(ModeCoreDeterministic, beginMap(2), wUint(0), wTag(1), wUint(5), wUint(1), wUint(0), end())
	if err != nil {
		t.Fatal(err)
	}
	if want := "a200c1050100"; hex.EncodeToString(got) != want {
		t.Fatalf("wrote %x, want %s", got, want)
	}
}

// Streaming a map in sorted order yields the same bytes as Encode.
func TestStreamDeterministicMatchesEncode(t *testing.T) {
	m := MakeMap(
		MapEntry{Key: Uint(1), Value: Text("x")},
		MapEntry{Key: Text("a"), Value: MakeArray(Uint(1), Uint(2))},
		MapEntry{Key: Text("bb"), Value: Bool(true)},
		MapEntry{Key: NegInt(0), Value: Null()},
	)
	for _, mode := range []Mode{ModeCoreDeterministic, ModeCanonical, ModeCTAP2} {
		want, err := New(mode).Encode(nil, m)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := NewDecoder(WithoutInternalArena()).Decode(want)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		s := New(mode).Stream(&buf)
		if err := s.BeginMap(len(dec.Pairs)); err != nil {
			t.Fatal(err)
		}
		for _, p := range dec.Pairs {
			if err := s.WriteValue(p.Key); err != nil {
				t.Fatalf("mode %d key %v: %v", mode, p.Key, err)
			}
			if err := s.WriteValue(p.Value); err != nil {
				t.Fatalf("mode %d value: %v", mode, err)
			}
		}
		if err := s.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("mode %d: stream %x, Encode %x", mode, buf.Bytes(), want)
		}
	}
}

// 021 D14: simple values 24-31 are not well-formed (RFC 8949 §3.3).
func TestEncodeReservedSimple(t *testing.T) {
	for _, mode := range []Mode{ModePermissive, ModeCoreDeterministic, ModeCanonical, ModeCTAP2} {
		enc := New(mode)
		for v := 24; v < 32; v++ {
			if _, err := enc.Encode(nil, Simple(uint8(v))); !errors.Is(err, ErrReservedSimple) {
				t.Errorf("mode %d simple(%d): err = %v, want ErrReservedSimple", mode, v, err)
			}
		}
		if _, err := enc.Encode(nil, MakeArray(Simple(24))); !errors.Is(err, ErrReservedSimple) {
			t.Errorf("mode %d nested simple(24): err = %v", mode, err)
		}
		for v, want := range map[uint8]string{0: "e0", 19: "f3", 32: "f820", 255: "f8ff"} {
			got, err := enc.Encode(nil, Simple(v))
			if err != nil || hex.EncodeToString(got) != want {
				t.Errorf("mode %d simple(%d) = %x, %v; want %s", mode, v, got, err, want)
			}
		}
	}
	if _, err := streamOps(ModePermissive, func(s *StreamEncoder) error { return s.WriteSimple(24) }); !errors.Is(err, ErrReservedSimple) {
		t.Errorf("WriteSimple(24): err = %v", err)
	}
	if _, err := streamOps(ModePermissive, func(s *StreamEncoder) error { return s.WriteValue(Simple(31)) }); !errors.Is(err, ErrReservedSimple) {
		t.Errorf("WriteValue(Simple(31)): err = %v", err)
	}
}

// 021 D15: deterministic modes reject duplicate map keys (RFC 8949 §5.6).
func TestEncodeDeterministicDuplicateKeys(t *testing.T) {
	dup := MakeMap(
		MapEntry{Key: Text("a"), Value: Uint(1)},
		MapEntry{Key: Uint(1), Value: Uint(0)},
		MapEntry{Key: Text("a"), Value: Uint(2)},
	)
	for _, mode := range []Mode{ModeCoreDeterministic, ModeCanonical, ModeCTAP2} {
		if _, err := New(mode).Encode(nil, dup); !errors.Is(err, ErrDuplicateMapKey) {
			t.Errorf("mode %d: err = %v, want ErrDuplicateMapKey", mode, err)
		}
		// Keys that differ as Values but encode identically are duplicates.
		floats := MakeMap(MapEntry{Key: Float32(1), Value: Uint(1)}, MapEntry{Key: Float64(1), Value: Uint(2)})
		if mode != ModeCTAP2 { // CTAP2 forces float64, also identical
			if _, err := New(mode).Encode(nil, floats); !errors.Is(err, ErrDuplicateMapKey) {
				t.Errorf("mode %d float widths: err = %v, want ErrDuplicateMapKey", mode, err)
			}
		}
	}
	got, err := New(ModePermissive).Encode(nil, dup)
	if err != nil {
		t.Fatalf("permissive: %v", err)
	}
	if want := "a36161010100616102"; hex.EncodeToString(got) != want {
		t.Fatalf("permissive wrote %x, want %s (unchanged)", got, want)
	}
	if _, err := rfc8949.PrecomputeMapOrder([]Value{Text("a"), Text("a")}, rfc8949.SortBytewiseLex, rfc8949.EncodeOpts{}); !errors.Is(err, ErrDuplicateMapKey) {
		t.Errorf("PrecomputeMapOrder: err = %v, want ErrDuplicateMapKey", err)
	}
}

// 021 D16: a break outside an indefinite-length item is not well-formed.
func TestDecodeStrayBreak(t *testing.T) {
	cases := map[string]error{
		"ff":       ErrUnexpectedBreak, // top level
		"81ff":     ErrUnexpectedBreak, // definite array element
		"a101ff":   ErrUnexpectedBreak, // definite map value
		"bf01ff":   ErrUnexpectedBreak, // indefinite map: break where a value is due
		"c1ff":     ErrUnexpectedBreak, // tag content
		"1f":       ErrReservedAI,      // indefinite length on major type 0
		"3f":       ErrReservedAI,      // major type 1
		"df00":     ErrReservedAI,      // major type 6
		"821f00":   ErrReservedAI,      // inside an array (fast path)
		"a11f0000": ErrReservedAI,      // as a map key
	}
	for in, want := range cases {
		src, _ := hex.DecodeString(in)
		decoders := []*Decoder{NewDecoder()}
		if in != "bf01ff" && in != "c1ff" { // strict rejects the indefinite map / tag first
			decoders = append(decoders, StrictDecoder())
		}
		for _, dec := range decoders {
			if _, err := dec.Decode(src); !errors.Is(err, want) {
				t.Errorf("%s: err = %v, want %v", in, err, want)
			}
		}
	}
	for _, ok := range []string{"9fff", "9f01ff", "bf0102ff", "5fff", "7f6161ff"} {
		src, _ := hex.DecodeString(ok)
		if _, err := NewDecoder().Decode(src); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
}

// 021 D10 through the root API: consecutive DecodeFrom calls return
// consecutive items, and Stream keeps working over buffered and
// unbuffered readers.
func TestDecodeFromConsecutiveItems(t *testing.T) {
	src, _ := hex.DecodeString("01a1616182020318ff9f0102ff")
	want := []string{"1", `{"a": [2, 3]}`, "255", "[1, 2]"}
	readers := map[string]func() io.Reader{
		"bytes.Reader": func() io.Reader { return bytes.NewReader(src) },
		"one-byte":     func() io.Reader { return iotest.OneByteReader(bytes.NewReader(src)) },
		"half":         func() io.Reader { return iotest.HalfReader(bytes.NewReader(src)) },
		"data-err-eof": func() io.Reader { return iotest.DataErrReader(bytes.NewReader(src)) },
	}
	dec := NewDecoder(WithoutInternalArena())
	for name, mk := range readers {
		r := mk()
		for i, w := range want {
			v, err := dec.DecodeFrom(r)
			if err != nil {
				t.Fatalf("%s item %d: %v", name, i, err)
			}
			if got := DiagnosticValue(v); got != w {
				t.Errorf("%s item %d = %s, want %s", name, i, got, w)
			}
		}
		if _, err := dec.DecodeFrom(r); !errors.Is(err, io.EOF) {
			t.Errorf("%s after last item: err = %v, want io.EOF", name, err)
		}

		st := dec.Stream(mk())
		n := 0
		for st.Next() {
			n++
		}
		if st.Err() != nil || n != len(want) {
			t.Errorf("%s Stream: %d items, err %v", name, n, st.Err())
		}
	}
}

func TestDecodeFromTruncated(t *testing.T) {
	_, err := NewDecoder().DecodeFrom(bytes.NewReader([]byte{0x82, 0x01}))
	if !errors.Is(err, ErrTruncated) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want ErrTruncated and io.ErrUnexpectedEOF", err)
	}
}
