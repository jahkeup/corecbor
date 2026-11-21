// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"unicode/utf8"

	"github.com/jahkeup/corecbor/cbor"
)

var encodeModes = []Mode{ModePermissive, ModeCoreDeterministic, ModeCanonical, ModeCTAP2, ModePreferredPlus}

// The proposal 035 encoder table, for every policy and mode.
func TestInvalidUTF8EncodePolicy(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want map[InvalidUTF8]string // "" = ErrInvalidUTF8
	}{
		{"valid", "ab", map[InvalidUTF8]string{
			InvalidUTF8Reject: "626162", InvalidUTF8Allow: "626162",
			InvalidUTF8Replace: "626162", InvalidUTF8Lossless: "626162",
		}},
		{"one-byte", "a\xffb", map[InvalidUTF8]string{
			InvalidUTF8Reject: "", InvalidUTF8Allow: "6361ff62",
			InvalidUTF8Replace: "6561efbfbd62", InvalidUTF8Lossless: "4361ff62",
		}},
		{"two-bytes", "a\xff\xfeb", map[InvalidUTF8]string{
			InvalidUTF8Reject: "", InvalidUTF8Allow: "6461fffe62",
			InvalidUTF8Replace: "6861efbfbdefbfbd62", InvalidUTF8Lossless: "4461fffe62",
		}},
		{"wtf8-surrogate", "x\xed\xa0\x80y", map[InvalidUTF8]string{
			InvalidUTF8Reject: "", InvalidUTF8Allow: "6578eda08079",
			InvalidUTF8Replace: "6b78efbfbdefbfbdefbfbd79", InvalidUTF8Lossless: "d901114578eda08079",
		}},
	}
	for _, mode := range encodeModes {
		for _, c := range cases {
			for pol, want := range c.want {
				enc := New(mode, WithInvalidUTF8(pol))
				got, err := enc.Encode(nil, Text(c.in))
				if want == "" {
					if !errors.Is(err, ErrInvalidUTF8) {
						t.Errorf("mode %d %s policy %d: err = %v, want ErrInvalidUTF8", mode, c.name, pol, err)
					}
					continue
				}
				if err != nil || hex.EncodeToString(got) != want {
					t.Errorf("mode %d %s policy %d: %x, %v; want %s", mode, c.name, pol, got, err, want)
				}
				// Nested positions follow the same policy.
				arr, err := enc.Encode(nil, MakeArray(Text(c.in)))
				if err != nil || hex.EncodeToString(arr) != "81"+want {
					t.Errorf("mode %d %s policy %d in array: %x, %v; want 81%s", mode, c.name, pol, arr, err, want)
				}
			}
		}
	}
}

// AllowInvalidUTF8() is WithInvalidUTF8(InvalidUTF8Allow), and the
// default rejects at every position.
func TestInvalidUTF8AllowEquivalence(t *testing.T) {
	v := MakeMap(
		MapEntry{Key: Text("k\xff"), Value: MakeArray(Text("a\xffb"))},
		MapEntry{Key: Text("j"), Value: Text("\xfe")},
	)
	for _, mode := range encodeModes {
		a, errA := New(mode, AllowInvalidUTF8()).Encode(nil, v)
		b, errB := New(mode, WithInvalidUTF8(InvalidUTF8Allow)).Encode(nil, v)
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			t.Errorf("mode %d: AllowInvalidUTF8 %x/%v vs policy %x/%v", mode, a, errA, b, errB)
		}
		if _, err := New(mode).Encode(nil, v); !errors.Is(err, ErrInvalidUTF8) {
			t.Errorf("mode %d default: err = %v, want ErrInvalidUTF8", mode, err)
		}
	}
}

// Map keys: deterministic modes sort by the bytes written, and keys that
// become equal under Replace are duplicates.
func TestInvalidUTF8MapKeys(t *testing.T) {
	enc := New(ModeCoreDeterministic, WithInvalidUTF8(InvalidUTF8Lossless))
	got, err := enc.Encode(nil, MakeMap(
		MapEntry{Key: Text("b"), Value: Uint(1)},
		MapEntry{Key: Text("a\xff"), Value: Uint(2)}, // becomes byte string 4261ff: sorts first
	))
	if err != nil || hex.EncodeToString(got) != "a24261ff0261620"+"1" {
		t.Errorf("lossless key sort: %x, %v", got, err)
	}
	_, err = New(ModeCoreDeterministic, WithInvalidUTF8(InvalidUTF8Replace)).Encode(nil, MakeMap(
		MapEntry{Key: Text("a\xff"), Value: Uint(1)},
		MapEntry{Key: Text("a\xfe"), Value: Uint(2)},
	))
	if !errors.Is(err, ErrDuplicateMapKey) {
		t.Errorf("replace collision: err = %v, want ErrDuplicateMapKey", err)
	}
}

func TestInvalidUTF8UnknownPolicy(t *testing.T) {
	if _, err := New(ModePermissive, WithInvalidUTF8(InvalidUTF8(99))).Encode(nil, Text("\xff")); !errors.Is(err, ErrInvalidOption) {
		t.Errorf("err = %v, want ErrInvalidOption", err)
	}
}

func TestWTF8Detection(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
	}{
		{"ab", "626162"},
		{"x\xed\xa0\x80y", "d901114578eda08079"},
		{"\xed\xa0\x80\xed\xb0\x80", "46eda080edb080"}, // lead+trail pair is not WTF-8
		{"\xed\xa0\x80\xff", "44eda080ff"},
		{"a\xffb", "4361ff62"},
	} {
		got, err := New(ModeCoreDeterministic).Encode(nil, TextLossless(c.in))
		if err != nil || hex.EncodeToString(got) != c.want {
			t.Errorf("TextLossless(%q) = %x, %v; want %s", c.in, got, err, c.want)
		}
		back, err := AsText(TextLossless(c.in))
		if err != nil || back != c.in {
			t.Errorf("AsText(TextLossless(%q)) = %q, %v", c.in, back, err)
		}
	}
	for _, tag := range []uint64{TagCESU8, TagWTF8, TagMUTF8} {
		if s, err := AsText(cbor.MakeTag(tag, Bytes([]byte("x")))); err != nil || s != "x" {
			t.Errorf("AsText(tag %d) = %q, %v", tag, s, err)
		}
	}
	if _, err := AsText(Uint(1)); !errors.Is(err, ErrTypeMismatch) {
		t.Errorf("AsText(Uint) err = %v, want ErrTypeMismatch", err)
	}
}

func TestInvalidUTF8DecodePolicy(t *testing.T) {
	// {"k\xff": "a\xffb", "i": (_ "x\xff", "y")} with an indefinite text
	data := mustHex(t, "a2"+"626bff"+"6361ff62"+"6169"+"7f6278ff6179ff")
	cases := []struct {
		name string
		opts []DecoderOption
		want string // DiagnosticValue, or "" for ErrInvalidUTF8
	}{
		{"default-allow", nil, `{/ text, invalid UTF-8 / h'6bff': / text, invalid UTF-8 / h'61ff62', "i": / text, invalid UTF-8 / h'78ff79'}`},
		{"reject", []DecoderOption{WithInvalidUTF8Decoding(InvalidUTF8Reject)}, ""},
		{"reject-legacy", []DecoderOption{RejectInvalidUTF8()}, ""},
		{"replace", []DecoderOption{WithInvalidUTF8Decoding(InvalidUTF8Replace)}, `{"k�": "a�b", "i": "x�y"}`},
		{"replace-after-reject", []DecoderOption{RejectInvalidUTF8(), WithInvalidUTF8Decoding(InvalidUTF8Replace)}, `{"k�": "a�b", "i": "x�y"}`},
	}
	for _, c := range cases {
		v, err := NewDecoder(c.opts...).Decode(data)
		if c.want == "" {
			if !errors.Is(err, ErrInvalidUTF8) {
				t.Errorf("%s: err = %v, want ErrInvalidUTF8", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := DiagnosticValue(v); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestInvalidUTF8UnmarshalLossless(t *testing.T) {
	type S struct {
		A string `cbor:"a"`
		B string `cbor:"b"`
		C string `cbor:"c"`
	}
	in := S{A: "ok", B: "x\xed\xa0\x80y", C: "a\xffb"}
	enc := New(ModeCoreDeterministic, WithInvalidUTF8(InvalidUTF8Lossless))
	data, err := enc.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out S
	if err := NewDecoder(WithInvalidUTF8Decoding(InvalidUTF8Lossless)).Unmarshal(data, &out); err != nil || out != in {
		t.Fatalf("lossless round trip = %+v, %v; want %+v", out, err, in)
	}
	// Without Lossless decoding, a byte string is not a string.
	if err := NewDecoder().Unmarshal(data, &out); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("default decoding: err = %v, want ErrTypeMismatch", err)
	}
}

func TestStreamInvalidUTF8Policy(t *testing.T) {
	for pol, want := range map[InvalidUTF8]string{
		InvalidUTF8Allow:    "826361ff626361ff62",
		InvalidUTF8Replace:  "826561efbfbd626561efbfbd62",
		InvalidUTF8Lossless: "824361ff624361ff62",
	} {
		var buf bytes.Buffer
		s := New(ModeCoreDeterministic, WithInvalidUTF8(pol)).Stream(&buf)
		if err := s.BeginArray(2); err != nil {
			t.Fatal(err)
		}
		if err := s.WriteText("a\xffb"); err != nil {
			t.Fatalf("policy %d WriteText: %v", pol, err)
		}
		if err := s.WriteValue(Text("a\xffb")); err != nil {
			t.Fatalf("policy %d WriteValue: %v", pol, err)
		}
		if err := s.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(buf.Bytes()); got != want {
			t.Errorf("policy %d: %s, want %s", pol, got, want)
		}
	}
	var buf bytes.Buffer
	if err := New(ModePermissive).Stream(&buf).WriteText("\xff"); !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("default WriteText: err = %v", err)
	}
}

// FuzzInvalidUTF8Replace: Replace output is valid UTF-8 and equals the
// range-loop substitution of the input.
func FuzzInvalidUTF8Replace(f *testing.F) {
	for _, s := range []string{"", "ab", "a\xffb", "x\xed\xa0\x80y", "\xe2\x82", "€\x80"} {
		f.Add(s)
	}
	enc := NewShared(ModeCoreDeterministic, WithInvalidUTF8(InvalidUTF8Replace))
	dec := NewDecoder(WithoutInternalArena(), RejectInvalidUTF8())
	f.Fuzz(func(t *testing.T, s string) {
		var want []rune
		for _, r := range s {
			want = append(want, r)
		}
		out, err := enc.Encode(nil, Text(s))
		if err != nil {
			t.Fatal(err)
		}
		v, err := dec.Decode(out)
		if err != nil || v.Kind != KindText || v.Str != string(want) || !utf8.ValidString(v.Str) {
			t.Fatalf("Replace(%q) decoded %v, %v; want %q", s, v, err, string(want))
		}
	})
}

// FuzzInvalidUTF8Lossless: every Go string round-trips exactly, the
// output is conformant (no invalid text strings) and passes the
// deterministic checking decoder.
func FuzzInvalidUTF8Lossless(f *testing.F) {
	for _, s := range []string{"", "ab", "a\xffb", "x\xed\xa0\x80y", "\xed\xa0\x80\xed\xb0\x80"} {
		f.Add(s)
	}
	enc := NewShared(ModeCoreDeterministic, WithInvalidUTF8(InvalidUTF8Lossless))
	strict := NewDecoder(WithoutInternalArena(), RejectInvalidUTF8(), RequireDeterministic())
	f.Fuzz(func(t *testing.T, s string) {
		out, err := enc.Encode(nil, MakeArray(Text(s), MakeMap(MapEntry{Key: Text(s), Value: Uint(1)})))
		if err != nil {
			t.Fatal(err)
		}
		v, err := strict.Decode(out)
		if err != nil {
			t.Fatalf("%q: lossless output rejected by strict deterministic decoder: %v (%x)", s, err, out)
		}
		got, err := AsText(v.Items[0])
		if err != nil || got != s {
			t.Fatalf("AsText = %q, %v; want %q", got, err, s)
		}
		key, err := AsText(v.Items[1].Pairs[0].Key)
		if err != nil || key != s {
			t.Fatalf("key AsText = %q, %v; want %q", key, err, s)
		}
	})
}
