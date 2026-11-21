// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/rfc8949"
)

// Proposal 023: structured decoder and reflection errors.

func TestDecodeErrorOffsets(t *testing.T) {
	cases := []struct {
		name string
		dec  *Decoder
		hex  string
		want error
		off  int
		text string
	}{
		{"truncated", NewDecoder(), "8201", ErrTruncated, 0, "cbor: unexpected end of input at offset 0"},
		{"reserved-ai", NewDecoder(), "1c", ErrReservedAI, 0, "cbor: reserved additional information value at offset 0"},
		{"stray-break", NewDecoder(), "ff", ErrUnexpectedBreak, 0, ""},
		{"trailing", NewDecoder(), "0102", ErrTrailingBytes, 1, "decode: cbor: trailing bytes after value"},
		{"non-shortest", StrictDecoder(), "1801", ErrNonShortest, 0, ""},
		{"indefinite", StrictDecoder(), "9fff", ErrIndefiniteLength, 0, ""},
		{"invalid-utf8", StrictDecoder(), "61ff", ErrInvalidUTF8, 0, ""},
		{"dup-key", StrictDecoder(), "a2616101616102", ErrDuplicateMapKey, 4, ""},
		{"non-finite", StrictDecoder(), "f97e00", ErrNonFiniteFloat, 0, ""},
		{"null-key", StrictDecoder(), "a1f601", ErrNullMapKey, 1, ""},
		{"unknown-tag", NewDecoder(RejectUnknownTags()), "8201d280", ErrUnknownTag, 2, ""},
		{"depth", NewDecoder(WithMaxNestingDepth(1)), "818100", ErrMaxNestingDepth, 2, ""},
		{"array-len", NewDecoder(WithMaxArrayLength(1)), "820102", ErrMaxArrayLength, 0, ""},
		{"bytes-len", NewDecoder(WithMaxByteStringLength(1)), "420102", ErrMaxByteStringLength, 0, ""},
		{"budget", NewDecoder(WithMemoryBudget(4), WithoutInternalArena()), "8101", cbor.ErrMemoryBudgetExceeded, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.dec.Decode(mustHex(t, tc.hex))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			var de *DecodeError
			if !errors.As(err, &de) {
				t.Fatalf("err %T is not a *DecodeError", err)
			}
			if de.Offset != tc.off {
				t.Errorf("Offset = %d, want %d (err %v)", de.Offset, tc.off, err)
			}
			if tc.text != "" && err.Error() != tc.text {
				t.Errorf("Error() = %q, want %q", err.Error(), tc.text)
			}
		})
	}
}

func TestDecodeErrorFromCursorAndHelpers(t *testing.T) {
	var de *DecodeError
	_, err := NewDecoder().Cursor(mustHex(t, "01")).EnterArray()
	if !errors.As(err, &de) || !errors.Is(err, ErrTypeMismatch) {
		t.Errorf("Cursor.EnterArray on uint: %v (%T)", err, err)
	}
	_, _, err = rfc8949.DecodeUintArray(mustHex(t, "8161"), rfc8949.DecodeOpts{})
	if !errors.As(err, &de) {
		t.Errorf("DecodeUintArray: %v (%T)", err, err)
	}
	// rfc8949.ErrTypeMismatch keeps its identity and text.
	if !errors.Is(err, rfc8949.ErrTypeMismatch) || rfc8949.ErrTypeMismatch.Error() != "cbor: type mismatch" {
		t.Errorf("rfc8949.ErrTypeMismatch: %v", err)
	}
}

func TestUnmarshalTypeError(t *testing.T) {
	type Header struct {
		Alg int `cbor:"1"`
	}
	type Msg struct {
		Header Header `cbor:"h"`
	}
	var m Msg
	err := Unmarshal(mustHex(t, "a16168a1016474657874"), &m) // {"h": {1: "text"}}
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("err = %v, want ErrTypeMismatch", err)
	}
	var ute *UnmarshalTypeError
	if !errors.As(err, &ute) {
		t.Fatalf("err %T is not *UnmarshalTypeError", err)
	}
	if ute.Field != "Header.Alg" || ute.CBORKind != cbor.KindText || ute.GoType.Kind().String() != "int" {
		t.Errorf("UnmarshalTypeError = %+v", ute)
	}
	if want := "cbor: cannot decode Text into Go type int"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}

	var i8 int8
	err = Unmarshal(mustHex(t, "190100"), &i8) // 256
	if !errors.Is(err, ErrOverflow) || !errors.As(err, &ute) || ute.CBORKind != cbor.KindUint {
		t.Errorf("overflow: %v (%T)", err, err)
	}
	if want := "cbor: integer overflow for target type: 256 into int8"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
	var f32 float32
	err = Unmarshal(mustHex(t, "fb7fefffffffffffff"), &f32)
	if !errors.As(err, &ute) || ute.CBORKind != cbor.KindFloat64 {
		t.Errorf("float overflow: %v (%T)", err, err)
	}
}

func TestEncodeInvalidKind(t *testing.T) {
	_, err := New(ModePermissive).Encode(nil, Value{Kind: 0x7e})
	if !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("err = %v, want ErrInvalidKind", err)
	}
	if want := "encode: unsupported Value kind 126"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}
