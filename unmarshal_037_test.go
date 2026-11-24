// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"errors"
	"math/big"
	"testing"
	"time"
)

// 037 C15: by default Unmarshal stores a tag's content into a target
// that has no place for the tag number; DisallowDroppedTags (and
// UnmarshalStrict) make that an error instead.
func TestC15DroppedTags(t *testing.T) {
	unknown := []byte{0xd9, 0x03, 0xe7, 0x05} // 999(5)
	var n int
	if err := Unmarshal(unknown, &n); err != nil || n != 5 {
		t.Fatalf("default: %d, %v; want 5, nil", n, err)
	}
	strict := NewDecoder(DisallowDroppedTags())
	if err := strict.Unmarshal(unknown, &n); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("DisallowDroppedTags into int: %v, want ErrTypeMismatch", err)
	}
	if err := UnmarshalStrict(unknown, &n); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("UnmarshalStrict into int: %v, want ErrTypeMismatch", err)
	}
	// Nested inside a struct field and a slice.
	var s struct {
		A []int `cbor:"a"`
	}
	if err := strict.Unmarshal([]byte{0xa1, 0x61, 0x61, 0x81, 0xd9, 0x03, 0xe7, 0x05}, &s); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("nested: %v", err)
	}

	// Targets that keep the tag are fine.
	var v Value
	var a any
	var rt RawTag
	for _, target := range []any{&v, &a, &rt} {
		if err := strict.Unmarshal(unknown, target); err != nil {
			t.Fatalf("%T: %v", target, err)
		}
	}
	var tm time.Time
	if err := strict.Unmarshal([]byte{0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0}, &tm); err != nil {
		t.Fatalf("tag 1 into time.Time: %v", err)
	}
	var bi big.Int
	if err := strict.Unmarshal([]byte{0xc2, 0x41, 0x01}, &bi); err != nil {
		t.Fatalf("tag 2 into big.Int: %v", err)
	}
	// A tag 1 epoch into an integer drops the tag number too.
	if err := strict.Unmarshal([]byte{0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0}, &n); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("tag 1 into int: %v", err)
	}
	// A field that declares the tag keeps it, on both decode paths.
	var tagged struct {
		N int        `cbor:"n,tag=999"`
		R RawMessage `cbor:"r"`
	}
	src := []byte{0xa2, 0x61, 0x6e, 0xd9, 0x03, 0xe7, 0x05, 0x61, 0x72, 0x01}
	if err := strict.Unmarshal(src, &tagged); err != nil || tagged.N != 5 {
		t.Fatalf("declared field tag: %+v, %v", tagged, err)
	}
	var plain struct {
		N int `cbor:"n,tag=999"`
	}
	if err := strict.Unmarshal([]byte{0xa1, 0x61, 0x6e, 0xd9, 0x03, 0xe7, 0x05}, &plain); err != nil || plain.N != 5 {
		t.Fatalf("declared field tag (Value path): %+v, %v", plain, err)
	}
	// Self-describe (55799) means nothing, so dropping it loses nothing.
	if err := strict.Unmarshal([]byte{0x81, 0xd9, 0xd9, 0xf7, 0x05}, &s.A); err != nil || s.A[0] != 5 {
		t.Fatalf("nested 55799: %v, %v", s.A, err)
	}
}

// 037 C16: undefined and null both leave a Go target at its zero value
// by default; DisallowUndefined (and UnmarshalStrict) reject undefined
// where it would be read as null.
func TestC16Undefined(t *testing.T) {
	undef := []byte{0xf7}
	n := 7
	if err := Unmarshal(undef, &n); err != nil || n != 0 {
		t.Fatalf("default: %d, %v", n, err)
	}
	for _, d := range []func([]byte, any) error{NewDecoder(DisallowUndefined()).Unmarshal, UnmarshalStrict} {
		var p *int
		var a any
		for _, target := range []any{&n, &p, &a} {
			if err := d(undef, target); !errors.Is(err, ErrTypeMismatch) {
				t.Fatalf("%T: %v, want ErrTypeMismatch", target, err)
			}
		}
		var v Value
		if err := d(undef, &v); err != nil || v.Kind != KindUndefined {
			t.Fatalf("Value: %v, %v", v, err)
		}
		if err := d([]byte{0xf6}, &p); err != nil || p != nil {
			t.Fatalf("null: %v, %v", p, err)
		}
	}
}

// 037 C17: UnmarshalStrict applies StrictDecoder's checks.
func TestC17UnmarshalStrict(t *testing.T) {
	var n int
	if err := UnmarshalStrict([]byte{0x18, 0x01}, &n); !errors.Is(err, ErrNonShortest) {
		t.Fatalf("non-shortest: %v", err)
	}
	var m map[string]int
	if err := UnmarshalStrict([]byte{0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02}, &m); !errors.Is(err, ErrDuplicateMapKey) {
		t.Fatalf("duplicate key: %v", err)
	}
	if err := UnmarshalStrict([]byte{0x05}, &n); err != nil || n != 5 {
		t.Fatalf("valid: %d, %v", n, err)
	}
}
