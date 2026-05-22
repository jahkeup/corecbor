// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func TestEncodeSequence_Basic(t *testing.T) {
	items := []Value{
		cbor.Uint(1),
		cbor.Text("hello"),
		cbor.Bool(true),
	}
	got, err := EncodeSequence(nil, items...)
	if err != nil {
		t.Fatal(err)
	}

	var want []byte
	enc := New(ModeCoreDeterministic)
	for _, item := range items {
		b, err := enc.Encode(nil, item)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, b...)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestDecodeSequence_Basic(t *testing.T) {
	items := []Value{
		cbor.Uint(1),
		cbor.Text("hello"),
		cbor.Bool(true),
	}
	encoded, err := EncodeSequence(nil, items...)
	if err != nil {
		t.Fatal(err)
	}

	seq, err := DecodeSequence(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(seq) != len(items) {
		t.Fatalf("got %d items, want %d", len(seq), len(items))
	}
	for i, item := range items {
		if seq[i] != item {
			t.Errorf("item[%d]: got %v, want %v", i, seq[i], item)
		}
	}
}

func TestSequence_RoundTrip(t *testing.T) {
	original := Sequence{
		cbor.Uint(42),
		cbor.NegInt(7),
		cbor.Bytes{0xde, 0xad, 0xbe, 0xef},
		cbor.Text("world"),
		cbor.Bool(false),
		cbor.Null{},
	}

	encoded, err := original.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	var decoded Sequence
	if err := decoded.UnmarshalCBOR(encoded); err != nil {
		t.Fatal(err)
	}

	if len(decoded) != len(original) {
		t.Fatalf("got %d items, want %d", len(decoded), len(original))
	}
	for i, item := range original {
		if !reflect.DeepEqual(decoded[i], item) {
			t.Errorf("item[%d]: got %v, want %v", i, decoded[i], item)
		}
	}
}

func TestSequence_Empty(t *testing.T) {
	encoded, err := EncodeSequence(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 0 {
		t.Fatalf("empty sequence should encode to empty bytes, got %x", encoded)
	}

	seq, err := DecodeSequence(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(seq) != 0 {
		t.Fatalf("empty bytes should decode to empty sequence, got %v", seq)
	}
}

func TestMarshalSequence(t *testing.T) {
	got, err := MarshalSequence(uint64(1), "hello", true)
	if err != nil {
		t.Fatal(err)
	}

	want, err := EncodeSequence(nil, cbor.Uint(1), cbor.Text("hello"), cbor.Bool(true))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestSequence_MarshalerInterface(t *testing.T) {
	var _ Marshaler = Sequence{}
	var _ Unmarshaler = (*Sequence)(nil)

	seq := Sequence{cbor.Uint(10), cbor.Text("test")}

	data, err := seq.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty encoded data")
	}

	var decoded Sequence
	if err := decoded.UnmarshalCBOR(data); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(seq) {
		t.Fatalf("got %d items, want %d", len(decoded), len(seq))
	}
	for i, item := range seq {
		if !reflect.DeepEqual(decoded[i], item) {
			t.Errorf("item[%d]: got %v, want %v", i, decoded[i], item)
		}
	}
}
