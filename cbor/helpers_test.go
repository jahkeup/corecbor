// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor_test

import (
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func TestAsStringMap_AllText(t *testing.T) {
	m := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("name"), Value: cbor.Text("alice")},
		cbor.MapEntry{Key: cbor.Text("age"), Value: cbor.Uint(30)},
	)
	got, err := cbor.AsStringMap(m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got["name"].Kind != cbor.KindText || got["name"].TextVal() != "alice" {
		t.Errorf("name = %v, want alice", got["name"])
	}
	if got["age"].Kind != cbor.KindUint || got["age"].UintVal() != 30 {
		t.Errorf("age = %v, want 30", got["age"])
	}
}

func TestAsStringMap_NonTextKey(t *testing.T) {
	m := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Uint(1), Value: cbor.Text("one")},
	)
	_, err := cbor.AsStringMap(m)
	if !errors.Is(err, cbor.ErrNonStringKey) {
		t.Fatalf("expected ErrNonStringKey, got %v", err)
	}
}

func TestAsStringMap_Empty(t *testing.T) {
	m := cbor.MakeMap()
	got, err := cbor.AsStringMap(m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(got))
	}
}

func TestClone_Scalar(t *testing.T) {
	v := cbor.Uint(42)
	c := v.Clone()
	if c.Kind != cbor.KindUint || c.Num != 42 {
		t.Fatalf("clone of Uint(42) = %+v", c)
	}
}

func TestClone_Bytes(t *testing.T) {
	orig := []byte{1, 2, 3}
	v := cbor.Bytes(orig)
	c := v.Clone()
	orig[0] = 99
	if c.Bstr[0] != 1 {
		t.Fatal("clone shares backing array with original")
	}
}

func TestClone_Text(t *testing.T) {
	v := cbor.Text("hello")
	c := v.Clone()
	if c.Str != "hello" {
		t.Fatalf("clone text = %q, want hello", c.Str)
	}
}

func TestClone_Array(t *testing.T) {
	v := cbor.MakeArray(cbor.Uint(1), cbor.Uint(2))
	c := v.Clone()
	v.Items[0] = cbor.Uint(99)
	if c.Items[0].Num != 1 {
		t.Fatal("clone array shares backing with original")
	}
}

func TestClone_Map(t *testing.T) {
	v := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("a"), Value: cbor.Uint(1)},
	)
	c := v.Clone()
	v.Pairs[0].Value = cbor.Uint(99)
	if c.Pairs[0].Value.Num != 1 {
		t.Fatal("clone map shares backing with original")
	}
}

func TestClone_Tag(t *testing.T) {
	v := cbor.MakeTag(1, cbor.Text("epoch"))
	c := v.Clone()
	v.Items[0] = cbor.Text("modified")
	if c.Items[0].Str != "epoch" {
		t.Fatal("clone tag shares backing with original")
	}
}

func TestClone_DeepNested(t *testing.T) {
	inner := cbor.MakeArray(cbor.Bytes([]byte{0xAA}))
	v := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("k"), Value: inner},
	)
	c := v.Clone()
	v.Pairs[0].Value.Items[0].Bstr[0] = 0xFF
	if c.Pairs[0].Value.Items[0].Bstr[0] != 0xAA {
		t.Fatal("deep clone shares nested backing")
	}
}
