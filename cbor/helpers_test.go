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
