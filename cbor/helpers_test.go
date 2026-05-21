package cbor_test

import (
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func TestAsStringMap_AllText(t *testing.T) {
	m := cbor.Map{
		{Key: cbor.Text("name"), Value: cbor.Text("alice")},
		{Key: cbor.Text("age"), Value: cbor.Uint(30)},
	}
	got, err := m.AsStringMap()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got["name"] != cbor.Text("alice") {
		t.Errorf("name = %v, want alice", got["name"])
	}
	if got["age"] != cbor.Uint(30) {
		t.Errorf("age = %v, want 30", got["age"])
	}
}

func TestAsStringMap_NonTextKey(t *testing.T) {
	m := cbor.Map{
		{Key: cbor.Uint(1), Value: cbor.Text("one")},
	}
	_, err := m.AsStringMap()
	if !errors.Is(err, cbor.ErrNonStringKey) {
		t.Fatalf("expected ErrNonStringKey, got %v", err)
	}
}

func TestAsStringMap_Empty(t *testing.T) {
	m := cbor.Map{}
	got, err := m.AsStringMap()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(got))
	}
}
