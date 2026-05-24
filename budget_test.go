// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func TestMemoryBudgetExceeded(t *testing.T) {
	enc := New(ModePermissive)
	bigArray := make(Array, 1000)
	for i := range bigArray {
		bigArray[i] = Uint(uint64(i))
	}
	data, _ := enc.Encode(nil, bigArray)

	dec := NewDecoder(WithMemoryBudget(100))
	_, err := dec.Decode(data)
	if err == nil {
		t.Fatal("expected budget error")
	}
	if !errors.Is(err, cbor.ErrMemoryBudgetExceeded) {
		t.Fatalf("expected ErrMemoryBudgetExceeded, got: %v", err)
	}
}

func TestMemoryBudgetSufficientPasses(t *testing.T) {
	enc := New(ModePermissive)
	small := Array{Uint(1), Uint(2), Uint(3)}
	data, _ := enc.Encode(nil, small)

	dec := NewDecoder(WithMemoryBudget(1 << 20))
	_, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("sufficient budget should not error: %v", err)
	}
}

func TestMemoryBudgetResetBetweenCalls(t *testing.T) {
	enc := New(ModePermissive)
	m := Map{
		{Key: Text("a"), Value: Bytes(make([]byte, 50))},
		{Key: Text("b"), Value: Bytes(make([]byte, 50))},
	}
	data, _ := enc.Encode(nil, m)

	dec := NewDecoder(WithMemoryBudget(500))
	_, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	_, err = dec.Decode(data)
	if err != nil {
		t.Fatalf("second decode should succeed (budget reset): %v", err)
	}
}

func TestMemoryBudgetDisabledByDefault(t *testing.T) {
	enc := New(ModePermissive)
	bigArray := make(Array, 10000)
	for i := range bigArray {
		bigArray[i] = Uint(uint64(i))
	}
	data, _ := enc.Encode(nil, bigArray)

	dec := NewDecoder()
	_, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("no budget should allow anything: %v", err)
	}
}

func TestMemoryBudgetMapExceeded(t *testing.T) {
	enc := New(ModePermissive)
	m := make(Map, 100)
	for i := range m {
		m[i] = MapEntry{Key: Text("key"), Value: Uint(uint64(i))}
	}
	data, _ := enc.Encode(nil, m)

	dec := NewDecoder(WithMemoryBudget(100))
	_, err := dec.Decode(data)
	if !errors.Is(err, cbor.ErrMemoryBudgetExceeded) {
		t.Fatalf("expected ErrMemoryBudgetExceeded, got: %v", err)
	}
}

func TestMemoryBudgetBytesExceeded(t *testing.T) {
	enc := New(ModePermissive)
	data, _ := enc.Encode(nil, Bytes(make([]byte, 1000)))

	dec := NewDecoder(WithMemoryBudget(500))
	_, err := dec.Decode(data)
	if !errors.Is(err, cbor.ErrMemoryBudgetExceeded) {
		t.Fatalf("expected ErrMemoryBudgetExceeded for large bytes, got: %v", err)
	}
}

func TestMemoryBudgetTextExceeded(t *testing.T) {
	enc := New(ModePermissive)
	data, _ := enc.Encode(nil, Text(string(make([]byte, 1000))))

	dec := NewDecoder(WithMemoryBudget(500))
	_, err := dec.Decode(data)
	if !errors.Is(err, cbor.ErrMemoryBudgetExceeded) {
		t.Fatalf("expected ErrMemoryBudgetExceeded for large text, got: %v", err)
	}
}

func TestMemoryBudgetNilSafe(t *testing.T) {
	enc := New(ModePermissive)
	data, _ := enc.Encode(nil, Uint(42))
	dec := NewDecoder()
	_, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("nil budget (no WithMemoryBudget) should pass: %v", err)
	}
}
