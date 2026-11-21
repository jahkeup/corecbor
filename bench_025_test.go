// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import "testing"

type benchStruct6 struct {
	ID    uint64 `cbor:"1"`
	Name  string `cbor:"name"`
	Email string `cbor:"email,omitempty"`
	Age   int    `cbor:"age"`
	Tags  []string
	Admin bool `cbor:"admin"`
}

// BenchmarkMarshalStruct marshals a 6-field struct (proposal 025
// performance table).
func BenchmarkMarshalStruct(b *testing.B) {
	v := benchStruct6{ID: 7, Name: "ada", Email: "a@example.com", Age: 36, Tags: []string{"x", "y"}, Admin: true}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Marshal(v); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkValueGetInt looks up an integer label in an 8-entry map.
func BenchmarkValueGetInt(b *testing.B) {
	pairs := make([]MapEntry, 8)
	for i := range pairs {
		pairs[i] = MapEntry{Key: NegInt(uint64(i)), Value: Uint(uint64(i))}
	}
	m := MakeMapFromSlice(pairs)
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := m.GetInt(-8); !ok {
			b.Fatal("missing")
		}
	}
}
