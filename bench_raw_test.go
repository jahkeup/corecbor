// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import "testing"

type benchRecord struct {
	ID    uint64            `cbor:"1"`
	Name  string            `cbor:"name"`
	Tags  []string          `cbor:"tags"`
	Attrs map[string]string `cbor:"attrs"`
	Blob  []byte            `cbor:"blob"`
}

type benchRecordRaw struct {
	ID    uint64            `cbor:"1"`
	Name  string            `cbor:"name"`
	Tags  []string          `cbor:"tags"`
	Attrs map[string]string `cbor:"attrs"`
	Blob  RawMessage        `cbor:"blob"`
}

func benchRecordBytes(b *testing.B) []byte {
	b.Helper()
	data, err := Marshal(benchRecord{
		ID: 7, Name: "sensor-42", Tags: []string{"a", "b", "c"},
		Attrs: map[string]string{"loc": "lab", "fw": "1.2.3"},
		Blob:  make([]byte, 64),
	})
	if err != nil {
		b.Fatal(err)
	}
	return data
}

// BenchmarkUnmarshalStruct: target with no Unmarshaler (Value path).
func BenchmarkUnmarshalStruct(b *testing.B) {
	data := benchRecordBytes(b)
	dec := NewDecoder()
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		var r benchRecord
		if err := dec.Unmarshal(data, &r); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUnmarshalStructRawMessage: same input with a RawMessage
// field (raw-span path since proposal 022).
func BenchmarkUnmarshalStructRawMessage(b *testing.B) {
	data := benchRecordBytes(b)
	dec := NewDecoder()
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		var r benchRecordRaw
		if err := dec.Unmarshal(data, &r); err != nil {
			b.Fatal(err)
		}
	}
}
