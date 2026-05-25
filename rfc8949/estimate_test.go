// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func TestEstimateSizeNeverUnderestimates(t *testing.T) {
	values := []cbor.Value{
		cbor.Uint(0), cbor.Uint(23), cbor.Uint(24), cbor.Uint(255),
		cbor.Uint(256), cbor.Uint(65535), cbor.Uint(65536),
		cbor.Uint(0xffffffff), cbor.Uint(0x100000000),
		cbor.NegInt(0), cbor.NegInt(1000),
		cbor.Bytes(nil),
		cbor.Bytes([]byte{0x01, 0x02, 0x03}),
		cbor.Bytes(make([]byte, 300)),
		cbor.Text(""), cbor.Text("hello"),
		cbor.Text(string(make([]byte, 300))),
		cbor.MakeArray(cbor.Uint(1), cbor.Uint(2), cbor.Uint(3)),
		cbor.MakeArray(),
		cbor.MakeMap(
			cbor.MapEntry{Key: cbor.Text("a"), Value: cbor.Uint(1)},
			cbor.MapEntry{Key: cbor.Text("b"), Value: cbor.Uint(2)},
		),
		cbor.MakeMap(),
		cbor.MakeTag(1, cbor.Uint(42)),
		cbor.MakeTag(55799, cbor.Text("self")),
		cbor.Bool(true), cbor.Bool(false),
		cbor.Null(), cbor.Undefined(),
		cbor.Simple(0), cbor.Simple(19), cbor.Simple(32), cbor.Simple(255),
		cbor.Float32(1.5), cbor.Float64(3.14159),
	}

	for _, v := range values {
		estimated := EstimateSize(v)
		actual, err := Encode(nil, v, EncodeOpts{})
		if err != nil {
			t.Fatalf("encode kind %d: %v", v.Kind, err)
		}
		if estimated < len(actual) {
			t.Errorf("EstimateSize(kind %d) = %d, actual encoded = %d (UNDERESTIMATE)",
				v.Kind, estimated, len(actual))
		}
	}
}

func TestEstimateSizeNested(t *testing.T) {
	nested := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("inner"), Value: cbor.MakeArray(
			cbor.Uint(1),
			cbor.Bytes([]byte{0xde, 0xad}),
			cbor.MakeMap(
				cbor.MapEntry{Key: cbor.Text("deep"), Value: cbor.MakeTag(1, cbor.Uint(999))},
			),
		)},
	)
	estimated := EstimateSize(nested)
	actual, err := Encode(nil, nested, EncodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if estimated < len(actual) {
		t.Errorf("nested: estimate %d < actual %d", estimated, len(actual))
	}
	overestimate := estimated - len(actual)
	if overestimate > 9*10 {
		t.Errorf("overestimate too large: %d bytes (estimate=%d, actual=%d)",
			overestimate, estimated, len(actual))
	}
}

func TestEstimateSizeZero(t *testing.T) {
	if got := EstimateSize(cbor.Value{}); got != 0 {
		t.Errorf("EstimateSize(zero) = %d, want 0", got)
	}
}

func TestEncodeWithHintPreAllocates(t *testing.T) {
	v := cbor.MakeArray(cbor.Uint(1), cbor.Uint(2), cbor.Uint(3))
	hint := EstimateSize(v)
	dst, err := EncodeWithHint(nil, v, EncodeOpts{}, hint)
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := Encode(nil, v, EncodeOpts{})
	if len(dst) != len(expected) {
		t.Fatalf("len mismatch: got %d, want %d", len(dst), len(expected))
	}
	for i := range dst {
		if dst[i] != expected[i] {
			t.Fatalf("byte %d: got %02x, want %02x", i, dst[i], expected[i])
		}
	}
}

func TestEncodeWithHintExistingCapacity(t *testing.T) {
	v := cbor.Uint(42)
	dst := make([]byte, 0, 100)
	result, err := EncodeWithHint(dst, v, EncodeOpts{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if cap(result) != 100 {
		t.Errorf("should reuse existing capacity: got cap=%d, want 100", cap(result))
	}
}

func BenchmarkEncodePresized(b *testing.B) {
	m := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("alg"), Value: cbor.NegInt(6)},
		cbor.MapEntry{Key: cbor.Text("kid"), Value: cbor.Bytes([]byte{0x01, 0x02, 0x03, 0x04})},
		cbor.MapEntry{Key: cbor.Text("data"), Value: cbor.Bytes(make([]byte, 64))},
	)
	hint := EstimateSize(m)
	b.ResetTimer()
	for range b.N {
		EncodeWithHint(nil, m, EncodeOpts{Deterministic: true}, hint) //nolint:errcheck
	}
}

func BenchmarkEncodeNoHint(b *testing.B) {
	m := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("alg"), Value: cbor.NegInt(6)},
		cbor.MapEntry{Key: cbor.Text("kid"), Value: cbor.Bytes([]byte{0x01, 0x02, 0x03, 0x04})},
		cbor.MapEntry{Key: cbor.Text("data"), Value: cbor.Bytes(make([]byte, 64))},
	)
	b.ResetTimer()
	for range b.N {
		Encode(nil, m, EncodeOpts{Deterministic: true}) //nolint:errcheck
	}
}
