// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// Arena allocation accounting (proposal 036 item 19). The arena backs
// container storage ([]Value, []MapEntry); text and byte strings are
// separate allocations unless interned or decoded zero-copy, because
// WithArena documents that only container backing is arena-owned and
// strings must stay valid after Reset.

func nestedMapFixture(t testing.TB) []byte {
	t.Helper()
	inner := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("x"), Value: cbor.Uint(1)},
		cbor.MapEntry{Key: cbor.Text("y"), Value: cbor.Uint(2)},
	)
	mid := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("alpha"), Value: inner},
		cbor.MapEntry{Key: cbor.Text("beta"), Value: inner},
		cbor.MapEntry{Key: cbor.Text("gamma"), Value: cbor.MakeArray(cbor.Uint(1), cbor.Uint(2), cbor.Uint(3))},
	)
	outer := cbor.MakeMap(
		cbor.MapEntry{Key: cbor.Text("level1a"), Value: mid},
		cbor.MapEntry{Key: cbor.Text("level1b"), Value: mid},
		cbor.MapEntry{Key: cbor.Text("level1c"), Value: cbor.Bytes([]byte{0xde, 0xad, 0xbe, 0xef})},
	)
	data, err := Encode(nil, outer, EncodeOpts{Deterministic: true, SortMode: SortBytewiseLex, FloatMode: FloatShortest})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestArenaNestedMapAllocs(t *testing.T) {
	data := nestedMapFixture(t)
	cases := []struct {
		name string
		opts func() DecodeOpts
		max  float64
	}{
		// Only strings allocate: every container is arena-backed.
		{"arena", func() DecodeOpts { return DecodeOpts{Arena: NewArena(64, 64)} }, 10},
		// Interned keys allocate nothing; the one byte string remains.
		{"arena+intern", func() DecodeOpts {
			return DecodeOpts{Arena: NewArena(64, 64), Interner: NewStringInterner(64)}
		}, 1},
		// Zero-copy strings alias the source.
		{"arena+zerocopy", func() DecodeOpts { return DecodeOpts{Arena: NewArena(64, 64), ZeroCopy: true} }, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts()
			if _, _, err := Decode(data, opts); err != nil { // warm arena and interner
				t.Fatal(err)
			}
			got := testing.AllocsPerRun(100, func() {
				opts.Arena.Reset()
				if _, _, err := Decode(data, opts); err != nil {
					t.Fatal(err)
				}
			})
			if got > tc.max {
				t.Fatalf("allocs = %v, want <= %v", got, tc.max)
			}
			t.Logf("allocs = %v", got)
		})
	}
}
