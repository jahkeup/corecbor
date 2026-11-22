// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// Tag inners come from the arena when one is set (proposal 036 item 22).

func tagArrayFixture(t testing.TB, n int) []byte {
	t.Helper()
	items := make([]cbor.Value, n)
	for i := range items {
		items[i] = cbor.MakeTag(uint64(100+i), cbor.Uint(uint64(i)))
	}
	data, err := Encode(nil, cbor.MakeArrayFromSlice(items), EncodeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestArenaTagInner(t *testing.T) {
	arena := NewArena(4, 0) // forces growth mid-decode
	v, _, err := Decode(tagArrayFixture(t, 50), DecodeOpts{Arena: arena})
	if err != nil {
		t.Fatal(err)
	}
	clone := v.Clone()
	for i, it := range v.Items {
		if it.Kind != cbor.KindTag || it.Num != uint64(100+i) || len(it.Items) != 1 || it.Items[0].Num != uint64(i) {
			t.Fatalf("item %d: %+v", i, it)
		}
		// Capped: an append must not overwrite the next arena slot.
		if cap(it.Items) != 1 {
			t.Fatalf("item %d: cap(Items) = %d, want 1", i, cap(it.Items))
		}
	}
	// The clone doesn't share arena storage, so reusing the arena
	// leaves it intact.
	arena.Reset()
	if _, _, err := Decode(tagArrayFixture(t, 60), DecodeOpts{Arena: arena}); err != nil {
		t.Fatal(err)
	}
	for i, it := range clone.Items {
		if it.Num != uint64(100+i) || it.Items[0].Num != uint64(i) {
			t.Fatalf("clone item %d changed after Reset: %+v", i, it)
		}
	}
}

func TestArenaTagAllocs(t *testing.T) {
	data := tagArrayFixture(t, 50)
	arena := NewArena(64, 0)
	got := testing.AllocsPerRun(100, func() {
		arena.Reset()
		if _, _, err := Decode(data, DecodeOpts{Arena: arena}); err != nil {
			t.Fatal(err)
		}
	})
	if got != 0 {
		t.Fatalf("arena: %v allocs, want 0", got)
	}
	heap := testing.AllocsPerRun(100, func() {
		if _, _, err := Decode(data, DecodeOpts{}); err != nil {
			t.Fatal(err)
		}
	})
	if heap != 51 {
		t.Fatalf("heap: %v allocs, want 51 (array + one per tag)", heap)
	}
}
