// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/jahkeup/corecbor/rfc8949"
)

// String interning (proposal 036 item 18).

func repeatedKeysMap(n int) []byte {
	pairs := make([]MapEntry, n)
	for i := range n {
		pairs[i] = MapEntry{Key: Text(fmt.Sprintf("key-%02d", i)), Value: Uint(uint64(i))}
	}
	data, err := New(ModeCoreDeterministic).Encode(nil, MakeMapFromSlice(pairs))
	if err != nil {
		panic(err)
	}
	return data
}

func stringData(s string) *byte { return unsafe.StringData(s) }

func TestInternEqualAndShared(t *testing.T) {
	data := repeatedKeysMap(8)
	si := rfc8949.NewStringInterner(64)
	dec := NewDecoder(WithStringIntern(si), WithoutInternalArena())
	a, err := dec.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	b, err := dec.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a.Pairs {
		ka, kb := a.Pairs[i].Key.Str, b.Pairs[i].Key.Str
		if ka != kb || ka != fmt.Sprintf("key-%02d", i) {
			t.Fatalf("key %d: %q vs %q", i, ka, kb)
		}
		if stringData(ka) != stringData(kb) {
			t.Fatalf("key %d not shared across decodes", i)
		}
	}
}

// Interned strings are copies: mutating the source after decode must not
// change them, with or without zero-copy and arena.
func TestInternDoesNotAliasSource(t *testing.T) {
	for name, opts := range map[string][]DecoderOption{
		"plain":     nil,
		"zero-copy": {WithZeroCopy()},
		"arena":     {WithArena(rfc8949.NewArena(64, 64))},
	} {
		t.Run(name, func(t *testing.T) {
			data := repeatedKeysMap(4)
			si := rfc8949.NewStringInterner(64)
			dec := NewDecoder(append(opts, WithStringIntern(si))...)
			v, err := dec.Decode(data)
			if err != nil {
				t.Fatal(err)
			}
			want := v.Pairs[0].Key.Str
			wantCopy := string([]byte(want))
			for i := range data {
				data[i] = 'X'
			}
			if v.Pairs[0].Key.Str != wantCopy {
				t.Fatalf("interned key changed with source: %q", v.Pairs[0].Key.Str)
			}
		})
	}
}

func TestInternPrefill(t *testing.T) {
	si := rfc8949.NewStringInterner(1)
	pre := "key-00"
	si.Prefill(pre, "key-01")
	got := si.Intern([]byte("key-01"))
	if got != "key-01" {
		t.Fatalf("Intern = %q", got)
	}
	if stringData(si.Intern([]byte(pre))) != stringData(pre) {
		t.Fatal("prefilled string not returned")
	}
}

// Beyond its capacity the interner still returns correct strings but
// stops storing new ones. (Multi-byte strings: Go returns static
// strings for single-byte conversions, which would hide the check.)
func TestInternCapacityBound(t *testing.T) {
	si := rfc8949.NewStringInterner(2)
	a := si.Intern([]byte("alpha"))
	_ = si.Intern([]byte("bravo"))
	c1 := si.Intern([]byte("charlie"))
	c2 := si.Intern([]byte("charlie"))
	if c1 != "charlie" || c2 != "charlie" {
		t.Fatalf("over-capacity Intern = %q, %q", c1, c2)
	}
	if stringData(c1) == stringData(c2) {
		t.Fatal("over-capacity string was stored")
	}
	if stringData(si.Intern([]byte("alpha"))) != stringData(a) {
		t.Fatal("stored string not reused")
	}
}

// Steady state: a decoder with an interner and its internal arena decodes
// a repeated-key map with no allocations.
func TestInternSteadyStateZeroAlloc(t *testing.T) {
	data := repeatedKeysMap(20)
	dec := NewDecoder(WithStringIntern(rfc8949.NewStringInterner(64)))
	if _, err := dec.Decode(data); err != nil { // warm interner and arena
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := dec.Decode(data); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("allocs per decode = %v, want 0", allocs)
	}
}

func BenchmarkDecodeRepeatedKeysIntern(b *testing.B) {
	data := repeatedKeysMap(20)
	dec := NewDecoder(WithStringIntern(rfc8949.NewStringInterner(64)))
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := dec.Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}
