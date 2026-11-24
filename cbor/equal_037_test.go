// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"math"
	"testing"
	"time"
)

// 037 C2: Equal on large maps pairs entries through a hash index; it
// gives the same answers as the pairwise scan, in linear time.
func TestEqualLargeMaps(t *testing.T) {
	mk := func(n int, f func(i int) MapEntry) Value {
		p := make([]MapEntry, n)
		for i := range p {
			p[i] = f(i)
		}
		return MakeMapFromSlice(p)
	}
	const n = 40
	fwd := mk(n, func(i int) MapEntry { return MapEntry{Key: Uint(uint64(i)), Value: Text("v")} })
	rev := mk(n, func(i int) MapEntry { return MapEntry{Key: Uint(uint64(n - 1 - i)), Value: Text("v")} })
	if !fwd.Equal(rev) {
		t.Fatal("reordered maps not equal")
	}
	diff := mk(n, func(i int) MapEntry {
		v := Text("v")
		if i == 7 {
			v = Text("w")
		}
		return MapEntry{Key: Uint(uint64(i)), Value: v}
	})
	if fwd.Equal(diff) || diff.Equal(fwd) {
		t.Fatal("maps differing in one value compare equal")
	}
	// Repeated pairs (KeepDuplicateMapKeys) must match by count.
	dupA := mk(n, func(i int) MapEntry { return MapEntry{Key: Text("a"), Value: Uint(uint64(i % 2))} })
	dupB := mk(n, func(i int) MapEntry { return MapEntry{Key: Text("a"), Value: Uint(uint64((i + 1) % 2))} })
	dupC := mk(n, func(i int) MapEntry { return MapEntry{Key: Text("a"), Value: Uint(uint64(i % 3 % 2))} })
	if !dupA.Equal(dupB) || dupA.Equal(dupC) {
		t.Fatal("maps with repeated pairs compared wrongly")
	}
	// Data-model rules inside the index: float widths, signed zero.
	f := mk(n, func(i int) MapEntry { return MapEntry{Key: Uint(uint64(i)), Value: Float32(float32(i))} })
	g := mk(n, func(i int) MapEntry {
		return MapEntry{Key: Uint(uint64(n - 1 - i)), Value: Float64(float64(n - 1 - i))}
	})
	if !f.Equal(g) {
		t.Fatal("float widths not equal in a large map")
	}
	z := mk(n, func(i int) MapEntry { return MapEntry{Key: Uint(uint64(i)), Value: Float64(math.Copysign(0, -1))} })
	z2 := mk(n, func(i int) MapEntry { return MapEntry{Key: Uint(uint64(i)), Value: Float64(0)} })
	if !z.Equal(z2) {
		t.Fatal("-0 and +0 not equal in a large map")
	}

	const big = 50_000
	a := mk(big, func(i int) MapEntry { return MapEntry{Key: Uint(uint64(i)), Value: Null()} })
	b := mk(big, func(i int) MapEntry { return MapEntry{Key: Uint(uint64(big - 1 - i)), Value: Null()} })
	start := time.Now()
	if !a.Equal(b) {
		t.Fatal("large reordered maps not equal")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Equal on two %d-pair maps took %v", big, d)
	}
}
