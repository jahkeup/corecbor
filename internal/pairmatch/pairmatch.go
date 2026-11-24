// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package pairmatch compares two unordered collections in time linear
// in their size, for map equality in the CBOR data model.
package pairmatch

// Small is the size up to which callers compare collections with a
// plain nested loop: below it, building an index costs more than it
// saves.
const Small = 16

// Match reports whether the n elements of a and the n elements of b can
// be paired so that every pair satisfies eq. eq must be an equivalence
// between elements (or a relation contained in one), and ha and hb must
// give equal hashes to elements eq relates. Elements are matched
// greedily, which is exact for an equivalence: equal elements are
// interchangeable.
//
// The cost is linear in n plus the elements that share a hash without
// being equal.
func Match(n int, ha, hb func(int) uint64, eq func(i, j int) bool) bool {
	buckets := make(map[uint64][]int32, n)
	for j := range n {
		h := hb(j)
		buckets[h] = append(buckets[h], int32(j))
	}
	for i := range n {
		h := ha(i)
		bk := buckets[h]
		found := false
		for k, j := range bk {
			if eq(i, int(j)) {
				// Remove the match so repeated equal elements stay O(1).
				bk[k] = bk[len(bk)-1]
				buckets[h] = bk[:len(bk)-1]
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
