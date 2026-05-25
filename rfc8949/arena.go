// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import "github.com/jahkeup/corecbor/cbor"

// Arena provides batch allocation for decode operations. It pre-allocates
// backing storage for Value slices (arrays, tag inners) and MapEntry
// slices (maps), eliminating per-container heap allocations.
//
// Not goroutine-safe. Use one Arena per decode call or per goroutine.
// All Values decoded into an Arena share its backing storage — when
// Reset is called, those Values become invalid.
type Arena struct {
	values []cbor.Value
	pairs  []cbor.MapEntry
	vOff   int
	pOff   int
}

// NewArena creates an arena pre-sized for approximately nValues Value
// slots and nPairs MapEntry slots. The arena grows if needed.
func NewArena(nValues, nPairs int) *Arena {
	return &Arena{
		values: make([]cbor.Value, nValues),
		pairs:  make([]cbor.MapEntry, nPairs),
	}
}

// Reset resets the arena for reuse without freeing backing storage.
// All Values previously decoded into this arena become invalid.
func (a *Arena) Reset() {
	a.vOff = 0
	a.pOff = 0
}

// AllocValues returns a slice of n Values from the arena's backing slab.
// If insufficient capacity remains, the slab is grown.
func (a *Arena) AllocValues(n int) []cbor.Value {
	if a.vOff+n > len(a.values) {
		needed := a.vOff + n
		if needed < len(a.values)*2 {
			needed = len(a.values) * 2
		}
		grown := make([]cbor.Value, needed)
		copy(grown, a.values[:a.vOff])
		a.values = grown
	}
	s := a.values[a.vOff : a.vOff+n]
	a.vOff += n
	return s
}

// AllocPairs returns a slice of n MapEntry slots from the arena's backing slab.
func (a *Arena) AllocPairs(n int) []cbor.MapEntry {
	if a.pOff+n > len(a.pairs) {
		needed := a.pOff + n
		if needed < len(a.pairs)*2 {
			needed = len(a.pairs) * 2
		}
		grown := make([]cbor.MapEntry, needed)
		copy(grown, a.pairs[:a.pOff])
		a.pairs = grown
	}
	s := a.pairs[a.pOff : a.pOff+n]
	a.pOff += n
	return s
}
