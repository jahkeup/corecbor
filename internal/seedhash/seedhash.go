// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package seedhash provides the keyed hash primitives behind map-key
// duplicate tracking and map equality. The key is chosen at random once
// per process (hash/maphash), so input can't be crafted to make keys
// collide and turn linear work quadratic (hash flooding).
// Only performance depends on the hash: callers decide equality
// with an exact comparison, so results are the same in every process.
package seedhash

import "hash/maphash"

var (
	seed = maphash.MakeSeed()
	key  = maphash.String(seed, "corecbor/seedhash")
	salt [256]uint64
)

func init() {
	for i := range salt {
		salt[i] = Mix(uint64(i) + 0x9e3779b97f4a7c15)
	}
}

// Mix is a keyed bijective mix of x (the splitmix64 finalizer applied to
// x xor the process key): distinct inputs never collide, and without the
// key the outputs can't be predicted.
func Mix(x uint64) uint64 {
	x ^= key
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// Salt returns a keyed constant for tag t, used to separate the hashes
// of different kinds of value.
func Salt(t byte) uint64 { return salt[t] }

// String returns the keyed hash of s.
func String(s string) uint64 { return maphash.String(seed, s) }

// Bytes returns the keyed hash of b; it equals String(string(b)).
func Bytes(b []byte) uint64 { return maphash.Bytes(seed, b) }
