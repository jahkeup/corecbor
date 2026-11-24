// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"math"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// keyHash must give keys that are the same in the data model the same
// hash, or duplicate detection would miss them; it is keyed per process
// (037 C2), so only this relation is fixed, not the values.
func TestKeyHashConsistentWithIdentity(t *testing.T) {
	nan32 := cbor.Float32(math.Float32frombits(0x7fc00001))
	nan64 := cbor.Float64(math.Float64frombits(0x7ff8000020000000))
	for _, pair := range [][2]cbor.Value{
		{cbor.Text("k1_ffff"), cbor.Text("k1_ffff")},
		{cbor.Text(""), cbor.Text("")},
		{cbor.Uint(1), cbor.Uint(1)},
		{cbor.Float32(1), cbor.Float64(1)},
		{cbor.Float64(0), cbor.Float64(math.Copysign(0, -1))},
		{nan32, nan64},
		{cbor.MakeArray(cbor.Uint(1), cbor.Text("a")), cbor.MakeArray(cbor.Uint(1), cbor.Text("a"))},
		{
			cbor.MakeMap(cbor.MapEntry{Key: cbor.Uint(1), Value: cbor.Null()}, cbor.MapEntry{Key: cbor.Uint(2), Value: cbor.Bool(true)}),
			cbor.MakeMap(cbor.MapEntry{Key: cbor.Uint(2), Value: cbor.Bool(true)}, cbor.MapEntry{Key: cbor.Uint(1), Value: cbor.Null()}),
		},
		{cbor.MakeTag(1, cbor.Float32(2)), cbor.MakeTag(1, cbor.Float64(2))},
	} {
		if !keysEqual(pair[0], pair[1], false) {
			t.Fatalf("test pair %v, %v not equal", pair[0], pair[1])
		}
		if keyHash(pair[0]) != keyHash(pair[1]) {
			t.Errorf("keyHash(%v) != keyHash(%v)", pair[0], pair[1])
		}
	}
	// Kinds are kept apart: text and bytes with the same content, 1 and
	// -2 (both Num 1), integer 1 and float 1.0.
	for _, pair := range [][2]cbor.Value{
		{cbor.Text("a"), cbor.Bytes([]byte("a"))},
		{cbor.Uint(1), cbor.NegInt(1)},
		{cbor.Uint(1), cbor.Float64(1)},
	} {
		if keyHash(pair[0]) == keyHash(pair[1]) {
			t.Errorf("keyHash(%v) == keyHash(%v)", pair[0], pair[1])
		}
	}
}
