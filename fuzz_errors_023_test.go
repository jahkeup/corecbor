// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

func addErrorSeeds(f *testing.F) {
	for _, tc := range rfc8949Vectors {
		b, _ := hex.DecodeString(tc.hexEncoded)
		f.Add(b)
	}
	for _, h := range []string{"", "ff", "1c", "8201", "9f01", "a16161", "d2" + "84", "c1fb7ff8000000000000", "0102"} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
}

// FuzzDecodeErrorOffsetInBounds: every error Decode returns for any
// input is a *DecodeError whose Offset lies within the input, with and
// without WithErrorPath, under the forgiving and strict presets
// (proposal 023).
func FuzzDecodeErrorOffsetInBounds(f *testing.F) {
	addErrorSeeds(f)
	decs := []*Decoder{
		NewDecoder(),
		NewDecoder(WithErrorPath()),
		StrictDecoder(RejectUnknownTags(), WithErrorPath()),
		NewDecoder(WithMaxNestingDepth(4), WithMaxArrayLength(8), WithMaxByteStringLength(8)),
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for i, dec := range decs {
			_, err := dec.Decode(data)
			if err == nil {
				continue
			}
			var de *DecodeError
			if !errors.As(err, &de) {
				t.Fatalf("decoder %d: error %v (%T) is not a *DecodeError", i, err, err)
			}
			if de.Offset < 0 || de.Offset > len(data) {
				t.Fatalf("decoder %d: Offset %d out of [0, %d]: %v", i, de.Offset, len(data), err)
			}
			if de.Err == nil {
				t.Fatalf("decoder %d: DecodeError without sentinel: %v", i, err)
			}
			// Trailing bytes follow the item, so they have no path.
			if i == 1 && !errors.Is(err, ErrTrailingBytes) && (de.Path == "" || de.Path[0] != '$') {
				t.Fatalf("WithErrorPath: Path = %q: %v", de.Path, err)
			}
		}
	})
}

// collectTags appends every tag number in v (outermost first).
func collectTags(v cbor.Value, out []uint64) []uint64 {
	switch v.Kind {
	case cbor.KindTag:
		out = append(out, v.TagID())
		return collectTags(v.TagInner(), out)
	case cbor.KindArray:
		for _, it := range v.Items {
			out = collectTags(it, out)
		}
	case cbor.KindMap:
		for _, p := range v.Pairs {
			out = collectTags(p.Key, out)
			out = collectTags(p.Value, out)
		}
	}
	return out
}

// FuzzTagPolicy: StrictDecoder never rejects an input for its tags
// alone, and WithAllowedTags(set) accepts an otherwise-valid input
// exactly when every tag in it is in set or is 55799 (proposal 023).
func FuzzTagPolicy(f *testing.F) {
	for _, tc := range rfc8949Vectors {
		b, _ := hex.DecodeString(tc.hexEncoded)
		f.Add(b, uint64(1), uint64(2))
	}
	f.Add([]byte{0xc1, 0x01}, uint64(1), uint64(18))
	f.Add([]byte{0xd2, 0x80}, uint64(18), uint64(61))
	// The oracle rejects duplicate keys: last-write-wins would drop a
	// shadowed entry's tags from v while the policy still checks them.
	oracle := NewDecoder(WithoutInternalArena(), RejectDuplicateMapKeys())
	f.Fuzz(func(t *testing.T, data []byte, a, b uint64) {
		v, err := oracle.Decode(data)
		if err != nil {
			return
		}
		tags := collectTags(v, nil)

		// StrictDecoder: any rejection must be for a reason other than
		// tags, i.e. must also happen with every tag allowed.
		_, strictErr := StrictDecoder().Decode(data)
		if errors.Is(strictErr, ErrUnknownTag) {
			t.Fatalf("StrictDecoder rejected tags: %v", strictErr)
		}

		allowed := []uint64{a, b}
		_, err = NewDecoder(WithAllowedTags(allowed...)).Decode(data)
		ok := true
		for _, id := range tags {
			if id != cbor.TagSelfDescribe && !slices.Contains(allowed, id) {
				ok = false
				break
			}
		}
		switch {
		case ok && err != nil:
			t.Fatalf("WithAllowedTags(%v) rejected %x (tags %v): %v", allowed, data, tags, err)
		case !ok && !errors.Is(err, ErrUnknownTag):
			t.Fatalf("WithAllowedTags(%v) accepted %x (tags %v): err %v", allowed, data, tags, err)
		}
	})
}
