// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"errors"
	"slices"
	"testing"

	"github.com/jahkeup/corecbor/rfc8949"
	"github.com/jahkeup/corecbor/wire"
)

// Proposal 023: strict decode tag policy.

// tagged returns the encoding of tag id wrapping the integer 1.
func tagged(id uint64) []byte {
	return append(wire.AppendHead(nil, wire.MajorTag, id), 0x01)
}

func TestStrictDecoderAcceptsTags(t *testing.T) {
	for _, h := range []string{"c101", "d280"} {
		if _, err := StrictDecoder().Decode(mustHex(t, h)); err != nil {
			t.Errorf("StrictDecoder().Decode(%s) = %v", h, err)
		}
	}
}

func TestStrictOptsMatchesSpec(t *testing.T) {
	// encoder-decoder-spec.md §3.2: RejectUnknownTags is NOT in the
	// strict preset.
	if rfc8949.StrictOpts().RejectUnknownTags {
		t.Fatal("StrictOpts().RejectUnknownTags = true; spec §3.2 excludes it")
	}
}

func TestRejectUnknownTagsDefaultAllowlist(t *testing.T) {
	_, err := StrictDecoder(RejectUnknownTags()).Decode(mustHex(t, "d9ffff00"))
	if !errors.Is(err, ErrUnknownTag) {
		t.Fatalf("tag 65535: err = %v, want ErrUnknownTag", err)
	}
}

func TestRejectUnknownTagsModeled(t *testing.T) {
	dec := NewDecoder(RejectUnknownTags())
	for _, id := range TagsModeled {
		if _, err := dec.Decode(tagged(id)); err != nil {
			t.Errorf("modeled tag %d rejected: %v", id, err)
		}
	}
	for _, id := range []uint64{4, 18, 61, 100, 601, 65535} {
		if slices.Contains(TagsModeled, id) {
			continue
		}
		if _, err := dec.Decode(tagged(id)); !errors.Is(err, ErrUnknownTag) {
			t.Errorf("tag %d: err = %v, want ErrUnknownTag", id, err)
		}
	}
}

func TestWithAllowedTags(t *testing.T) {
	dec := NewDecoder(RejectUnknownTags(), WithAllowedTags(18))
	if _, err := dec.Decode(tagged(18)); err != nil {
		t.Errorf("allowed tag 18 rejected: %v", err)
	}
	if _, err := dec.Decode(tagged(55799)); err != nil {
		t.Errorf("tag 55799 rejected: %v", err)
	}
	if _, err := dec.Decode(tagged(1)); !errors.Is(err, ErrUnknownTag) {
		t.Errorf("tag 1: err = %v, want ErrUnknownTag", err)
	}
	// WithAllowedTags alone enables the restriction, and repeated
	// options accumulate.
	dec = NewDecoder(WithAllowedTags(18), WithAllowedTags(61))
	for _, id := range []uint64{18, 61} {
		if _, err := dec.Decode(tagged(id)); err != nil {
			t.Errorf("tag %d rejected: %v", id, err)
		}
	}
	if _, err := dec.Decode(tagged(1)); !errors.Is(err, ErrUnknownTag) {
		t.Errorf("tag 1: err = %v, want ErrUnknownTag", err)
	}
	// TagsWellKnown covers the COSE/CWT/EAT family.
	dec = NewDecoder(WithAllowedTags(TagsWellKnown...))
	for _, id := range []uint64{16, 17, 18, 61, 96, 97, 98, 601, 602} {
		if _, err := dec.Decode(tagged(id)); err != nil {
			t.Errorf("well-known tag %d rejected: %v", id, err)
		}
	}
}

// StrictDecoder(RejectUnknownTags(), WithAllowedTags()) reproduces the
// v0.2.2 StrictDecoder, which allowed only 55799.
func TestCompatV02StrictTags(t *testing.T) {
	dec := StrictDecoder(RejectUnknownTags(), WithAllowedTags())
	for _, h := range []string{"c101", "d280"} {
		if _, err := dec.Decode(mustHex(t, h)); !errors.Is(err, ErrUnknownTag) {
			t.Errorf("Decode(%s) err = %v, want ErrUnknownTag", h, err)
		}
	}
}

func TestCompatRejectUnknownTagsEmptyAllowlist(t *testing.T) {
	dec := NewDecoder(RejectUnknownTags(), WithAllowedTags())
	if _, err := dec.Decode(tagged(55799)); err != nil {
		t.Errorf("tag 55799 rejected: %v", err)
	}
	for _, id := range []uint64{0, 1, 2} {
		if _, err := dec.Decode(tagged(id)); !errors.Is(err, ErrUnknownTag) {
			t.Errorf("tag %d: err = %v, want ErrUnknownTag", id, err)
		}
	}
	// Default (no tag options) accepts every tag.
	if _, err := NewDecoder().Decode(tagged(65535)); err != nil {
		t.Errorf("forgiving decoder rejected tag 65535: %v", err)
	}
}

// The Cursor applies the same tag policy as Decode.
func TestCursorTagPolicy(t *testing.T) {
	src := mustHex(t, "82d2800101") // [18([]), 1] then trailing 01
	dec := NewDecoder(RejectUnknownTags())
	c := dec.Cursor(src)
	if _, err := c.EnterArray(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Skip(); !errors.Is(err, ErrUnknownTag) {
		t.Fatalf("Cursor.Skip over tag 18: err = %v, want ErrUnknownTag", err)
	}
}
