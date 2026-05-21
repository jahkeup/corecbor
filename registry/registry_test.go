// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package registry

import (
	"strings"
	"testing"
)

func TestLookupTag_Known(t *testing.T) {
	tests := []struct {
		tag        uint64
		wantSemSub string
		wantRefSub string
	}{
		{0, "date/time string", "RFC8949"},
		{1, "date/time", "RFC8949"},
		{18, "COSE", "RFC9052"},
		{24, "Encoded CBOR data item", "RFC8949"},
		{55799, "Self-described CBOR", "RFC8949"},
	}
	for _, tt := range tests {
		info := LookupTag(tt.tag)
		if info == nil {
			t.Fatalf("LookupTag(%d) = nil, want non-nil", tt.tag)
		}
		if info.Tag != tt.tag {
			t.Errorf("LookupTag(%d).Tag = %d", tt.tag, info.Tag)
		}
		if !strings.Contains(strings.ToLower(info.Semantics), strings.ToLower(tt.wantSemSub)) {
			t.Errorf("LookupTag(%d).Semantics = %q, want to contain %q", tt.tag, info.Semantics, tt.wantSemSub)
		}
		if !strings.Contains(info.Reference, tt.wantRefSub) {
			t.Errorf("LookupTag(%d).Reference = %q, want to contain %q", tt.tag, info.Reference, tt.wantRefSub)
		}
	}
}

func TestLookupTag_Unknown(t *testing.T) {
	unknowns := []uint64{7777777, 123456789012}
	for _, tag := range unknowns {
		if info := LookupTag(tag); info != nil {
			t.Errorf("LookupTag(%d) = %+v, want nil", tag, info)
		}
	}
}

func TestIsRegistered(t *testing.T) {
	if !IsRegistered(0) {
		t.Error("IsRegistered(0) = false, want true")
	}
	if !IsRegistered(55799) {
		t.Error("IsRegistered(55799) = false, want true")
	}
	if IsRegistered(999999999) {
		t.Error("IsRegistered(999999999) = true, want false")
	}
}

func TestAllTags_NonEmpty(t *testing.T) {
	tags := AllTags()
	if len(tags) < 100 {
		t.Errorf("AllTags() returned %d entries, want at least 100", len(tags))
	}
}

func TestAllTags_Sorted(t *testing.T) {
	tags := AllTags()
	for i := 1; i < len(tags); i++ {
		if tags[i].Tag <= tags[i-1].Tag {
			t.Fatalf("AllTags() not sorted: index %d has tag %d <= previous %d",
				i, tags[i].Tag, tags[i-1].Tag)
		}
	}
}

func TestAllTags_MatchesLookup(t *testing.T) {
	for _, info := range AllTags() {
		got := LookupTag(info.Tag)
		if got == nil {
			t.Errorf("AllTags has tag %d but LookupTag returns nil", info.Tag)
		}
	}
}
