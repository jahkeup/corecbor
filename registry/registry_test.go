package registry

import "testing"

func TestLookupTag_Known(t *testing.T) {
	tests := []struct {
		tag     uint64
		wantSem string
		wantRef string
	}{
		{0, "Standard date/time string; see Section 3.4.1 of RFC 8949", "RFC 8949"},
		{1, "Epoch-based date/time; see Section 3.4.2 of RFC 8949", "RFC 8949"},
		{18, "COSE Single Signer Data Object", "RFC 9052"},
		{24, "Encoded CBOR data item", "RFC 8949"},
		{55799, "Self-Described CBOR", "RFC 8949"},
		{258, "Mathematical finite set", "RFC 9557"},
	}
	for _, tt := range tests {
		info := LookupTag(tt.tag)
		if info == nil {
			t.Fatalf("LookupTag(%d) = nil, want non-nil", tt.tag)
		}
		if info.Tag != tt.tag {
			t.Errorf("LookupTag(%d).Tag = %d", tt.tag, info.Tag)
		}
		if info.Semantics != tt.wantSem {
			t.Errorf("LookupTag(%d).Semantics = %q, want %q", tt.tag, info.Semantics, tt.wantSem)
		}
		if info.Reference != tt.wantRef {
			t.Errorf("LookupTag(%d).Reference = %q, want %q", tt.tag, info.Reference, tt.wantRef)
		}
	}
}

func TestLookupTag_Unknown(t *testing.T) {
	unknowns := []uint64{99, 1000, 65535, 999999}
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
	if IsRegistered(9999) {
		t.Error("IsRegistered(9999) = true, want false")
	}
}

func TestAllTags_NonEmpty(t *testing.T) {
	tags := AllTags()
	if len(tags) < 20 {
		t.Errorf("AllTags() returned %d entries, want at least 20", len(tags))
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
