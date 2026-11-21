// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
)

type draftExample struct {
	File          string   `json:"file"`
	Description   string   `json:"description"`
	General       []string `json:"general-serializations"`
	PreferredPlus []string `json:"preferred-plus-serializations"`
	Deterministic []string `json:"deterministic-serialization"`
}

// TestSerializationDraftVectors runs the Appendix K examples of
// draft-ietf-cbor-serialization-13 (Experimental, proposal 024 Phase 4)
// as the draft's K.1 encode, decode and checking-decoder tests. There is
// no EDN parser here, so the deterministic serialization, decoded, stands
// in for each example's EDN value.
func TestSerializationDraftVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/serialization-13/examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Examples []draftExample `json:"examples"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Examples) < 20 {
		t.Fatalf("only %d examples parsed", len(doc.Examples))
	}

	forgiving := NewDecoder(WithoutInternalArena())
	core := New(ModeCoreDeterministic, AllowNonFiniteFloats())
	pp := New(ModePreferredPlus, AllowNonFiniteFloats())
	checkPP := NewDecoder(RequirePreferredPlus())
	// The draft's Deterministic Serialization is RFC 8949 §4.2.1 plus its
	// NaN rule, so check with both options.
	checkDet := NewDecoder(RequireDeterministic(), RequirePreferredPlus())

	for _, ex := range doc.Examples {
		t.Run(ex.File, func(t *testing.T) {
			if len(ex.Deterministic) == 1 {
				det := mustHex(t, ex.Deterministic[0])
				v, err := forgiving.Decode(det)
				if err != nil {
					t.Fatalf("decode deterministic form: %v", err)
				}
				// K.1.1 encode test.
				if got := encHex(t, core, v); got != ex.Deterministic[0] {
					t.Errorf("CoreDeterministic encode = %s, want %s", got, ex.Deterministic[0])
				}
				if got := encHex(t, pp, v); !slices.Contains(ex.PreferredPlus, got) {
					t.Errorf("PreferredPlus encode = %s, want one of %v", got, ex.PreferredPlus)
				}
				// K.1.2 decode test: every general form is the same value.
				for _, g := range ex.General {
					gv, err := forgiving.Decode(mustHex(t, g))
					if err != nil {
						t.Errorf("decode general %s: %v", g, err)
						continue
					}
					if got := encHex(t, core, gv); got != ex.Deterministic[0] {
						t.Errorf("general %s decodes to %s (re-encoded %s), want the value of %s", g, DiagnosticValue(gv), got, ex.Deterministic[0])
					}
				}
			}
			// K.1.3 checking decoder test.
			for _, g := range ex.General {
				_, err := checkPP.Decode(mustHex(t, g))
				switch allowed := slices.Contains(ex.PreferredPlus, g); {
				case allowed && err != nil:
					t.Errorf("RequirePreferredPlus rejected allowed %s: %v", g, err)
				case !allowed && !errors.Is(err, ErrNotPreferred):
					t.Errorf("RequirePreferredPlus accepted non-conforming %s (err %v)", g, err)
				}
				_, err = checkDet.Decode(mustHex(t, g))
				switch allowed := slices.Contains(ex.Deterministic, g); {
				case allowed && err != nil:
					t.Errorf("deterministic check rejected allowed %s: %v", g, err)
				case !allowed && err == nil:
					t.Errorf("deterministic check accepted non-conforming %s", g)
				}
			}
		})
	}
}
