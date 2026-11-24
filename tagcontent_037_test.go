// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// 037 C10: tag content is validated under RejectInvalidTagContent, in
// StrictDecoder and DeterministicDecoder, and on encode with
// CheckTagContent.
func TestC10TagContent(t *testing.T) {
	for _, tc := range []struct {
		hex   string
		valid bool
	}{
		{"c074323031332d30332d32315432303a30343a30305a", true}, // 0("2013-03-21T20:04:00Z")
		{"c06474657874", false},                                // 0("text")
		{"c001", false},                                        // 0(1)
		{"c11a514b67b0", true},                                 // 1(1363896240)
		{"c1fb41d452d9ec200000", true},                         // 1(1363896240.5)
		{"c16161", false},                                      // 1("a")
		{"c24101", true},                                       // 2(h'01')
		{"c26161", false},                                      // 2("a")
		{"c34101", true},
		{"c301", false},
		{"c482211903e8", true},                             // 4([-2, 1000])
		{"c48221c24101", true},                             // 4([-2, 2(h'01')])
		{"c482216161", false},                              // 4([-2, "a"])
		{"c48121", false},                                  // one element
		{"c4c24101", false},                                // not an array
		{"c5820101", true},                                 // 5([1, 1])
		{"d818420102", false},                              // 24(h'0102'): two items
		{"d8184101", true},                                 // 24(h'01')
		{"d818415f", false},                                // 24(h'5f'): truncated
		{"d8186161", false},                                // 24("a")
		{"d82071687474703a2f2f612e6578616d706c652f", true}, // 32("http://a.example/")
		{"d82001", false},
		{"d8216441424344", true},  // 33("ABCD")
		{"d82163414241", true},    // 33("ABA") unpadded
		{"d82163414244", false},   // 33("ABD"): non-zero padding bits
		{"d821644142413d", false}, // 33("ABA=") padded
		{"d82263414241", false},   // 34("ABA") unpadded
		{"d822644142413d", true},  // 34("ABA=")
		{"d8236161", true},        // 35("a")
		{"d82301", false},
		{"d9010280", true}, // 258([])
		{"d9010201", false},
		{"d8404101", true},                  // 64(h'01'): uint8
		{"d841420102", true},                // 65(h'0102'): uint16 BE
		{"d8414101", false},                 // 65(h'01'): short
		{"d85243010203", false},             // 82: float64 needs 8 bytes
		{"d852490000000000000000f0", false}, // 9 bytes
		{"d852480000000000000000", true},
		{"d84c4101", true},    // 76 is reserved: not checked
		{"d5820102", true},    // 21: any content
		{"d9d9f76161", true},  // 55799: any content
		{"d903e76161", true},  // unknown tag: any content
		{"81c26161", false},   // nested
		{"a1c2616101", false}, // as a map key
	} {
		src, err := hex.DecodeString(tc.hex)
		if err != nil {
			t.Fatal(err)
		}
		// Forgiving decoding accepts every well-formed item.
		v, err := NewDecoder().Decode(src)
		if err != nil {
			t.Fatalf("%s: forgiving decode: %v", tc.hex, err)
		}
		for name, d := range map[string]*Decoder{
			"RejectInvalidTagContent": NewDecoder(RejectInvalidTagContent()),
			"StrictDecoder":           StrictDecoder(),
		} {
			_, err := d.Decode(src)
			if tc.valid && err != nil {
				t.Errorf("%s %s: %v, want accepted", name, tc.hex, err)
			}
			if !tc.valid && !errors.Is(err, ErrMalformedTag) {
				t.Errorf("%s %s: err = %v, want ErrMalformedTag", name, tc.hex, err)
			}
		}
		_, err = New(ModePermissive, CheckTagContent()).Encode(nil, v)
		if tc.valid && err != nil {
			t.Errorf("CheckTagContent %s: %v, want accepted", tc.hex, err)
		}
		if !tc.valid && !errors.Is(err, ErrMalformedTag) {
			t.Errorf("CheckTagContent %s: err = %v, want ErrMalformedTag", tc.hex, err)
		}
		// Without CheckTagContent the encoder writes what it's given.
		if _, err := New(ModePermissive).Encode(nil, v); err != nil {
			t.Errorf("Permissive %s: %v", tc.hex, err)
		}
	}
	// The checking decoder includes it.
	if _, err := DeterministicDecoder().Decode([]byte{0xc2, 0x61, 0x61}); !errors.Is(err, ErrMalformedTag) {
		t.Errorf("DeterministicDecoder: %v", err)
	}
	if _, err := Marshal(cbor.MakeTag(2, Text("a"))); err != nil {
		t.Errorf("Marshal without CheckTagContent: %v", err)
	}
}
