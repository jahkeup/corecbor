// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"testing"
)

// compatVector is a cross-library compatibility test case. Each entry
// contains a corecbor Value and the canonical hex encoding that all
// RFC 8949 §4.2.1 Core Deterministic encoders must produce.
type compatVector struct {
	name         string // descriptive test name
	value        Value  // the logical CBOR value
	canonicalHex string // expected Core Deterministic encoding
	notes        string // provenance: which library produced/verified this
}

// quirkyVector represents non-canonical CBOR that other implementations
// produce. Our decoder must accept these (Postel's law) and decode them
// to the expected Value.
type quirkyVector struct {
	name      string // descriptive test name
	inputHex  string // non-canonical CBOR input
	wantValue Value  // expected decoded value
	notes     string // which library/scenario produces this encoding
}

// compatVectors contains 35+ test cases verified against fxamacker/cbor v2
// (CoreDet mode), cbor2 (Python canonical=True), and cbor.me.
var compatVectors = []compatVector{
	// === Integers at encoding boundaries ===
	// Major type 0: unsigned integers
	{
		name:         "uint/zero",
		value:        Uint(0),
		canonicalHex: "00",
		notes:        "fxamacker/cbor, cbor2, cbor.me: single byte 0x00",
	},
	{
		name:         "uint/max-inline-23",
		value:        Uint(23),
		canonicalHex: "17",
		notes:        "fxamacker/cbor, cbor2: largest value in single-byte encoding",
	},
	{
		name:         "uint/boundary-24",
		value:        Uint(24),
		canonicalHex: "1818",
		notes:        "fxamacker/cbor, cbor2: first value requiring 1-byte additional info",
	},
	{
		name:         "uint/boundary-255",
		value:        Uint(255),
		canonicalHex: "18ff",
		notes:        "fxamacker/cbor, cbor2: max 1-byte additional info",
	},
	{
		name:         "uint/boundary-256",
		value:        Uint(256),
		canonicalHex: "190100",
		notes:        "fxamacker/cbor, cbor2: first value requiring 2-byte additional info",
	},
	{
		name:         "uint/boundary-65535",
		value:        Uint(65535),
		canonicalHex: "19ffff",
		notes:        "fxamacker/cbor, cbor2: max 2-byte additional info",
	},
	{
		name:         "uint/boundary-65536",
		value:        Uint(65536),
		canonicalHex: "1a00010000",
		notes:        "fxamacker/cbor, cbor2: first value requiring 4-byte additional info",
	},
	{
		name:         "uint/max-uint32",
		value:        Uint(4294967295),
		canonicalHex: "1affffffff",
		notes:        "fxamacker/cbor, cbor2: max 4-byte additional info",
	},
	{
		name:         "uint/boundary-4294967296",
		value:        Uint(4294967296),
		canonicalHex: "1b0000000100000000",
		notes:        "fxamacker/cbor, cbor2: first value requiring 8-byte additional info",
	},
	{
		name:         "uint/max-uint64",
		value:        Uint(18446744073709551615),
		canonicalHex: "1bffffffffffffffff",
		notes:        "fxamacker/cbor, cbor2: maximum CBOR unsigned integer",
	},

	// === Negative integers at boundaries ===
	// Major type 1: NegInt(n) encodes as -1-n on wire
	{
		name:         "negint/-1",
		value:        NegInt(0),
		canonicalHex: "20",
		notes:        "fxamacker/cbor, cbor2: -1 = 0x20",
	},
	{
		name:         "negint/-24",
		value:        NegInt(23),
		canonicalHex: "37",
		notes:        "fxamacker/cbor, cbor2: last inline negative",
	},
	{
		name:         "negint/-25",
		value:        NegInt(24),
		canonicalHex: "3818",
		notes:        "fxamacker/cbor, cbor2: first 1-byte payload negative",
	},
	{
		name:         "negint/-256",
		value:        NegInt(255),
		canonicalHex: "38ff",
		notes:        "fxamacker/cbor, cbor2: max 1-byte payload negative",
	},
	{
		name:         "negint/-257",
		value:        NegInt(256),
		canonicalHex: "390100",
		notes:        "fxamacker/cbor, cbor2: first 2-byte payload negative",
	},
	{
		name:         "negint/-65536",
		value:        NegInt(65535),
		canonicalHex: "39ffff",
		notes:        "fxamacker/cbor, cbor2: max 2-byte payload negative",
	},

	// === Byte strings ===
	{
		name:         "bytes/empty",
		value:        Bytes(nil),
		canonicalHex: "40",
		notes:        "fxamacker/cbor, cbor2: empty byte string",
	},
	{
		name:         "bytes/short",
		value:        Bytes([]byte{0xde, 0xad, 0xbe, 0xef}),
		canonicalHex: "44deadbeef",
		notes:        "fxamacker/cbor, cbor2: 4-byte string",
	},

	// === Text strings ===
	{
		name:         "text/empty",
		value:        Text(""),
		canonicalHex: "60",
		notes:        "fxamacker/cbor, cbor2: empty text string",
	},
	{
		name:         "text/ascii",
		value:        Text("hello"),
		canonicalHex: "6568656c6c6f",
		notes:        "fxamacker/cbor, cbor2: ASCII text",
	},
	{
		name:         "text/unicode-2byte",
		value:        Text("\u00fc"), // ü (U+00FC, 2-byte UTF-8: c3 bc)
		canonicalHex: "62c3bc",
		notes:        "fxamacker/cbor, cbor2: 2-byte UTF-8 character",
	},
	{
		name:         "text/unicode-3byte",
		value:        Text("\u6c34"), // 水 (U+6C34, 3-byte UTF-8: e6 b0 b4)
		canonicalHex: "63e6b0b4",
		notes:        "fxamacker/cbor, cbor2: 3-byte UTF-8 CJK character",
	},
	{
		name:         "text/unicode-4byte",
		value:        Text("\U0001f600"), // 😀 (U+1F600, 4-byte UTF-8: f0 9f 98 80)
		canonicalHex: "64f09f9880",
		notes:        "fxamacker/cbor, cbor2: 4-byte UTF-8 emoji",
	},

	// === Nested arrays ===
	{
		name:         "array/empty",
		value:        Array(nil),
		canonicalHex: "80",
		notes:        "fxamacker/cbor, cbor2: empty array",
	},
	{
		name:         "array/nested",
		value:        Array{Uint(1), Array{Uint(2), Uint(3)}, Array{Uint(4), Uint(5)}},
		canonicalHex: "8301820203820405",
		notes:        "fxamacker/cbor, cbor2: [1, [2, 3], [4, 5]]",
	},
	{
		name:         "array/deeply-nested",
		value:        Array{Array{Array{Uint(42)}}},
		canonicalHex: "818181182a",
		notes:        "fxamacker/cbor, cbor2: [[[42]]]",
	},

	// === Maps with deterministic key sorting ===
	// Core Deterministic: bytewise-lex of encoded keys
	{
		name:  "map/mixed-keys-sorted",
		value: Map{{Key: Uint(1), Value: Text("one")}, {Key: Uint(100), Value: Text("hundred")}, {Key: NegInt(0), Value: Text("neg1")}, {Key: Text("z"), Value: Uint(26)}},
		// Sorted by encoded key bytes: 01 < 1864 < 20 < 617a
		canonicalHex: "a401636f6e651864676875" + "6e6472656420646e65673161" + "7a181a",
		notes:        "fxamacker/cbor CoreDet: uint(1) < uint(100) < negint(-1) < text(z)",
	},
	{
		name:  "map/text-keys-length-order",
		value: Map{{Key: Text("a"), Value: Uint(1)}, {Key: Text("b"), Value: Uint(2)}, {Key: Text("aa"), Value: Uint(3)}},
		// Encoded keys: 6161(a) < 6162(b) < 626161(aa) — bytewise-lex
		canonicalHex: "a3616101616202626161" + "03",
		notes:        "fxamacker/cbor, cbor2: text keys sorted bytewise-lex",
	},
	{
		name:  "map/bytes-key",
		value: Map{{Key: Uint(0), Value: Bool(true)}, {Key: Bytes([]byte{0x01}), Value: Bool(false)}},
		// Encoded keys: 00 (uint 0) < 4101 (bytes [0x01])
		canonicalHex: "a200f54101f4",
		notes:        "fxamacker/cbor CoreDet: uint key before bytes key",
	},

	// === Tags ===
	{
		name:         "tag/epoch-datetime",
		value:        Tag{ID: TagEpochDateTime, Inner: Uint(1363896240)},
		canonicalHex: "c11a514b67b0",
		notes:        "fxamacker/cbor, cbor2, RFC 8949 Appendix A",
	},
	{
		name:         "tag/unsigned-bignum",
		value:        Tag{ID: TagUnsignedBignum, Inner: Bytes([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})},
		canonicalHex: "c249010000000000000000",
		notes:        "fxamacker/cbor, cbor2: bignum 2^64",
	},
	{
		name:         "tag/negative-bignum",
		value:        Tag{ID: TagNegativeBignum, Inner: Bytes([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})},
		canonicalHex: "c349010000000000000000",
		notes:        "fxamacker/cbor, cbor2: negative bignum -(2^64+1)",
	},

	// === Floats (canonical shortest form) ===
	{
		name:         "float/zero",
		value:        Float64(0.0),
		canonicalHex: "f90000",
		notes:        "fxamacker/cbor, cbor2: 0.0 → float16",
	},
	{
		name:         "float/neg-zero",
		value:        Float64(math.Copysign(0, -1)),
		canonicalHex: "f98000",
		notes:        "fxamacker/cbor, cbor2: -0.0 → float16 with sign bit",
	},
	{
		name:         "float/1.5",
		value:        Float64(1.5),
		canonicalHex: "f93e00",
		notes:        "fxamacker/cbor, cbor2: 1.5 representable as float16",
	},

	// === Simple values ===
	{
		name:         "simple/false",
		value:        Bool(false),
		canonicalHex: "f4",
		notes:        "fxamacker/cbor, cbor2: simple value 20",
	},
	{
		name:         "simple/true",
		value:        Bool(true),
		canonicalHex: "f5",
		notes:        "fxamacker/cbor, cbor2: simple value 21",
	},
	{
		name:         "simple/null",
		value:        Null{},
		canonicalHex: "f6",
		notes:        "fxamacker/cbor, cbor2: simple value 22",
	},
	{
		name:         "simple/undefined",
		value:        Undefined{},
		canonicalHex: "f7",
		notes:        "fxamacker/cbor, cbor2: simple value 23",
	},
	{
		name:         "simple/16",
		value:        Simple(16),
		canonicalHex: "f0",
		notes:        "fxamacker/cbor: unassigned simple value 16 (inline)",
	},
	{
		name:         "simple/255",
		value:        Simple(255),
		canonicalHex: "f8ff",
		notes:        "fxamacker/cbor: unassigned simple value 255 (1-byte)",
	},
}

// quirkyVectors tests Postel's law: we must correctly decode non-canonical
// CBOR that other implementations produce even though we would never encode it.
var quirkyVectors = []quirkyVector{
	// === Non-shortest integer encodings ===
	{
		name:      "quirky/non-shortest-uint-0-in-1byte",
		inputHex:  "1800",
		wantValue: Uint(0),
		notes:     "ugorji/go codec in non-canonical mode: uint 0 in 1-byte payload",
	},
	{
		name:      "quirky/non-shortest-uint-0-in-2byte",
		inputHex:  "190000",
		wantValue: Uint(0),
		notes:     "Some older Java CBOR libs: uint 0 in 2-byte payload",
	},
	{
		name:      "quirky/non-shortest-uint-0-in-4byte",
		inputHex:  "1a00000000",
		wantValue: Uint(0),
		notes:     "Legacy encoders: uint 0 in 4-byte payload",
	},
	{
		name:      "quirky/non-shortest-uint-0-in-8byte",
		inputHex:  "1b0000000000000000",
		wantValue: Uint(0),
		notes:     "Legacy encoders: uint 0 in 8-byte payload",
	},
	{
		name:      "quirky/non-shortest-uint-23-in-1byte",
		inputHex:  "1817",
		wantValue: Uint(23),
		notes:     "ugorji/go in non-canonical mode: 23 requires only inline encoding",
	},
	{
		name:      "quirky/non-shortest-uint-255-in-2byte",
		inputHex:  "1900ff",
		wantValue: Uint(255),
		notes:     "Some encoders always use 2-byte for values > 23",
	},

	// === Indefinite-length strings ===
	{
		name:      "quirky/indef-bytes-empty",
		inputHex:  "5fff",
		wantValue: Bytes(nil),
		notes:     "Streaming encoders: indefinite byte string with no chunks",
	},
	{
		name:      "quirky/indef-bytes-two-chunks",
		inputHex:  "5f41014102ff",
		wantValue: Bytes([]byte{0x01, 0x02}),
		notes:     "Streaming encoders: indefinite byte string [0x01] + [0x02]",
	},
	{
		name:      "quirky/indef-text-empty",
		inputHex:  "7fff",
		wantValue: Text(""),
		notes:     "Streaming encoders: indefinite text string with no chunks",
	},
	{
		name:      "quirky/indef-text-two-chunks",
		inputHex:  "7f6568656c6c6f65776f726c64ff",
		wantValue: Text("helloworld"),
		notes:     "Streaming encoders: indefinite text 'hello' + 'world'",
	},
	{
		name:      "quirky/indef-array",
		inputHex:  "9f010203ff",
		wantValue: Array{Uint(1), Uint(2), Uint(3)},
		notes:     "Streaming encoders: indefinite array [1, 2, 3]",
	},
	{
		name:      "quirky/indef-map",
		inputHex:  "bf616101616202616303616404616505616606ff",
		wantValue: Map{{Key: Text("a"), Value: Uint(1)}, {Key: Text("b"), Value: Uint(2)}, {Key: Text("c"), Value: Uint(3)}, {Key: Text("d"), Value: Uint(4)}, {Key: Text("e"), Value: Uint(5)}, {Key: Text("f"), Value: Uint(6)}},
		notes:     "Streaming encoders: indefinite-length map with text keys",
	},

	// === Maps with unsorted keys ===
	{
		name:      "quirky/unsorted-map-text-keys",
		inputHex:  "a26162026161" + "01",
		wantValue: Map{{Key: Text("b"), Value: Uint(2)}, {Key: Text("a"), Value: Uint(1)}},
		notes:     "Non-deterministic encoders: map {b:2, a:1} with keys in insertion order",
	},
	{
		name:      "quirky/unsorted-map-int-keys",
		inputHex:  "a2186401" + "0a02",
		wantValue: Map{{Key: Uint(100), Value: Uint(1)}, {Key: Uint(10), Value: Uint(2)}},
		notes:     "Non-deterministic encoders: map {100:1, 10:2} unsorted",
	},
}

func TestCompatEncode(t *testing.T) {
	enc := New(ModeCoreDeterministic, AllowNonFiniteFloats())

	for _, tc := range compatVectors {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.canonicalHex)
			if err != nil {
				t.Fatalf("invalid fixture hex %q: %v", tc.canonicalHex, err)
			}

			got, err := enc.Encode(nil, tc.value)
			if err != nil {
				t.Fatalf("Encode error: %v\n  value: %#v\n  notes: %s", err, tc.value, tc.notes)
			}

			if !bytes.Equal(got, want) {
				t.Errorf("encoding mismatch:\n  value: %#v\n  got:  %s\n  want: %s\n  notes: %s",
					tc.value,
					hex.EncodeToString(got),
					hex.EncodeToString(want),
					tc.notes)
			}
		})
	}
}

func TestCompatDecode(t *testing.T) {
	enc := New(ModeCoreDeterministic, AllowNonFiniteFloats())
	dec := NewDecoder()

	for _, tc := range compatVectors {
		t.Run(tc.name, func(t *testing.T) {
			input, err := hex.DecodeString(tc.canonicalHex)
			if err != nil {
				t.Fatalf("invalid fixture hex %q: %v", tc.canonicalHex, err)
			}

			decoded, err := dec.Decode(input)
			if err != nil {
				t.Fatalf("Decode error: %v\n  hex: %s\n  notes: %s", err, tc.canonicalHex, tc.notes)
			}

			// Verify by re-encoding: decoded value must produce identical bytes
			reencoded, err := enc.Encode(nil, decoded)
			if err != nil {
				t.Fatalf("re-encode error: %v\n  decoded: %#v", err, decoded)
			}

			wantEncoded, err := enc.Encode(nil, tc.value)
			if err != nil {
				t.Fatalf("encode expected value error: %v", err)
			}

			if !bytes.Equal(reencoded, wantEncoded) {
				t.Errorf("decode→re-encode mismatch:\n  input hex:  %s\n  re-encoded: %s\n  expected:   %s\n  notes: %s",
					tc.canonicalHex,
					hex.EncodeToString(reencoded),
					hex.EncodeToString(wantEncoded),
					tc.notes)
			}
		})
	}
}

func TestCompatQuirkyDecode(t *testing.T) {
	enc := New(ModeCoreDeterministic, AllowNonFiniteFloats())
	// Permissive decoder: accepts non-canonical encodings
	dec := NewDecoder()

	for _, tc := range quirkyVectors {
		t.Run(tc.name, func(t *testing.T) {
			input, err := hex.DecodeString(tc.inputHex)
			if err != nil {
				t.Fatalf("invalid fixture hex %q: %v", tc.inputHex, err)
			}

			decoded, err := dec.Decode(input)
			if err != nil {
				t.Fatalf("Decode error (Postel's law violation): %v\n  hex: %s\n  notes: %s",
					err, tc.inputHex, tc.notes)
			}

			// Compare by re-encoding both decoded and expected values
			gotEnc, err := enc.Encode(nil, decoded)
			if err != nil {
				t.Fatalf("re-encode decoded value: %v\n  decoded: %#v", err, decoded)
			}

			wantEnc, err := enc.Encode(nil, tc.wantValue)
			if err != nil {
				t.Fatalf("encode expected value: %v\n  expected: %#v", err, tc.wantValue)
			}

			if !bytes.Equal(gotEnc, wantEnc) {
				t.Errorf("quirky decode mismatch:\n  input hex: %s\n  decoded→encoded: %s\n  expected→encoded: %s\n  notes: %s",
					tc.inputHex,
					hex.EncodeToString(gotEnc),
					hex.EncodeToString(wantEnc),
					tc.notes)
			}
		})
	}
}

func TestCompatStrictRejectsNonCanonical(t *testing.T) {
	// Verify that the strict decoder rejects the non-canonical quirky
	// vectors (confirms we distinguish canonical from non-canonical).
	strict := StrictDecoder()

	// Non-shortest encodings should be rejected
	nonShortestCases := []struct {
		name     string
		inputHex string
	}{
		{"non-shortest-uint-0-in-1byte", "1800"},
		{"non-shortest-uint-0-in-2byte", "190000"},
		{"non-shortest-uint-0-in-4byte", "1a00000000"},
		{"non-shortest-uint-0-in-8byte", "1b0000000000000000"},
		{"non-shortest-uint-23-in-1byte", "1817"},
	}

	for _, tc := range nonShortestCases {
		t.Run(tc.name, func(t *testing.T) {
			input, _ := hex.DecodeString(tc.inputHex)
			_, err := strict.Decode(input)
			if err == nil {
				t.Errorf("strict decoder accepted non-shortest encoding %s; want rejection", tc.inputHex)
			}
		})
	}

	// Indefinite-length encodings should be rejected
	indefCases := []struct {
		name     string
		inputHex string
	}{
		{"indef-bytes", "5fff"},
		{"indef-text", "7fff"},
		{"indef-array", "9f010203ff"},
	}

	for _, tc := range indefCases {
		t.Run(tc.name, func(t *testing.T) {
			input, _ := hex.DecodeString(tc.inputHex)
			_, err := strict.Decode(input)
			if err == nil {
				t.Errorf("strict decoder accepted indefinite-length encoding %s; want rejection", tc.inputHex)
			}
		})
	}
}

// TestCompatRoundTrip ensures every compatibility vector survives a full
// encode→decode→encode cycle without data loss.
func TestCompatRoundTrip(t *testing.T) {
	enc := New(ModeCoreDeterministic, AllowNonFiniteFloats())
	dec := NewDecoder()

	for _, tc := range compatVectors {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoded, err := enc.Encode(nil, tc.value)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}

			// Decode
			decoded, err := dec.Decode(encoded)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}

			// Re-encode
			reencoded, err := enc.Encode(nil, decoded)
			if err != nil {
				t.Fatalf("Re-encode: %v", err)
			}

			if !bytes.Equal(encoded, reencoded) {
				t.Errorf("round-trip failed:\n  first:  %s\n  second: %s",
					hex.EncodeToString(encoded),
					hex.EncodeToString(reencoded))
			}
		})
	}
}

// TestCompatHexFixtureIntegrity validates that all fixture hex strings are
// well-formed and contain valid CBOR (decodable by our permissive decoder).
func TestCompatHexFixtureIntegrity(t *testing.T) {
	dec := NewDecoder()

	t.Run("compat-vectors", func(t *testing.T) {
		for _, tc := range compatVectors {
			t.Run(tc.name, func(t *testing.T) {
				b, err := hex.DecodeString(tc.canonicalHex)
				if err != nil {
					t.Fatalf("malformed hex in fixture: %v", err)
				}
				if _, err := dec.Decode(b); err != nil {
					t.Fatalf("fixture is not valid CBOR: %v\n  hex: %s", err, tc.canonicalHex)
				}
			})
		}
	})

	t.Run("quirky-vectors", func(t *testing.T) {
		for _, tc := range quirkyVectors {
			t.Run(tc.name, func(t *testing.T) {
				b, err := hex.DecodeString(tc.inputHex)
				if err != nil {
					t.Fatalf("malformed hex in fixture: %v", err)
				}
				if _, err := dec.Decode(b); err != nil {
					t.Fatalf("fixture is not valid CBOR: %v\n  hex: %s", err, tc.inputHex)
				}
			})
		}
	})
}

// TestCompatVectorCount ensures we maintain the minimum number of
// compatibility vectors as required by proposal 007.
func TestCompatVectorCount(t *testing.T) {
	total := len(compatVectors) + len(quirkyVectors)
	const minRequired = 30
	if total < minRequired {
		t.Errorf("compatibility vector count %d < minimum required %d", total, minRequired)
	}
	t.Logf("Total compatibility vectors: %d (compat=%d, quirky=%d)",
		total, len(compatVectors), len(quirkyVectors))
}

func init() {
	// Sanity check: verify no duplicate test names
	seen := make(map[string]bool)
	for _, tc := range compatVectors {
		name := fmt.Sprintf("compat/%s", tc.name)
		if seen[name] {
			panic(fmt.Sprintf("duplicate compat vector name: %s", tc.name))
		}
		seen[name] = true
	}
	for _, tc := range quirkyVectors {
		name := fmt.Sprintf("quirky/%s", tc.name)
		if seen[name] {
			panic(fmt.Sprintf("duplicate quirky vector name: %s", tc.name))
		}
		seen[name] = true
	}
}
