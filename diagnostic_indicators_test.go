// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/hex"
	"testing"
)

func TestDiagnostic_NegIntMin(t *testing.T) {
	// -2^64: NegInt(2^64-1). v0.2 printed "-0".
	got := DiagnosticValue(NegInt(^uint64(0)))
	if want := "-18446744073709551616"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := DiagnosticValue(NegInt(0)); got != "-1" {
		t.Fatalf("NegInt(0): got %q, want -1", got)
	}
}

func TestDiagnostic_InvalidUTF8(t *testing.T) {
	for _, tc := range []struct{ hex, want string }{
		{"61ff", "/ text, invalid UTF-8 / h'ff'"},
		{"6261ff", "/ text, invalid UTF-8 / h'61ff'"},
		{"6161", `"a"`},
	} {
		got, err := Diagnostic(mustHex(t, tc.hex))
		if err != nil {
			t.Fatalf("%s: %v", tc.hex, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.hex, got, tc.want)
		}
	}
}

func TestDiagnostic_Indicators(t *testing.T) {
	cases := []struct{ hex, want string }{
		// Shortest encodings carry no indicator.
		{"00", "0"},
		{"1818", "24"},
		{"f93c00", "1.0"},
		{"8201820203", "[1, [2, 3]]"},
		// Non-shortest arguments: _0.._3 for AI 24..27.
		{"1800", "0_0"},
		{"190001", "1_1"},
		{"1a00000001", "1_2"},
		{"1b0000000000000001", "1_3"},
		{"3800", "-1_0"},
		{"5800", "h''_0"},
		{"780161", `"a"_0`},
		{"980101", "[_0 1]"},
		{"b8010102", "{_0 1: 2}"},
		{"d8010a", "1_0(10)"},
		// Floats wider than needed.
		{"fa3f800000", "1.0_2"},
		{"fb3ff0000000000000", "1.0_3"},
		{"fb3ff199999999999a", "1.1"},
		// Indefinite lengths.
		{"9f0102ff", "[_ 1, 2]"},
		{"9fff", "[_ ]"},
		{"bf616101ff", `{_ "a": 1}`},
		{"5f4201024103ff", "(_ h'0102', h'03')"},
		{"7f61616162ff", `(_ "a", "b")`},
		// Leading self-describe tag is stripped, as by the decoder.
		{"d9d9f71800", "0_0"},
		// Invalid UTF-8 keeps its indicator.
		{"7801ff", "/ text, invalid UTF-8 / h'ff'_0"},
	}
	for _, tc := range cases {
		got, err := Diagnostic(mustHex(t, tc.hex), DiagIndicators())
		if err != nil {
			t.Fatalf("%s: %v", tc.hex, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.hex, got, tc.want)
		}
	}
}

func TestDiagnostic_IndicatorsCompact(t *testing.T) {
	got, err := Diagnostic(mustHex(t, "9f01bf61611801ffff"), DiagIndicators(), DiagCompact())
	if err != nil {
		t.Fatal(err)
	}
	// The space after "_" stays so "[_ 1" can't read as "[_1".
	if want := `[_ 1,{_ "a":1_0}]`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDiagnosticValue_IgnoresIndicators(t *testing.T) {
	v, err := NewDecoder().Decode(mustHex(t, "9f1800ff"))
	if err != nil {
		t.Fatal(err)
	}
	if got := DiagnosticValue(v, DiagIndicators()); got != "[0]" {
		t.Fatalf("got %q, want [0]", got)
	}
}

func FuzzDiagnosticNeverPanics(f *testing.F) {
	for _, h := range []string{
		"00", "1800", "9f0102ff", "bf616101ff", "5f4201024103ff", "7f61616162ff",
		"61ff", "3bffffffffffffffff", "fa3f800000", "d9d9f7d9d9f700", "c1fb41d6b5f8d9000000",
	} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Diagnostic(data)
		_, _ = Diagnostic(data, DiagIndicators())
		_, _ = Diagnostic(data, DiagIndicators(), DiagCompact())
	})
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// D19: Diagnostic shows every encoded map entry, with or without
// indicators; DiagnosticValue renders the resolved Value.
func TestD19_DiagnosticShowsDuplicateKeys(t *testing.T) {
	data := mustHex(t, "a2616101616102") // {"a": 1, "a": 2}
	for name, opts := range map[string][]DiagnosticOption{
		"plain":      nil,
		"compact":    {DiagCompact()},
		"indicators": {DiagIndicators()},
	} {
		got, err := Diagnostic(data, opts...)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"a": 1, "a": 2}`
		if name == "compact" {
			want = `{"a":1,"a":2}`
		}
		if got != want {
			t.Errorf("%s: Diagnostic = %s, want %s", name, got, want)
		}
	}
	v, err := NewDecoder().Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := DiagnosticValue(v); got != `{"a": 2}` {
		t.Errorf("DiagnosticValue = %s, want {\"a\": 2}", got)
	}
}
