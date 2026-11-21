// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package utf8x

import (
	"testing"
	"unicode/utf8"
)

func TestReplacedMatchesRange(t *testing.T) {
	for _, s := range []string{"", "ab", "a\xffb", "a\xff\xfeb", "x\xed\xa0\x80y", "\xe2\x82", "€\x80", "�"} {
		var want []rune
		for _, r := range s {
			want = append(want, r)
		}
		got := Replaced(s)
		if got != string(want) || !utf8.ValidString(got) {
			t.Errorf("Replaced(%q) = %q, want %q", s, got, string(want))
		}
	}
	if got := Replaced("a\xffb"); got != "a�b" {
		t.Errorf("Replaced(a\\xffb) = %q", got)
	}
	if got := Replaced("x\xed\xa0\x80y"); got != "x���y" {
		t.Errorf("Replaced(lone surrogate) = %q (Go treats each byte of an encoded surrogate as invalid)", got)
	}
}

func TestIsWTF8(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"", false},
		{"ab", false},                       // valid UTF-8: no special form needed
		{"x\xed\xa0\x80y", true},            // lone lead surrogate U+D800
		{"\xed\xbf\xbf", true},              // lone trail surrogate U+DFFF
		{"\xed\xb0\x80\xed\xa0\x80", true},  // trail then lead: allowed
		{"\xed\xa0\x80\xed\xb0\x80", false}, // lead then trail: must be a 4-byte sequence
		{"a\xffb", false},                   // arbitrary invalid byte
		{"\xed\xa0", false},                 // truncated surrogate
		{"\xed\xa0\x80\xff", false},         // surrogate plus another defect
		{"€\xed\xa0\x80", true},
	}
	for _, c := range cases {
		if got := IsWTF8(c.s); got != c.want {
			t.Errorf("IsWTF8(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}
