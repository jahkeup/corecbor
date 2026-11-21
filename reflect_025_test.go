// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// Proposal 025 Phase B/D.

// sigStructure is RFC 9052 §4.4 Sig_structure for COSE_Sign1.
type sigStructure struct {
	_             struct{} `cbor:",toarray"`
	Context       string
	BodyProtected []byte
	ExternalAAD   []byte
	Payload       []byte
}

func TestMarshalToArraySigStructure(t *testing.T) {
	// RFC 9052 Appendix C.2.1: ToBeSigned for the COSE_Sign1 example.
	in := sigStructure{
		Context:       "Signature1",
		BodyProtected: mustHex(t, "a10126"),
		ExternalAAD:   []byte{},
		Payload:       []byte("This is the content."),
	}
	want := "846a5369676e61747572653143a101264054546869732069732074686520636f6e74656e742e"
	got, err := New(ModeCoreDeterministic).Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("Marshal = %x\n want %s", got, want)
	}
	var out sigStructure
	if err := Unmarshal(got, &out); err != nil {
		t.Fatal(err)
	}
	if out.Context != in.Context || string(out.Payload) != string(in.Payload) || hex.EncodeToString(out.BodyProtected) != "a10126" {
		t.Fatalf("round trip = %+v", out)
	}
	// A map isn't a toarray struct.
	if err := Unmarshal(mustHex(t, "a0"), &out); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("map into toarray struct: err = %v", err)
	}
}

type arrTail struct {
	_   struct{} `cbor:",toarray"`
	A   int
	B   string
	Opt *int
	Raw RawMessage `cbor:",tag=24"`
}

func TestUnmarshalToArrayLength(t *testing.T) {
	type head struct {
		_ struct{} `cbor:",toarray"`
		A int
		B string
		C *int
	}
	var h head
	if err := Unmarshal(mustHex(t, "82016162"), &h); err != nil || h.A != 1 || h.B != "b" || h.C != nil {
		t.Fatalf("short array with pointer tail: %+v, %v", h, err)
	}
	if err := Unmarshal(mustHex(t, "830161620c"), &h); err != nil || h.C == nil || *h.C != 12 {
		t.Fatalf("full array: %+v, %v", h, err)
	}
	if err := Unmarshal(mustHex(t, "8401616203f6"), &h); !errors.Is(err, ErrArrayLength) {
		t.Fatalf("too long: err = %v", err)
	}
	if err := Unmarshal(mustHex(t, "8101"), &h); !errors.Is(err, ErrArrayLength) {
		t.Fatalf("missing non-pointer field: err = %v", err)
	}

	// Raw path: a RawMessage field (under tag=24) makes the struct
	// decode from source bytes; the same length rules apply.
	var a arrTail
	if err := Unmarshal(mustHex(t, "84016162f6d81843a10102"), &a); err != nil {
		t.Fatal(err)
	}
	if a.A != 1 || a.B != "b" || a.Opt != nil || hex.EncodeToString(a.Raw) != "43a10102" {
		t.Fatalf("raw toarray = %+v (raw %x)", a, []byte(a.Raw))
	}
	if err := Unmarshal(mustHex(t, "85016162f6d8184001"), &a); !errors.Is(err, ErrArrayLength) {
		t.Fatalf("raw too long: err = %v", err)
	}

	type bad struct {
		_ struct{} `cbor:",toarray"`
		A int      `cbor:",omitempty"`
	}
	if _, err := Marshal(bad{}); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("omitempty in toarray: err = %v", err)
	}
}

func TestDisallowUnknownFields(t *testing.T) {
	type S struct {
		A int `cbor:"a"`
	}
	type R struct {
		A int        `cbor:"a"`
		R RawMessage `cbor:"r"`
	}
	data := mustHex(t, "a2616101617802") // {"a": 1, "x": 2}
	var s S
	if err := Unmarshal(data, &s); err != nil || s.A != 1 {
		t.Fatalf("default skips unknown: %+v, %v", s, err)
	}
	strict := NewDecoder(DisallowUnknownFields())
	if err := strict.Unmarshal(data, &s); !errors.Is(err, ErrUnknownField) || !strings.Contains(err.Error(), `"x"`) {
		t.Fatalf("DisallowUnknownFields: err = %v", err)
	}
	var r R
	if err := strict.Unmarshal(data, &r); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("raw path DisallowUnknownFields: err = %v", err)
	}
}

type upper string

func (u *upper) UnmarshalText(b []byte) error {
	*u = upper(strings.ToUpper(string(b)))
	return nil
}

type stamp struct{ s string }

func (s stamp) MarshalText() ([]byte, error) { return []byte("v=" + s.s), nil }

func (s *stamp) UnmarshalText(b []byte) error {
	v, ok := strings.CutPrefix(string(b), "v=")
	if !ok {
		return errors.New("bad stamp")
	}
	s.s = v
	return nil
}

func TestTextBinaryUnmarshaler(t *testing.T) {
	type S struct {
		Addr  netip.Addr `cbor:"addr"`
		Stamp stamp      `cbor:"stamp"`
		Up    upper      `cbor:"up"`
	}
	in := S{Addr: netip.MustParseAddr("192.0.2.7"), Stamp: stamp{"x"}, Up: "abc"}
	data, err := Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out S
	if err := Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Addr != in.Addr || out.Stamp != in.Stamp || out.Up != "ABC" {
		t.Fatalf("round trip = %+v", out)
	}

	// v0.2 behavior: string-kinded types take the text as-is, and other
	// implementers are a type mismatch.
	var legacy S
	err = NewDecoder(WithLegacyNoTextBinaryUnmarshal()).Unmarshal(data, &legacy)
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("legacy: err = %v", err)
	}
	type L struct {
		Up upper `cbor:"up"`
	}
	var l L
	if err := NewDecoder(CompatV02Decoding()).Unmarshal(mustHex(t, "a1627570626162"), &l); err != nil || l.Up != "ab" {
		t.Fatalf("CompatV02Decoding: %+v, %v", l, err)
	}
}

type zeroer struct{ n int }

func (z zeroer) IsZero() bool { return z.n == 0 || z.n == 7 }

func TestOmitZero(t *testing.T) {
	type S struct {
		Z    zeroer    `cbor:"z,omitzero"`
		T    time.Time `cbor:"t,omitzero"`
		N    int       `cbor:"n,omitzero"`
		Arr  [2]int    `cbor:"arr,omitzero"`
		Keep [2]int    `cbor:"keep,omitempty"`
	}
	got, err := Marshal(S{Z: zeroer{7}})
	if err != nil {
		t.Fatal(err)
	}
	// Only "keep" remains: omitempty never omits a fixed-size array.
	if want := "a1646b65657082" + "0000"; hex.EncodeToString(got) != want {
		t.Fatalf("Marshal = %x, want %s", got, want)
	}
	got, _ = Marshal(S{Z: zeroer{1}, N: 2})
	if !strings.Contains(hex.EncodeToString(got), "617a") || !strings.Contains(hex.EncodeToString(got), "616e02") {
		t.Fatalf("non-zero fields kept: %x", got)
	}
}

type named struct {
	UserID string
	Tagged int `cbor:"t"`
}

func TestFieldNamesDefaultUnchanged(t *testing.T) {
	got, err := Marshal(named{UserID: "u", Tagged: 1})
	if err != nil {
		t.Fatal(err)
	}
	if want := "a2617401667573657269646175"; hex.EncodeToString(got) != want {
		t.Fatalf("default Marshal = %x, want %s", got, want)
	}
}

func TestWithGoFieldNames(t *testing.T) {
	got, err := New(ModeCoreDeterministic, WithGoFieldNames()).Marshal(named{UserID: "u", Tagged: 1})
	if err != nil {
		t.Fatal(err)
	}
	if want := "a26174016655736572494461" + "75"; hex.EncodeToString(got) != want {
		t.Fatalf("WithGoFieldNames Marshal = %x, want %s", got, want)
	}

	// Default decode matches only the default naming.
	var n named
	if err := Unmarshal(got, &n); err != nil || n.UserID != "" || n.Tagged != 1 {
		t.Fatalf("default decode of Go names: %+v, %v", n, err)
	}
	ci := NewDecoder(WithCaseInsensitiveFieldNames())
	if err := ci.Unmarshal(got, &n); err != nil || n.UserID != "u" {
		t.Fatalf("case-insensitive decode: %+v, %v", n, err)
	}

	// Both spellings present: the exact one wins, in either order; with
	// DisallowUnknownFields the other is an error.
	for _, h := range []string{
		"a2665573657249446161667573657269646162", // {"UserID": "a", "userid": "b"}
		"a2667573657269646162665573657249446161", // {"userid": "b", "UserID": "a"}
	} {
		var m named
		if err := ci.Unmarshal(mustHex(t, h), &m); err != nil || m.UserID != "b" {
			t.Fatalf("%s: %+v, %v", h, m, err)
		}
		err := NewDecoder(WithCaseInsensitiveFieldNames(), DisallowUnknownFields()).Unmarshal(mustHex(t, h), &m)
		if !errors.Is(err, ErrUnknownField) {
			t.Fatalf("%s with DisallowUnknownFields: err = %v", h, err)
		}
	}
}

func TestStructCacheConcurrent(t *testing.T) {
	type S struct {
		A int `cbor:"a"`
		B string
		C []int `cbor:",omitempty"`
	}
	enc := NewShared(ModeCoreDeterministic, WithGoFieldNames())
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 200 {
				data, err := Marshal(S{A: i, B: "x"})
				if err != nil {
					t.Error(err)
					return
				}
				var s S
				if err := Unmarshal(data, &s); err != nil || s.A != i {
					t.Errorf("Unmarshal = %+v, %v", s, err)
					return
				}
				if _, err := enc.Marshal(S{A: i}); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
}
