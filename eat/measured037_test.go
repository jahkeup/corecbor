// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/eat"
)

// W29: RFC 10013 measured components (CBOR, Content-Format 295).
func TestMeasuredComponent037(t *testing.T) {
	scheme := int64(1)
	digest := bytes.Repeat([]byte{0xaa}, 32)
	in := &eat.MeasuredComponent{
		Name:        "BL",
		Version:     &eat.Version{Version: "2.1.0", Scheme: &scheme},
		Digest:      &eat.ComponentDigest{Alg: 1, Value: digest}, // sha-256 (named information)
		Authorities: [][]byte{{1, 2, 3}},
		Flags:       make([]byte, 8),
	}
	b, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// {1: ["BL", ["2.1.0", 1]], 2: [1, h'aa..'], 3: [h'010203'], 4: h'00..'}
	want := hx(t, "a4"+"0182"+"62424c"+"8265322e312e3001"+"02820158"+"20"+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+"03814301020304"+"48"+"0000000000000000")
	if !bytes.Equal(b, want) {
		t.Fatalf("Encode = %x\nwant     %x", b, want)
	}
	out, err := eat.ParseMeasuredComponent(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Name != "BL" || out.Version.Version != "2.1.0" || *out.Version.Scheme != 1 || out.Digest.Alg != 1 ||
		!bytes.Equal(out.Digest.Value, digest) || len(out.Authorities) != 1 || len(out.Flags) != 8 {
		t.Fatalf("parsed %+v", out)
	}

	// RFC 10013 Figure 2, re-encoded from its diagnostic notation.
	semver := int64(16384)
	fig2 := &eat.MeasuredComponent{
		Name:    "boot loader X",
		Version: &eat.Version{Version: "1.2.3rc2", Scheme: &semver},
		Digest:  &eat.ComponentDigest{AlgName: "sha-256", Value: hx(t, "3996003d486fb91ffb056f7d03f2b2992b215b31dbe7af4b373431fc7d319da3")},
		Authorities: [][]byte{
			hx(t, "492e9b676c21f6012b1ceeb9032feb4141a880797355f6675015ec59c51ca1ec"),
			hx(t, "4277bb97ba7b51577a0d38151d3e08b40bdf946753f5b5bdeb814d6ff57a8a5e"),
		},
		Flags: hx(t, "0000000000000101"),
	}
	fb, err := fig2.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := eat.ParseMeasuredComponent(fb); err != nil || got.Digest.AlgName != "sha-256" || *got.Version.Scheme != 16384 || len(got.Authorities) != 2 {
		t.Fatalf("Figure 2: %+v, %v", got, err)
	}

	raw, err := (&eat.MeasuredComponent{Name: "reg", Raw: []byte{9}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if m, err := eat.ParseMeasuredComponent(raw); err != nil || !bytes.Equal(m.Raw, []byte{9}) || m.Digest != nil {
		t.Fatalf("raw measurement: %+v, %v", m, err)
	}

	for name, hexIn := range map[string]string{
		"no measurement":   "a1018162424c",                 // {1: ["BL"]}
		"both forms":       "a3018162424c0282014101054101", // {1:..., 2: [1, h'01'], 5: h'01'}
		"no id":            "a1054101",                     // {5: h'01'}
		"flags 7 bytes":    "a3018162424c054101044700000000000000",
		"unknown member":   "a3018162424c0541010a01", // 10: 1
		"empty authority":  "a3018162424c0541010380",
		"digest alg float": "a2018162424c0282f93c004101",
		"not a map":        "80",
		"trailing bytes":   "a2018162424c054101" + "00",
	} {
		if _, err := eat.ParseMeasuredComponent(hx(t, hexIn)); !errors.Is(err, eat.ErrMalformedEAT) {
			t.Errorf("%s: %v, want ErrMalformedEAT", name, err)
		}
	}

	// Measurements carrying Content-Format 295 are checked by Validate.
	cf := eat.ContentFormatMeasuredComponentCBOR
	good := &eat.Claims{Measurements: []eat.TypedBytes{{ContentFormat: &cf, Value: b}}}
	if err := good.Validate(); err != nil {
		t.Errorf("Validate, valid measured component: %v", err)
	}
	if m, ok, err := good.Measurements[0].MeasuredComponent(); !ok || err != nil || m.Name != "BL" {
		t.Errorf("TypedBytes.MeasuredComponent = %+v, %v, %v", m, ok, err)
	}
	bad := &eat.Claims{Measurements: []eat.TypedBytes{{ContentFormat: &cf, Value: []byte{0xa0}}}}
	if err := bad.Validate(); !claimIs(err, eat.ClaimMeasurements, eat.ErrInvalidClaimValue) {
		t.Errorf("Validate, malformed measured component: %v", err)
	}
	other := uint64(60)
	if _, ok, _ := (eat.TypedBytes{ContentFormat: &other, Value: []byte{1}}).MeasuredComponent(); ok {
		t.Error("TypedBytes.MeasuredComponent ok for another content format")
	}
}
