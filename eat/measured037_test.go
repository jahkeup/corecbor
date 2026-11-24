// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/eat"
)

// rfc10013Fig4 is the measured component of RFC 10013 Figure 4, with
// the RFC 8792 line folding undone.
const rfc10013Fig4 = `{ "id": [ "boot loader X", [ "1.2.3rc2", 16384 ] ], "digested-measurement": [ "sha-256", "OZYAPUhvuR_7BW99A_KymSshWzHb569LNzQx_H0xnaM" ], "authorities": [ "SS6bZ2wh9gErHO65Ay_rQUGogHlzVfZnUBXsWcUcoew", "Qne7l7p7UVd6DTgVHT4ItAvflGdT9bW964FNb_V6il4" ] }`

// RFC 10013 measured components, JSON form (mc-json, Content-Format
// 296), carried as a text string in a CBOR EAT ("tunnel").
func TestMeasuredComponentJSON037(t *testing.T) {
	m, err := eat.ParseMeasuredComponentJSON([]byte(rfc10013Fig4))
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "boot loader X" || m.Version == nil || m.Version.Version != "1.2.3rc2" || *m.Version.Scheme != 16384 ||
		m.Digest == nil || m.Digest.AlgName != "sha-256" ||
		!bytes.Equal(m.Digest.Value, hx(t, "3996003d486fb91ffb056f7d03f2b2992b215b31dbe7af4b373431fc7d319da3")) ||
		len(m.Authorities) != 2 || !bytes.Equal(m.Authorities[1], hx(t, "4277bb97ba7b51577a0d38151d3e08b40bdf946753f5b5bdeb814d6ff57a8a5e")) {
		t.Fatalf("Figure 4: %+v", m)
	}
	js, err := m.EncodeJSON()
	if err != nil {
		t.Fatal(err)
	}
	again, err := eat.ParseMeasuredComponentJSON(js)
	if err != nil || again.Name != m.Name || !bytes.Equal(again.Digest.Value, m.Digest.Value) {
		t.Fatalf("EncodeJSON round trip: %s, %+v, %v", js, again, err)
	}
	for name, in := range map[string]string{
		"duplicate member": `{"id":["a"],"raw-measurement":"AQ","raw-measurement":"Ag"}`,
		"unknown member":   `{"id":["a"],"raw-measurement":"AQ","x":1}`,
		"padded base64":    `{"id":["a"],"raw-measurement":"AQ=="}`,
		"std base64":       `{"id":["a"],"raw-measurement":"+/8"}`,
		"flags 7 bytes":    `{"id":["a"],"raw-measurement":"AQ","flags":"AAAAAAAAAA"}`,
		"both forms":       `{"id":["a"],"raw-measurement":"AQ","digested-measurement":[1,"AQ"]}`,
		"no id":            `{"raw-measurement":"AQ"}`,
		"integer keys":     `{"1":["a"],"5":"AQ"}`,
		"trailing data":    `{"id":["a"],"raw-measurement":"AQ"} {}`,
		"not an object":    `["a"]`,
		"empty authority":  `{"id":["a"],"raw-measurement":"AQ","authorities":[]}`,
		"fractional alg":   `{"id":["a"],"digested-measurement":[1.5,"AQ"]}`,
	} {
		if _, err := eat.ParseMeasuredComponentJSON([]byte(in)); !errors.Is(err, eat.ErrMalformedEAT) {
			t.Errorf("%s: %v, want ErrMalformedEAT", name, err)
		}
	}

	// In a CBOR EAT the JSON form is a text string: {273: [[296, "..."]]}.
	cf := eat.ContentFormatMeasuredComponentJSON
	c := &eat.Claims{Measurements: []eat.TypedBytes{{ContentFormat: &cf, Value: []byte(rfc10013Fig4), Text: true}}}
	enc := encodeClaimsT(t, c)
	dec, err := eat.DecodeClaims(enc) // Text is set only for a CBOR text string
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Measurements[0].Text || !bytes.Equal(encodeClaimsT(t, dec), enc) {
		t.Fatalf("decoded %+v, re-encoded differently", dec.Measurements[0])
	}
	if err := dec.Validate(); err != nil {
		t.Errorf("Validate, Figure 4 measurement: %v", err)
	}
	if got, ok, err := dec.Measurements[0].MeasuredComponent(); !ok || err != nil || got.Name != "boot loader X" {
		t.Errorf("TypedBytes.MeasuredComponent (296): %+v, %v, %v", got, ok, err)
	}
	for name, tb := range map[string]eat.TypedBytes{
		"bad JSON":     {ContentFormat: &cf, Value: []byte(`{"id":["a"]}`), Text: true},
		"296 as bytes": {ContentFormat: &cf, Value: []byte(rfc10013Fig4)},
	} {
		if err := (&eat.Claims{Measurements: []eat.TypedBytes{tb}}).Validate(); !claimIs(err, eat.ClaimMeasurements, eat.ErrInvalidClaimValue) {
			t.Errorf("Validate, %s: %v", name, err)
		}
	}
	cbor295 := eat.ContentFormatMeasuredComponentCBOR
	if err := (&eat.Claims{Measurements: []eat.TypedBytes{{ContentFormat: &cbor295, Value: []byte{0xa0}, Text: true}}}).Validate(); !claimIs(err, eat.ClaimMeasurements, eat.ErrInvalidClaimValue) {
		t.Errorf("Validate, 295 as text: %v", err)
	}
}

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
