// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package psa_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/eat"
	"github.com/jahkeup/corecbor/eat/psa"
)

// RFC 9783 Appendix A.1: a PSA token as a tagged COSE_Sign1, and the
// JWK of the key that signed it.
const (
	rfc9783Token = "d28443a10126a0590100a819010058210102020202020202020202020202" +
		"0202020202020202020202020202020202020219095c5820000000000000" +
		"00000000000000000000000000000000000000000000000000000a582001" +
		"010101010101010101010101010101010101010101010101010101010101" +
		"0119095a1a7fffffff19095b19300019010978217461673a707361636572" +
		"7469666965642e6f72672c323032333a7073612374666d19010c48000000" +
		"000000000019095f81a30558200404040404040404040404040404040404" +
		"040404040404040404040404040404025820030303030303030303030303" +
		"0303030303030303030303030303030303030303016450526f545840786e" +
		"937a4c42667af3847399319ca95c7e7dbabdc9b50fdb8de3f6bff4ab82ff" +
		"80c42140e2a488000219e3e10663193da69c75f52b798ea10b2f7041a90e" +
		"8e5a"
	rfc9783JWK = `{"kty":"EC","crv":"P-256","alg":"ES256",` +
		`"x":"Tl4iCZ47zrRbRG0TVf0dw7VFlHtv18HInYhnmMNybo8",` +
		`"y":"gNcLhAslaqw0pi7eEEM2TwRAlfADR0uR4Bggkq-xPy4"}`
)

func TestPSA_RFC9783Example(t *testing.T) {
	raw, err := hex.DecodeString(rfc9783Token)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cose.KeyFromJWK([]byte(rfc9783JWK))
	if err != nil {
		t.Fatal(err)
	}
	v, err := cose.NewVerifierFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := eat.Verify(raw, v)
	if err != nil {
		t.Fatalf("verify RFC 9783 token: %v", err)
	}
	p, err := psa.FromEAT(c)
	if err != nil {
		t.Fatal(err)
	}
	if p.ClientID == nil || *p.ClientID != 2147483647 {
		t.Errorf("client id = %v", p.ClientID)
	}
	if p.SecurityLifecycle == nil || *p.SecurityLifecycle != 12288 || psa.LifecycleState(*p.SecurityLifecycle) != psa.LifecycleSecured {
		t.Errorf("lifecycle = %v", p.SecurityLifecycle)
	}
	if !bytes.Equal(p.ImplementationID, make([]byte, 32)) {
		t.Errorf("implementation id = %x", p.ImplementationID)
	}
	if c.Profile != psa.Profile || len(c.BootSeed) != 8 || len(c.UEID) != 33 || len(c.Nonce[0]) != 32 {
		t.Errorf("eat claims = profile %q bootseed %x ueid %x nonce %x", c.Profile, c.BootSeed, c.UEID, c.Nonce)
	}
	if len(p.SoftwareComponents) != 1 || p.SoftwareComponents[0].Type != "PRoT" ||
		!bytes.Equal(p.SoftwareComponents[0].SignerID, bytes.Repeat([]byte{4}, 32)) {
		t.Errorf("software components = %+v", p.SoftwareComponents)
	}
	// A PSA instance ID is a 33-byte RAND UEID (RFC 9783 §4.2.1); the
	// whole token passes RFC 9711 value checks.
	if err := c.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}

	// ToEAT writes the PSA claims back; the payload re-encodes to the
	// same claims.
	again, err := p.ToEAT().Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := eat.DecodeClaims(again)
	if err != nil {
		t.Fatal(err)
	}
	q, err := psa.FromEAT(d)
	if err != nil || *q.ClientID != *p.ClientID || q.SoftwareComponents[0].Type != "PRoT" {
		t.Fatalf("ToEAT round trip = %+v, %v", q, err)
	}
}

func TestPSA_Malformed(t *testing.T) {
	for _, h := range []string{
		"a119095a6178",       // client id as text
		"a119095b1a00010000", // lifecycle above uint16
		"a119095c01",         // implementation id as integer
	} {
		raw, _ := hex.DecodeString(h)
		c, err := eat.DecodeClaims(raw)
		if err != nil {
			t.Fatalf("%s: decode: %v", h, err)
		}
		if _, err := psa.FromEAT(c); err == nil || !strings.HasPrefix(err.Error(), "psa: ") {
			t.Errorf("%s: FromEAT = %v, want ErrMalformedPSA", h, err)
		}
	}
}
