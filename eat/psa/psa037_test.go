// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package psa_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
	"github.com/jahkeup/corecbor/eat"
	"github.com/jahkeup/corecbor/eat/psa"
)

func examplePSA(t *testing.T) *psa.Claims {
	t.Helper()
	raw, _ := hex.DecodeString(rfc9783Token)
	key, err := cose.KeyFromJWK([]byte(rfc9783JWK))
	if err != nil {
		t.Fatal(err)
	}
	v, _ := cose.NewVerifierFromKey(key)
	c, err := eat.Verify(raw, v)
	if err != nil {
		t.Fatal(err)
	}
	p, err := psa.FromEAT(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// RFC 9783 §5.1.1: with a symmetric key, a PSA token is a COSE_Mac0.
// eat.VerifyMACToken verifies, bounds and validates it; psa.Validate
// then checks the profile.
func TestPSAOverMac0037(t *testing.T) {
	ctx := context.Background()
	p := examplePSA(t)
	payload, err := p.ToEAT().Encode()
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x5a}, 32)
	msg, err := cose.ComputeMAC0(payload, key, cose.AlgHMAC256)
	if err != nil {
		t.Fatal(err)
	}
	data, err := cose.MarshalMac0(msg)
	if err != nil {
		t.Fatal(err)
	}
	// PSA has no exp; freshness is the nonce, checked by the appraiser.
	v := cwt.NewValidator()
	v.RequireExpiration = false
	tok, err := eat.VerifyMACToken(ctx, data, key, eat.VerifyOptions{Validator: v})
	if err != nil {
		t.Fatalf("VerifyMACToken: %v", err)
	}
	got, err := psa.FromEAT(tok.Claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("psa.Validate over COSE_Mac0: %v", err)
	}
	a := eat.NewAppraiser()
	a.AllowNonceInsteadOfExpiration = true
	a.RequireNonce = tok.Claims.Nonce[0]
	if err := a.Appraise(tok.Claims); err != nil {
		t.Errorf("Appraise: %v", err)
	}
	if _, err := eat.VerifyMACToken(ctx, data, bytes.Repeat([]byte{1}, 32), eat.VerifyOptions{Validator: v}); !errors.Is(err, cose.ErrMACVerification) {
		t.Errorf("wrong key: %v, want cose.ErrMACVerification", err)
	}
}

// W26: RFC 9783 §4 and §5.2 — the PSA profile's mandatory claims and
// value rules.
func TestValidate037(t *testing.T) {
	if err := examplePSA(t).Validate(); err != nil {
		t.Fatalf("RFC 9783 Appendix A.1 token: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*psa.Claims)
		key  int64
	}{
		{"no nonce", func(p *psa.Claims) { p.Nonce = nil }, eat.ClaimNonce},
		{"two nonces", func(p *psa.Claims) { p.Nonce = append(p.Nonce, p.Nonce[0]) }, eat.ClaimNonce},
		{"nonce 16 bytes", func(p *psa.Claims) { p.Nonce = [][]byte{make([]byte, 16)} }, eat.ClaimNonce},
		{"no client id", func(p *psa.Claims) { p.ClientID = nil }, psa.ClaimClientID},
		{"no instance id", func(p *psa.Claims) { p.UEID = nil }, eat.ClaimUEID},
		{"instance id not RAND", func(p *psa.Claims) { p.UEID = append([]byte{2}, make([]byte, 32)...) }, eat.ClaimUEID},
		{"no implementation id", func(p *psa.Claims) { p.ImplementationID = nil }, psa.ClaimImplementationID},
		{"implementation id 31 bytes", func(p *psa.Claims) { p.ImplementationID = make([]byte, 31) }, psa.ClaimImplementationID},
		{"no lifecycle", func(p *psa.Claims) { p.SecurityLifecycle = nil }, psa.ClaimSecurityLifecycle},
		{"no profile", func(p *psa.Claims) { p.Profile = "" }, eat.ClaimProfile},
		{"other profile", func(p *psa.Claims) { p.Profile = "http://arm.com/psa/2.0.0" }, eat.ClaimProfile},
		{"boot seed 4 bytes", func(p *psa.Claims) { p.BootSeed = make([]byte, 4) }, eat.ClaimBootSeed},
		{"certification reference", func(p *psa.Claims) { p.CertificationRef = "123" }, psa.ClaimCertificationReference},
		{"sw component without signer id", func(p *psa.Claims) { p.SoftwareComponents[0].SignerID = nil }, psa.ClaimSoftwareComponents},
		{"sw component short measurement", func(p *psa.Claims) { p.SoftwareComponents[0].MeasurementValue = make([]byte, 20) }, psa.ClaimSoftwareComponents},
	} {
		p := examplePSA(t)
		tc.edit(p)
		err := p.Validate()
		var ce *cwt.ClaimError
		if !errors.Is(err, psa.ErrInvalidPSA) || !errors.As(err, &ce) || ce.Key != cwt.IntKey(tc.key) {
			t.Errorf("%s: %v, want ErrInvalidPSA naming claim %d", tc.name, err, tc.key)
		}
	}
	p := examplePSA(t)
	p.CertificationRef = "1234567890123-12345"
	p.Profile = psa.Profile
	if err := p.Validate(); err != nil {
		t.Errorf("valid certification reference: %v", err)
	}
}
