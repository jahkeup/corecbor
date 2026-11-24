// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
)

// Proposal 037 tests.

// claimKeyOf returns the claim a *cwt.ClaimError names, or false.
func claimKeyOf(err error) (cwt.ClaimKey, bool) {
	var ce *cwt.ClaimError
	if !errors.As(err, &ce) {
		return cwt.ClaimKey{}, false
	}
	return ce.Key, true
}

// W1: RFC 7519 §4.1.3 — a token whose aud the processor doesn't
// identify with is rejected, whether or not an audience is configured.
func TestValidator_Audience037(t *testing.T) {
	aud := func(a ...string) *cwt.ClaimsSet { return &cwt.ClaimsSet{Audiences: a} }
	for _, tc := range []struct {
		name   string
		v      cwt.Validator
		claims *cwt.ClaimsSet
		want   error
	}{
		{"no aud, none configured", cwt.Validator{}, &cwt.ClaimsSet{}, nil},
		{"aud, none configured", cwt.Validator{}, aud("rs1"), cwt.ErrAudienceMismatch},
		{"single-string aud, none configured", cwt.Validator{}, &cwt.ClaimsSet{Audience: "rs1"}, cwt.ErrAudienceMismatch},
		{"empty-string aud, none configured", cwt.Validator{}, aud(""), cwt.ErrAudienceMismatch},
		{"aud matches Audience", cwt.Validator{Audience: "rs1"}, aud("rs0", "rs1"), nil},
		{"aud matches one of Audiences", cwt.Validator{Audiences: []string{"x", "rs1"}}, aud("rs1"), nil},
		{"aud matches none of Audiences", cwt.Validator{Audiences: []string{"x", "y"}}, aud("rs1"), cwt.ErrAudienceMismatch},
		{"Audiences configured, no aud", cwt.Validator{Audiences: []string{"x"}}, &cwt.ClaimsSet{}, cwt.ErrAudienceMismatch},
		{"IgnoreAudience", cwt.Validator{IgnoreAudience: true}, aud("rs1"), nil},
		{"IgnoreAudience with Audience", cwt.Validator{IgnoreAudience: true, Audience: "rs1"}, aud("rs1"), cwt.ErrInvalidValidator},
		{"IgnoreAudience with Audiences", cwt.Validator{IgnoreAudience: true, Audiences: []string{"rs1"}}, aud("rs1"), cwt.ErrInvalidValidator},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.v.Validate(tc.claims)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate = %v, want %v", err, tc.want)
			}
			if tc.want == cwt.ErrAudienceMismatch {
				if k, ok := claimKeyOf(err); !ok || k != cwt.IntKey(cwt.ClaimAud) {
					t.Fatalf("error %v does not name the aud claim", err)
				}
			}
		})
	}

	// NewValidator applies the same rule.
	v := cwt.NewValidator()
	v.Now = func() time.Time { return t0 }
	c := validClaims()
	c.Audience = "rs1"
	if err := v.Validate(c); !errors.Is(err, cwt.ErrAudienceMismatch) {
		t.Fatalf("NewValidator, unexpected aud: %v", err)
	}
	v.Audiences = []string{"rs1"}
	if err := v.Validate(c); err != nil {
		t.Fatalf("NewValidator, expected aud: %v", err)
	}
}

// symmetricCnf returns claims whose cnf holds the RFC 8392 A.2.1
// symmetric key by value.
func symmetricCnf(t *testing.T) *cwt.ClaimsSet {
	t.Helper()
	k, err := cose.ParseKey(h(t, rfc8392A21Key))
	if err != nil {
		t.Fatal(err)
	}
	c := validClaims()
	c.Confirmation = &cwt.Confirmation{Key: k}
	return c
}

// isSymmetricCnfErr reports whether err is the W7 rejection, naming cnf.
func isSymmetricCnfErr(err error) bool {
	k, ok := claimKeyOf(err)
	return errors.Is(err, cwt.ErrSymmetricKeyNotEncrypted) && ok && k == cwt.IntKey(cwt.ClaimCnf)
}

// W7: RFC 8747 §3.2 — a symmetric COSE_Key may be carried by value
// only in an encrypted CWT.
func TestSymmetricCnf_PlaintextRejected037(t *testing.T) {
	ctx := context.Background()
	claims := symmetricCnf(t)
	signer, _ := cose.NewSigner(edPriv)
	if _, err := cwt.Sign(claims, signer); !isSymmetricCnfErr(err) {
		t.Errorf("Sign: %v, want ErrSymmetricKeyNotEncrypted for cnf", err)
	}
	if _, err := cwt.MAC(claims, macKey, cose.AlgHMAC256); !isSymmetricCnfErr(err) {
		t.Errorf("MAC: %v, want ErrSymmetricKeyNotEncrypted for cnf", err)
	}
	var hdr cose.Headers
	if err := cwt.SetClaimsHeader(&hdr, claims); !isSymmetricCnfErr(err) {
		t.Errorf("SetClaimsHeader: %v, want ErrSymmetricKeyNotEncrypted for cnf", err)
	}

	// A peer that emitted one anyway: every verifying entry point refuses it.
	signed := signedWith(t, claims, cose.Headers{})
	verifier, _ := cose.NewVerifier(edPub)
	if _, err := cwt.Verify(signed, verifier); !isSymmetricCnfErr(err) {
		t.Errorf("Verify: %v", err)
	}
	opts := cwt.VerifyOptions{Keys: edResolver(t), Validator: fixedNow(cwt.NewValidator(), t0)}
	if _, err := cwt.VerifyToken(ctx, signed, opts); !isSymmetricCnfErr(err) {
		t.Errorf("VerifyToken: %v", err)
	}
	payload, err := claims.Encode()
	if err != nil {
		t.Fatal(err)
	}
	mac, err := cose.ComputeMAC0(payload, macKey, cose.AlgHMAC256)
	if err != nil {
		t.Fatal(err)
	}
	macked, _ := cose.MarshalMac0(mac)
	if _, err := cwt.VerifyMAC(macked, macKey, cose.AlgHMAC256); !isSymmetricCnfErr(err) {
		t.Errorf("VerifyMAC: %v", err)
	}
	if _, err := cwt.VerifyMACToken(ctx, macked, macKey, opts); !isSymmetricCnfErr(err) {
		t.Errorf("VerifyMACToken: %v", err)
	}

	// Encrypted CWTs may carry it.
	sealed, err := cwt.Seal(claims, aesKey, cose.AlgA128GCM)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := cwt.OpenToken(ctx, sealed, aesKey, opts); err != nil {
		t.Errorf("OpenToken: %v", err)
	}
	enc, err := cwt.Encrypt(claims, aesKey, nonce, cose.AlgA128GCM) //nolint:staticcheck // deprecated path still encrypts
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := cwt.Decrypt(enc, aesKey, nonce, cose.AlgA128GCM); err != nil { //nolint:staticcheck // deprecated path
		t.Errorf("Decrypt: %v", err)
	}

	// An asymmetric key by value and a kid are unaffected.
	k, _ := cose.NewKeyFromPublic(edPub)
	for _, cnf := range []*cwt.Confirmation{{Key: k}, {KeyID: []byte("k")}} {
		c := validClaims()
		c.Confirmation = cnf
		if _, err := cwt.Sign(c, signer); err != nil {
			t.Errorf("Sign %+v: %v", cnf, err)
		}
	}
}

// W8: the v0.2.2 entry points bound the COSE envelope (8 MiB, the
// claims decoder's budget) instead of decoding it with no limit.
func TestLegacyPaths_Bounded037(t *testing.T) {
	var big cose.Headers
	big.Set(int64(-70000), bytes.Repeat([]byte{1}, 9<<20))
	payload, err := validClaims().Encode()
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := cose.NewSigner(edPriv)
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	sig.Unprotected = big
	signed, _ := cose.MarshalSign1(sig)
	verifier, _ := cose.NewVerifier(edPub)
	if _, err := cwt.Verify(signed, verifier); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Errorf("Verify: %v, want ErrMalformedClaims", err)
	}

	mac, err := cose.ComputeMAC0(payload, macKey, cose.AlgHMAC256)
	if err != nil {
		t.Fatal(err)
	}
	mac.Unprotected = big
	macked, _ := cose.MarshalMac0(mac)
	if _, err := cwt.VerifyMAC(macked, macKey, cose.AlgHMAC256); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Errorf("VerifyMAC: %v, want ErrMalformedClaims", err)
	}

	enc, err := cose.Encrypt0Seal(payload, aesKey, cose.AlgA128GCM, cose.WithNonce(nonce))
	if err != nil {
		t.Fatal(err)
	}
	enc.Unprotected = big
	sealed, _ := cose.MarshalEncrypt0(enc)
	if _, err := cwt.Decrypt(sealed, aesKey, nonce, cose.AlgA128GCM); !errors.Is(err, cwt.ErrMalformedClaims) { //nolint:staticcheck // deprecated path
		t.Errorf("Decrypt: %v, want ErrMalformedClaims", err)
	}

	// Anything well within the budget still verifies.
	var ok cose.Headers
	ok.Set(int64(-70000), bytes.Repeat([]byte{1}, 2<<20))
	sig.Unprotected = ok
	signed, _ = cose.MarshalSign1(sig)
	if _, err := cwt.Verify(signed, verifier); err != nil {
		t.Errorf("Verify, 2 MiB header: %v", err)
	}
}

// W2: RFC 8747 §3.1 — an empty cnf, or one holding only members this
// package doesn't understand, carries no proof-of-possession key.
func TestValidator_RequireConfirmation037(t *testing.T) {
	v := cwt.Validator{RequireConfirmation: true}
	for name, in := range map[string]string{
		"empty cnf":          "a108a0",     // {8: {}}
		"unknown member":     "a108a104a0", // {8: {4: {}}}
		"unknown int member": "a108a10a01", // {8: {10: 1}}
	} {
		t.Run(name, func(t *testing.T) {
			cs, err := cwt.DecodeClaimsSet(h(t, in))
			if err != nil {
				t.Fatalf("decode: %v (unknown members are ignored, RFC 8747 §3.1)", err)
			}
			err = v.Validate(cs)
			if !errors.Is(err, cwt.ErrMissingConfirmation) {
				t.Fatalf("Validate = %v, want ErrMissingConfirmation", err)
			}
			if k, ok := claimKeyOf(err); !ok || k != cwt.IntKey(cwt.ClaimCnf) {
				t.Fatalf("error %v does not name cnf", err)
			}
		})
	}
	for name, c := range map[string]*cwt.Confirmation{
		"empty Encrypted": {Encrypted: []byte{}},
		"empty KeyID":     {KeyID: []byte{}},
	} {
		if err := v.Validate(&cwt.ClaimsSet{Confirmation: c}); !errors.Is(err, cwt.ErrMissingConfirmation) {
			t.Errorf("%s: Validate = %v, want ErrMissingConfirmation", name, err)
		}
	}
	for name, c := range map[string]*cwt.Confirmation{
		"kid":       {KeyID: []byte{1}},
		"encrypted": {Encrypted: []byte{1}},
	} {
		if err := v.Validate(&cwt.ClaimsSet{Confirmation: c}); err != nil {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
}
