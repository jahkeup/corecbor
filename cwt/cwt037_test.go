// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/jahkeup/corecbor"
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

// W10: a NumericDate at 0001-01-01T00:00:00Z is the zero time.Time,
// which ClaimsSet uses for "absent": an exp there would not be checked.
// W30: float NumericDates decode to the nearest nanosecond, so they
// re-encode unchanged.
func TestNumericDate_Edges037(t *testing.T) {
	// exp = -62135596800 (0001-01-01T00:00:00Z).
	for _, k := range []string{"04", "05", "06"} {
		_, err := cwt.DecodeClaimsSet(h(t, "a1"+k+"3b0000000e7791f6ff"))
		if !errors.Is(err, cwt.ErrMalformedClaims) {
			t.Errorf("claim %s at year 1: %v, want ErrMalformedClaims", k, err)
		}
		if ck, ok := claimKeyOf(err); !ok || ck.Int != int64(h(t, k)[0]) {
			t.Errorf("claim %s at year 1: error %v does not name the claim", k, err)
		}
	}
	// One second later is an ordinary (long expired) time.
	cs, err := cwt.DecodeClaimsSet(h(t, "a1043b0000000e7791f6fe"))
	if err != nil || cs.Expiration.IsZero() {
		t.Fatalf("exp one second after year 1: %+v, %v", cs, err)
	}
	if err := (&cwt.Validator{}).Validate(cs); !errors.Is(err, cwt.ErrTokenExpired) {
		t.Errorf("Validate: %v, want ErrTokenExpired", err)
	}

	for _, f := range []float64{0.3, 1700000000.3, -0.7, 1.1, 0.29, 2.675, 1.005, 4.35, 0.57, 1700000000.123456, -1.005} {
		enc, err := corecbor.New(corecbor.ModeCoreDeterministic).Encode(nil, corecbor.Float64(f))
		if err != nil {
			t.Fatal(err)
		}
		cs, err := cwt.DecodeClaimsSet(append(h(t, "a104"), enc...))
		if err != nil {
			t.Fatal(err)
		}
		out, err := cs.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if want := append(h(t, "a104"), enc...); !bytes.Equal(out, want) {
			t.Errorf("exp %v: re-encoded %x, want %x", f, out, want)
		}
	}
}

// W16: RFC 8392 §7.2 step 2 — tag 61 must be followed by a COSE tag.
func TestTag61_NeedsCOSETag037(t *testing.T) {
	ctx := context.Background()
	signed := signedWith(t, validClaims(), cose.Headers{})
	untagged := append([]byte{0xd8, 0x3d}, signed[1:]...) // 61([...])
	verifier, _ := cose.NewVerifier(edPub)
	if _, err := cwt.Verify(untagged, verifier); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Errorf("Verify(61(untagged)): %v", err)
	}
	opts := cwt.VerifyOptions{Keys: edResolver(t), Validator: fixedNow(cwt.NewValidator(), t0)}
	if _, err := cwt.VerifyToken(ctx, untagged, opts); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Errorf("VerifyToken(61(untagged)): %v", err)
	}
	macked, _ := cwt.MAC(validClaims(), macKey, cose.AlgHMAC256)
	if _, err := cwt.VerifyMACToken(ctx, append([]byte{0xd8, 0x3d}, macked[1:]...), macKey, opts); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Errorf("VerifyMACToken(61(untagged)): %v", err)
	}
	if _, err := cwt.VerifyToken(ctx, append([]byte{0xd8, 0x3d}, signed...), opts); err != nil {
		t.Errorf("VerifyToken(61(18(...))): %v", err)
	}
}

// W17: RFC 8392 §7.2 step 6 — a payload that starts with a COSE tag is
// a nested CWT, with or without cty.
func TestNested_ByTag037(t *testing.T) {
	ctx := context.Background()
	inner := signedWith(t, validClaims(), cose.Headers{})
	signer, _ := cose.NewSigner(edPriv)
	msg, err := signer.Sign(inner) // no cty
	if err != nil {
		t.Fatal(err)
	}
	outer, _ := cose.MarshalSign1(msg)
	opts := cwt.VerifyOptions{Keys: edResolver(t), Validator: fixedNow(cwt.NewValidator(), t0)}
	tok, err := cwt.VerifyToken(ctx, outer, opts)
	if err != nil || tok.Nested == nil || tok.Claims.Issuer != "as" {
		t.Fatalf("nested by tag: %+v, %v", tok, err)
	}
	// Inside a MAC or an encryption, nesting is unsupported: say so.
	mac, _ := cose.ComputeMAC0(inner, macKey, cose.AlgHMAC256)
	macked, _ := cose.MarshalMac0(mac)
	if _, err := cwt.VerifyMACToken(ctx, macked, macKey, opts); !errors.Is(err, cwt.ErrUnexpectedType) {
		t.Errorf("VerifyMACToken(nested): %v, want ErrUnexpectedType", err)
	}
	enc, _ := cose.Encrypt0Seal(inner, aesKey, cose.AlgA128GCM)
	sealed, _ := cose.MarshalEncrypt0(enc)
	if _, err := cwt.OpenToken(ctx, sealed, aesKey, opts); !errors.Is(err, cwt.ErrUnexpectedType) {
		t.Errorf("OpenToken(nested): %v, want ErrUnexpectedType", err)
	}
}

// W12: RFC 8725 §3.11 explicit typing — the accepted typ values are
// selectable, and typ can be required.
func TestVerifyToken_Types037(t *testing.T) {
	ctx := context.Background()
	typed := func(typ any) []byte {
		var prot cose.Headers
		if typ != nil {
			if err := prot.SetType(typ); err != nil {
				t.Fatal(err)
			}
		}
		return signedWith(t, validClaims(), prot)
	}
	base := cwt.VerifyOptions{Keys: edResolver(t), Validator: fixedNow(cwt.NewValidator(), t0)}
	eatTypes := base
	eatTypes.Types = []any{"application/eat+cwt", uint64(263)}
	required := base
	required.RequireType = true
	for _, tc := range []struct {
		name string
		typ  any
		opts cwt.VerifyOptions
		ok   bool
	}{
		{"default, EAT typ", "application/eat+cwt", base, false},
		{"default, no typ", nil, base, true},
		{"Types, EAT typ", "application/eat+cwt", eatTypes, true},
		{"Types, EAT typ with parameter", `Application/EAT+CWT; eat_profile="x"`, eatTypes, true},
		{"Types, EAT content format", uint64(263), eatTypes, true},
		{"Types, CWT typ not listed", "application/cwt", eatTypes, false},
		{"Types, no typ", nil, eatTypes, true},
		{"RequireType, no typ", nil, required, false},
		{"RequireType, CWT typ", uint64(61), required, true},
	} {
		_, err := cwt.VerifyToken(ctx, typed(tc.typ), tc.opts)
		if tc.ok != (err == nil) || (!tc.ok && !errors.Is(err, cwt.ErrUnexpectedType)) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	bad := base
	bad.Types = []any{1.5}
	if _, err := cwt.VerifyToken(ctx, typed(nil), bad); !errors.Is(err, cwt.ErrUnexpectedType) {
		t.Errorf("Types with a float: %v", err)
	}
}

// W15: RFC 8392 §3 (and RFC 9711's Claim-Label = int / text) — claim
// keys are integers or text strings.
func TestClaimKeys_IntOrText037(t *testing.T) {
	for name, in := range map[string]string{
		"bytes":         "a1410101",
		"array":         "a1810101",
		"map":           "a1a1010101",
		"float":         "a1f93c0001",
		"bool":          "a1f501",
		"null":          "a1f601",
		"tagged text":   "a1c1616101",
		"bignum 2^64":   "a1c24901000000000000000001",
		"neg bignum":    "a1c34901000000000000000001",
		"inside cnf ok": "a108a1410101", // cnf members are not claims
	} {
		t.Run(name, func(t *testing.T) {
			_, err := cwt.DecodeClaimsSet(h(t, in))
			if name == "inside cnf ok" {
				if err != nil {
					t.Fatalf("cnf with an unknown member: %v", err)
				}
				return
			}
			if !errors.Is(err, cwt.ErrMalformedClaims) {
				t.Fatalf("DecodeClaimsSet = %v, want ErrMalformedClaims", err)
			}
			if k, ok := claimKeyOf(err); !ok || k.Raw == "" {
				t.Fatalf("error %v does not name the key as received", err)
			}
		})
	}
	// Integers beyond int64 are integers: kept as private claims.
	cs, err := cwt.DecodeClaimsSet(h(t, "a13bfffffffffffffffe6161"))
	if err != nil || len(cs.PrivateClaims) != 1 {
		t.Fatalf("negint beyond int64: %+v, %v", cs, err)
	}
	// Encode refuses to write such a key, too.
	for name, c := range map[string]*cwt.ClaimsSet{
		"Private float key": {Private: map[any]any{float64(1.5): 1}},
		"Private bool key":  {Private: map[any]any{true: 1}},
		"PrivateClaims Raw": {PrivateClaims: map[cwt.ClaimKey]corecbor.Value{{Raw: "\x41\x01"}: corecbor.Uint(1)}},
	} {
		if _, err := c.Encode(); !errors.Is(err, cwt.ErrMalformedClaims) {
			t.Errorf("Encode %s: %v, want ErrMalformedClaims", name, err)
		}
	}
}

// W21: the RFC 9200 claims have registered types; an ill-typed one is
// an error naming it, not a private claim.
func TestACEClaims_IllTyped037(t *testing.T) {
	for in, key := range map[string]int64{
		"a10901":                       cwt.ClaimScope,      // scope: 1
		"a118266178":                   cwt.ClaimACEProfile, // ace_profile: "x"
		"a11826c249010000000000000000": cwt.ClaimACEProfile, // ace_profile: bignum 2^64
		"a1182701":                     cwt.ClaimCNonce,     // cnonce: 1
		"a1182820":                     cwt.ClaimExi,        // exi: -1
		"a11828617a":                   cwt.ClaimExi,        // exi: "z"
	} {
		_, err := cwt.DecodeClaimsSet(h(t, in))
		if k, ok := claimKeyOf(err); !errors.Is(err, cwt.ErrMalformedClaims) || !ok || k != cwt.IntKey(key) {
			t.Errorf("%s: %v, want ErrMalformedClaims naming claim %d", in, err, key)
		}
	}
}

// W20: RFC 9200 §5.10.3 — exi is the lifetime from first receipt; a
// validator that can't tell when it first saw the token rejects it.
func TestValidator_Exi037(t *testing.T) {
	exi := uint64(60)
	c := validClaims()
	c.Exi = &exi
	c.CWTID = []byte{1, 2}
	now := t0
	isExi := func(err error, sentinel error) bool {
		k, ok := claimKeyOf(err)
		return errors.Is(err, sentinel) && ok && k == cwt.IntKey(cwt.ClaimExi)
	}

	v := fixedNow(cwt.NewValidator(), now)
	if err := v.Validate(c); !isExi(err, cwt.ErrExiNotTracked) {
		t.Errorf("no ExiFirstSeen: %v, want ErrExiNotTracked for exi", err)
	}
	if err := fixedNow(&cwt.Validator{}, now).Validate(c); !isExi(err, cwt.ErrExiNotTracked) {
		t.Errorf("zero Validator: %v, want ErrExiNotTracked for exi", err)
	}
	first := now.Add(-30 * time.Second)
	v.ExiFirstSeen = func(cs *cwt.ClaimsSet) (time.Time, error) {
		if !bytes.Equal(cs.CWTID, []byte{1, 2}) {
			t.Errorf("ExiFirstSeen got cti %x", cs.CWTID)
		}
		return first, nil
	}
	if err := v.Validate(c); err != nil {
		t.Errorf("within exi: %v", err)
	}
	first = now.Add(-60 * time.Second)
	if err := v.Validate(c); !isExi(err, cwt.ErrTokenExpired) {
		t.Errorf("exi elapsed: %v, want ErrTokenExpired for exi", err)
	}
	boom := errors.New("store down")
	v.ExiFirstSeen = func(*cwt.ClaimsSet) (time.Time, error) { return time.Time{}, boom }
	if err := v.Validate(c); !errors.Is(err, boom) {
		t.Errorf("hook error: %v", err)
	}
	// RFC 9200 §5.10.3: the AS MUST add a cti to a token with exi.
	v.ExiFirstSeen = func(*cwt.ClaimsSet) (time.Time, error) { return now, nil }
	c.CWTID = nil
	if err := v.Validate(c); !isExi(err, cwt.ErrMalformedClaims) {
		t.Errorf("exi without cti: %v, want ErrMalformedClaims for exi", err)
	}
	// Tokens without exi are unaffected.
	if err := fixedNow(cwt.NewValidator(), now).Validate(validClaims()); err != nil {
		t.Errorf("no exi: %v", err)
	}
}

// W22: RFC 8747 §3.1 allows at most one of COSE_Key and
// Encrypted_COSE_Key; a kid may accompany either.
func TestCnf_KeyWithKid037(t *testing.T) {
	k, _ := cose.NewKeyFromPublic(edPub)
	kb, _ := k.MarshalCBOR()
	in := append(append(h(t, "a108a201"), kb...), h(t, "034101")...) // {8: {1: key, 3: h'01'}}
	cs, err := cwt.DecodeClaimsSet(in)
	if err != nil {
		t.Fatalf("COSE_Key + kid: %v", err)
	}
	if cs.Confirmation.Key == nil || !bytes.Equal(cs.Confirmation.KeyID, []byte{1}) {
		t.Fatalf("Confirmation = %+v", cs.Confirmation)
	}
	out, err := cs.Encode()
	if err != nil || !bytes.Equal(out, in) {
		t.Fatalf("Encode = %x, %v; want %x", out, err, in)
	}
	if err := (&cwt.Validator{RequireConfirmation: true}).Validate(cs); err != nil {
		t.Errorf("RequireConfirmation: %v", err)
	}
	// With a key present, the key decides Match: another key with the
	// same kid is not the bound key.
	other, _ := cose.NewKeyFromPublic(edPriv2Pub(t))
	other.SetID([]byte{1})
	if cs.Confirmation.Match(other) {
		t.Error("Match accepted a different key carrying the same kid")
	}
	k.SetID([]byte{1})
	if !cs.Confirmation.Match(k) {
		t.Error("Match rejected the bound key")
	}

	// COSE_Key and Encrypted_COSE_Key together are still two keys.
	both := append(append(h(t, "a108a201"), kb...), h(t, "02420102")...)
	if _, err := cwt.DecodeClaimsSet(both); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Errorf("COSE_Key + Encrypted_COSE_Key: %v", err)
	}
	if _, err := (&cwt.ClaimsSet{Confirmation: &cwt.Confirmation{Key: k, Encrypted: []byte{1}}}).Encode(); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Errorf("encode COSE_Key + Encrypted: %v", err)
	}
	if err := (&cwt.Validator{RequireConfirmation: true}).Validate(&cwt.ClaimsSet{Confirmation: &cwt.Confirmation{Key: k, Encrypted: []byte{1}}}); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Errorf("RequireConfirmation, COSE_Key + Encrypted: %v", err)
	}
}

func edPriv2Pub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public().(ed25519.PublicKey)
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
