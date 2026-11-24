// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
)

// Proposal 031 tests.

func h(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 8392 Appendix A vectors.
const (
	rfc8392A3 = `d28443a10126a104524173796d6d657472696345434453413235365850a701756
		36f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f
		61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d
		9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6f
		a29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a5
		2b9b63632c57209120e1c9e30`
	rfc8392A4 = `d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f6170
		3a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a
		2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f006
		1a5610d9f007420b7148093101ef6d789200`
	// A.2.3 ECDSA P-256 COSE_Key (with d, kid, alg -7).
	rfc8392A23Key = `a72358206c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858
		bc206c1922582060f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db
		9529971a36e7b9215820143329cce7868e416927599cf65a34f3ce2ffda55a7e
		ca69ed8919a394d42f0f2001010202524173796d6d6574726963454344534132
		35360326`
	// A.2.1 128-bit symmetric COSE_Key; A.2.2 256-bit HMAC key value.
	rfc8392A21Key = `a42050231f4c4d4d3051fdc2ec0a3851d5b3830104024c53796d6d6574726963
		313238030a`
	rfc8392A22K = `403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388`
)

// rfc8392Now is inside the A.1 claims' validity window.
var rfc8392Now = time.Unix(1444000000, 0)

func rfc8392Pub(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	x := new(big.Int).SetBytes(h(t, "143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f"))
	y := new(big.Int).SetBytes(h(t, "60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"))
	pt := append([]byte{4}, append(x.FillBytes(make([]byte, 32)), y.FillBytes(make([]byte, 32))...)...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func checkA1Claims(t *testing.T, cs *cwt.ClaimsSet) {
	t.Helper()
	if cs.Issuer != "coap://as.example.com" || cs.Subject != "erikw" || cs.Audience != "coap://light.example.com" ||
		cs.Expiration.Unix() != 1444064944 || cs.NotBefore.Unix() != 1443944944 || cs.IssuedAt.Unix() != 1443944944 ||
		!bytes.Equal(cs.CWTID, []byte{0x0b, 0x71}) {
		t.Fatalf("claims = %+v", cs)
	}
}

func TestVerify_RFC8392_A3(t *testing.T) {
	signed := h(t, rfc8392A3)
	verifier, err := cose.NewVerifier(rfc8392Pub(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"tag18":        signed,
		"tag61(tag18)": append([]byte{0xd8, 0x3d}, signed...),
		"untagged":     signed[1:],
	} {
		t.Run(name, func(t *testing.T) {
			// Verify: signature only, as in v0.2.2 (the token is long expired).
			cs, err := cwt.Verify(data, verifier)
			if err != nil {
				t.Fatal(err)
			}
			checkA1Claims(t, cs)

			key, err := cose.ParseKey(h(t, rfc8392A23Key))
			if err != nil {
				t.Fatal(err)
			}
			v := cwt.NewValidator()
			v.Now = func() time.Time { return rfc8392Now }
			v.Audience = "coap://light.example.com" // RFC 7519 §4.1.3
			tok, err := cwt.VerifyToken(context.Background(), data, cwt.VerifyOptions{
				Keys: cose.KeySetResolver(cose.KeySet{key}), Validator: v,
			})
			if err != nil {
				t.Fatal(err)
			}
			checkA1Claims(t, tok.Claims)
			if tok.Tagged != (name == "tag61(tag18)") {
				t.Fatalf("Tagged = %v", tok.Tagged)
			}

			// At the real current time the token is expired.
			_, err = cwt.VerifyToken(context.Background(), data, cwt.VerifyOptions{Keys: cose.KeySetResolver(cose.KeySet{key})})
			if !errors.Is(err, cwt.ErrTokenExpired) {
				t.Fatalf("VerifyToken now: %v, want ErrTokenExpired", err)
			}
		})
	}
	key, _ := cose.ParseKey(h(t, rfc8392A23Key))
	_, err = cwt.VerifyToken(context.Background(), signed, cwt.VerifyOptions{
		Keys: cose.KeySetResolver(cose.KeySet{key}), RequireTag: true,
	})
	if !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Fatalf("RequireTag without tag 61: %v", err)
	}
}

func TestVerifyMAC_RFC8392_A4(t *testing.T) {
	data := h(t, rfc8392A4)
	key := h(t, rfc8392A22K)
	cs, err := cwt.VerifyMAC(data, key, cose.AlgHMAC256_64)
	if err != nil {
		t.Fatal(err)
	}
	checkA1Claims(t, cs)

	v := cwt.NewValidator()
	v.Now = func() time.Time { return rfc8392Now }
	v.Audience = "coap://light.example.com"
	// HMAC 256/64 must be allowed explicitly.
	if _, err := cwt.VerifyMACToken(context.Background(), data, key, cwt.VerifyOptions{Validator: v}); !errors.Is(err, cose.ErrAlgorithmMismatch) {
		t.Fatalf("default algorithms: %v, want ErrAlgorithmMismatch", err)
	}
	tok, err := cwt.VerifyMACToken(context.Background(), data, key, cwt.VerifyOptions{
		Validator: v, AllowedAlgorithms: []cose.Algorithm{cose.AlgHMAC256_64}, RequireTag: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkA1Claims(t, tok.Claims)
}

// TestDecodeClaims_NonScalarKey: 031 made these keys decode without a
// panic; 037 W15 rejects them, since claim keys are integers or text
// (RFC 8392 §3). The error names the key as received.
func TestDecodeClaims_NonScalarKey(t *testing.T) {
	for name, in := range map[string]string{"bytes": "a1410101", "array": "a1810101", "map": "a1a1010101"} {
		t.Run(name, func(t *testing.T) {
			_, err := cwt.DecodeClaimsSet(h(t, in))
			var ce *cwt.ClaimError
			if !errors.Is(err, cwt.ErrMalformedClaims) || !errors.As(err, &ce) || ce.Key.Raw != string(h(t, in)[1:len(h(t, in))-1]) {
				t.Fatalf("DecodeClaimsSet = %v, want a *ClaimError naming the key", err)
			}
		})
	}
}

func TestDecodeClaims_KeyOverflow(t *testing.T) {
	cs, err := cwt.DecodeClaimsSet(h(t, "a13bfffffffffffffffe6161")) // {-(2^64-1): "a"}
	if err != nil {
		t.Fatal(err)
	}
	if cs.Issuer != "" || len(cs.Private) != 0 || len(cs.PrivateClaims) != 1 {
		t.Fatalf("decoded %+v", cs)
	}
	cs, err = cwt.DecodeClaimsSet(h(t, "a11bffffffffffffffff6161")) // {2^64-1: "a"}
	if err != nil || len(cs.PrivateClaims) != 1 || len(cs.Private) != 0 {
		t.Fatalf("decoded %+v, %v", cs, err)
	}
}

func TestNumericDate_Range(t *testing.T) {
	for _, in := range []string{
		"a1041bffffffffffffffff", // exp 2^64-1
		"a1053bffffffffffffffff", // nbf -2^64 (v0.2.2 failed open)
		"a104f97e00",             // NaN
		"a105f97c00",             // +Inf
		"a106f9fc00",             // -Inf
		"a104fb7e37e43c8800759c", // 1e300
	} {
		_, err := cwt.DecodeClaimsSet(h(t, in))
		if !errors.Is(err, cwt.ErrMalformedClaims) || !errors.Is(err, corecbor.ErrTimeRange) {
			t.Errorf("%s: err = %v, want ErrMalformedClaims and ErrTimeRange", in, err)
		}
		var ce *cwt.ClaimError
		if !errors.As(err, &ce) {
			t.Errorf("%s: err %v is not a *ClaimError", in, err)
		}
	}
	d, err := cwt.ParseNumericDate(corecbor.Float64(1.5))
	if err != nil || d.Unix() != 1 || d.Nanosecond() != 5e8 {
		t.Fatalf("ParseNumericDate(1.5) = %v, %v", d, err)
	}
	if got := (cwt.NumericDate{Time: time.Unix(-10, 0)}).MarshalCBORValue(); got.Kind != corecbor.KindNegInt || got.NegIntVal() != 9 {
		t.Fatalf("MarshalCBORValue(-10) = %v", corecbor.DiagnosticValue(got))
	}
}

func TestDecodeClaims_DuplicateKey(t *testing.T) {
	in := h(t, "a2041a6553f100041a00000001") // exp twice
	_, err := cwt.DecodeClaimsSet(in)
	if !errors.Is(err, corecbor.ErrDuplicateMapKey) || !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Fatalf("err = %v, want ErrDuplicateMapKey and ErrMalformedClaims", err)
	}
	cs, err := cwt.DecodeClaimsSetWith(in, cwt.DecodeOptions{AllowDuplicateClaims: true})
	if err != nil || cs.Expiration.Unix() != 1 {
		t.Fatalf("AllowDuplicateClaims: %v, %v (want last-wins exp=1)", cs, err)
	}
}

func TestErrors_WrapChain(t *testing.T) {
	// A 9 MiB byte string exceeds the 8 MiB decode budget.
	big := make([]byte, 9<<20)
	in := append(h(t, "a1"+"1901f4"+"5a00900000"), big...)
	_, err := cwt.DecodeClaimsSet(in)
	if !errors.Is(err, cbor.ErrMemoryBudgetExceeded) || !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Fatalf("err = %v, want ErrMemoryBudgetExceeded and ErrMalformedClaims", err)
	}
	_, err = cwt.DecodeClaimsSet(h(t, "a1046161")) // exp as text
	var ce *cwt.ClaimError
	if !errors.As(err, &ce) || ce.Key != cwt.IntKey(cwt.ClaimExp) || !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Fatalf("err = %v, want *ClaimError for exp", err)
	}
}

func fixedNow(v *cwt.Validator, t time.Time) *cwt.Validator {
	v.Now = func() time.Time { return t }
	return v
}

func TestValidator_Defaults(t *testing.T) {
	var nilV *cwt.Validator
	if err := nilV.Validate(&cwt.ClaimsSet{}); !errors.Is(err, cwt.ErrInvalidValidator) {
		t.Fatalf("nil Validator: %v", err)
	}
	future := &cwt.ClaimsSet{IssuedAt: t0.Add(time.Hour)}
	if err := fixedNow(&cwt.Validator{}, t0).Validate(future); err != nil {
		t.Fatalf("zero Validator, no exp + future iat: %v (v0.2.2 accepted)", err)
	}
	if err := fixedNow(cwt.NewValidator(), t0).Validate(&cwt.ClaimsSet{}); !errors.Is(err, cwt.ErrMissingExpiration) {
		t.Fatalf("NewValidator, no exp: %v", err)
	}
	future.Expiration = t0.Add(2 * time.Hour)
	if err := fixedNow(cwt.NewValidator(), t0).Validate(future); !errors.Is(err, cwt.ErrIssuedInFuture) {
		t.Fatalf("NewValidator, future iat: %v", err)
	}
	// Within the 60 s leeway.
	if err := fixedNow(cwt.NewValidator(), t0).Validate(&cwt.ClaimsSet{Expiration: t0.Add(time.Hour), IssuedAt: t0.Add(30 * time.Second)}); err != nil {
		t.Fatalf("iat within leeway: %v", err)
	}
}

func TestValidator_ExpBoundary(t *testing.T) {
	v := fixedNow(&cwt.Validator{}, t0)
	if err := v.Validate(&cwt.ClaimsSet{Expiration: t0}); !errors.Is(err, cwt.ErrTokenExpired) {
		t.Fatalf("now == exp: %v, want ErrTokenExpired", err)
	}
	if err := v.Validate(&cwt.ClaimsSet{Expiration: t0.Add(time.Nanosecond)}); err != nil {
		t.Fatalf("now == exp - 1ns: %v", err)
	}
}

func TestValidator_IssuerAgeIat(t *testing.T) {
	cs := &cwt.ClaimsSet{Issuer: "as", Expiration: t0.Add(time.Hour), IssuedAt: t0.Add(-2 * time.Hour)}
	if err := fixedNow(&cwt.Validator{Issuers: []string{"other"}}, t0).Validate(cs); !errors.Is(err, cwt.ErrIssuerMismatch) {
		t.Fatalf("issuer: %v", err)
	}
	if err := fixedNow(&cwt.Validator{Issuers: []string{"other", "as"}}, t0).Validate(cs); err != nil {
		t.Fatalf("issuer allowed: %v", err)
	}
	if err := fixedNow(&cwt.Validator{MaxAge: time.Hour}, t0).Validate(cs); !errors.Is(err, cwt.ErrTokenTooOld) {
		t.Fatalf("MaxAge: %v", err)
	}
	if err := fixedNow(&cwt.Validator{RequireIssuedAt: true}, t0).Validate(&cwt.ClaimsSet{}); !errors.Is(err, cwt.ErrMissingIssuedAt) {
		t.Fatalf("RequireIssuedAt: %v", err)
	}
}

func TestAudience_StringOrArray(t *testing.T) {
	cs, err := cwt.DecodeClaimsSet(h(t, "a103826161626262")) // aud ["a", "bb"]
	if err != nil {
		t.Fatal(err)
	}
	if cs.Audience != "" || len(cs.Audiences) != 2 || !cs.ContainsAudience("bb") || cs.ContainsAudience("c") {
		t.Fatalf("array aud: %+v", cs)
	}
	if err := fixedNow(&cwt.Validator{Audience: "bb"}, t0).Validate(cs); err != nil {
		t.Fatalf("Validator.Audience in array: %v", err)
	}
	out, err := cs.Encode()
	if err != nil || hex.EncodeToString(out) != "a103826161626262" {
		t.Fatalf("Encode = %x, %v", out, err)
	}
	cs, err = cwt.DecodeClaimsSet(h(t, "a1036161")) // aud "a"
	if err != nil || cs.Audience != "a" || len(cs.Audiences) != 1 || cs.Audiences[0] != "a" {
		t.Fatalf("text aud: %+v, %v", cs, err)
	}
	if _, err := cwt.DecodeClaimsSet(h(t, "a10380")); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Fatalf("empty aud array: %v", err)
	}
	if _, err := (&cwt.ClaimsSet{Audience: "x", Audiences: []string{"a", "b"}}).Encode(); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Fatalf("Audience not in Audiences: %v", err)
	}
}

func TestACEClaimsPrivateCompat(t *testing.T) {
	// {9: "read write", 38: 2, 39: h'01', 40: 3600}
	cs, err := cwt.DecodeClaimsSet(h(t, "a4096a72656164207772697465182602182741011828190e10"))
	if err != nil {
		t.Fatal(err)
	}
	if cs.Scope == nil || !cs.Scope.IsText || cs.Scope.Text != "read write" ||
		cs.ACEProfile == nil || *cs.ACEProfile != 2 || !bytes.Equal(cs.CNonce, []byte{1}) || cs.Exi == nil || *cs.Exi != 3600 {
		t.Fatalf("typed ACE claims: %+v", cs)
	}
	if cs.Private[int64(9)] != "read write" || cs.Private[int64(40)] != int64(3600) {
		t.Fatalf("Private (v0.2.2 view) = %v", cs.Private)
	}
	if len(cs.PrivateClaims) != 0 {
		t.Fatalf("PrivateClaims = %v, want empty", cs.PrivateClaims)
	}
	out, err := cs.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(out) != "a4096a72656164207772697465182602182741011828190e10" {
		t.Fatalf("Encode = %x", out)
	}
	// Ill-typed scope stays a private claim.
	cs, err = cwt.DecodeClaimsSet(h(t, "a10901"))
	if err != nil || cs.Scope != nil || len(cs.PrivateClaims) != 1 || cs.Private[int64(9)] != int64(1) {
		t.Fatalf("ill-typed scope: %+v, %v", cs, err)
	}
}

func TestEncode_Collisions(t *testing.T) {
	if _, err := (&cwt.ClaimsSet{Issuer: "a", Private: map[any]any{int64(1): "b"}}).Encode(); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Fatalf("conflicting iss: %v", err)
	}
	out, err := (&cwt.ClaimsSet{Issuer: "a", Private: map[any]any{int64(1): "a"}}).Encode()
	if err != nil || hex.EncodeToString(out) != "a1016161" {
		t.Fatalf("equal duplicate: %x, %v", out, err)
	}
	if _, err := (&cwt.ClaimsSet{
		Private:       map[any]any{"x": int64(1)},
		PrivateClaims: map[cwt.ClaimKey]corecbor.Value{cwt.TextKey("x"): corecbor.Uint(2)},
	}).Encode(); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Fatalf("Private vs PrivateClaims: %v", err)
	}
}

func signedWith(t *testing.T, cs *cwt.ClaimsSet, prot cose.Headers) []byte {
	t.Helper()
	signer, err := cose.NewSigner(edPriv, cose.WithProtectedHeaders(prot))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cs.Encode()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	b, err := cose.MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func edResolver(t *testing.T) cose.KeyResolver {
	t.Helper()
	k, err := cose.NewKeyFromPublic(edPub)
	if err != nil {
		t.Fatal(err)
	}
	return cose.KeySetResolver(cose.KeySet{k})
}

func validClaims() *cwt.ClaimsSet {
	return &cwt.ClaimsSet{Issuer: "as", Expiration: t0.Add(time.Hour), IssuedAt: t0}
}

func TestVerify_TypHeader(t *testing.T) {
	opts := func() cwt.VerifyOptions {
		return cwt.VerifyOptions{Keys: edResolver(t), Validator: fixedNow(cwt.NewValidator(), t0)}
	}
	verifier, _ := cose.NewVerifier(edPub)
	for typ, want := range map[any]error{"application/cwt": nil, uint64(61): nil, "application/json": cwt.ErrUnexpectedType} {
		var prot cose.Headers
		if err := prot.SetType(typ); err != nil {
			t.Fatal(err)
		}
		data := signedWith(t, validClaims(), prot)
		_, err := cwt.VerifyToken(context.Background(), data, opts())
		if ok := (want == nil && err == nil) || (want != nil && errors.Is(err, want)); !ok {
			t.Errorf("typ %v: VerifyToken = %v, want %v", typ, err, want)
		}
		if _, err := cwt.Verify(data, verifier); err != nil {
			t.Errorf("typ %v: Verify = %v (v0.2.2 ignores typ)", typ, err)
		}
	}
}

func TestVerifyTokenValidates(t *testing.T) {
	expired := &cwt.ClaimsSet{Expiration: t0.Add(-time.Hour)}
	data := signedWith(t, expired, cose.Headers{})
	verifier, _ := cose.NewVerifier(edPub)
	if _, err := cwt.Verify(data, verifier); err != nil {
		t.Fatalf("Verify (signature only): %v", err)
	}
	if _, err := cwt.VerifyToken(context.Background(), data, cwt.VerifyOptions{Keys: edResolver(t)}); !errors.Is(err, cwt.ErrTokenExpired) {
		t.Fatalf("VerifyToken expired: %v", err)
	}
	if _, err := cwt.VerifyToken(context.Background(), data, cwt.VerifyOptions{}); !errors.Is(err, cwt.ErrKeyResolution) {
		t.Fatalf("no resolver: %v", err)
	}
	boom := errors.New("directory down")
	failing := cose.KeyResolverFunc(func(context.Context, *cose.Headers, *cose.Headers) ([]*cose.Key, error) { return nil, boom })
	if _, err := cwt.VerifyToken(context.Background(), data, cwt.VerifyOptions{Keys: failing}); !errors.Is(err, cwt.ErrKeyResolution) || !errors.Is(err, boom) {
		t.Fatalf("resolver error: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	ok, _ := cose.NewKeyFromPublic(other)
	if _, err := cwt.VerifyToken(context.Background(), data, cwt.VerifyOptions{Keys: cose.KeySetResolver(cose.KeySet{ok})}); !errors.Is(err, cose.ErrVerification) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestVerifyToken_Nested(t *testing.T) {
	inner := signedWith(t, validClaims(), cose.Headers{})
	var prot cose.Headers
	if err := prot.SetContentType(uint64(61)); err != nil {
		t.Fatal(err)
	}
	signer, _ := cose.NewSigner(edPriv, cose.WithProtectedHeaders(prot))
	msg, err := signer.Sign(inner)
	if err != nil {
		t.Fatal(err)
	}
	outer, _ := cose.MarshalSign1(msg)
	opts := cwt.VerifyOptions{Keys: edResolver(t), Validator: fixedNow(cwt.NewValidator(), t0)}
	tok, err := cwt.VerifyToken(context.Background(), outer, opts)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Nested == nil || tok.Claims.Issuer != "as" {
		t.Fatalf("nested token: %+v", tok)
	}
	opts.MaxNesting = -1
	if _, err := cwt.VerifyToken(context.Background(), outer, opts); !errors.Is(err, cwt.ErrUnexpectedType) {
		t.Fatalf("MaxNesting -1: %v", err)
	}
}

func TestClaimsHeader_RoundTrip(t *testing.T) {
	var prot cose.Headers
	in := &cwt.ClaimsSet{Issuer: "issuer.example", Subject: "pkg:artifact", IssuedAt: t0}
	if err := cwt.SetClaimsHeader(&prot, in); err != nil {
		t.Fatal(err)
	}
	data := signedWith(t, &cwt.ClaimsSet{Expiration: t0.Add(time.Hour)}, prot)
	msg, err := cose.UnmarshalSign1(data)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := cwt.ClaimsFromHeaders(&msg.Protected)
	if err != nil || !ok || got.Issuer != in.Issuer || got.Subject != in.Subject || !got.IssuedAt.Equal(in.IssuedAt) {
		t.Fatalf("ClaimsFromHeaders = %+v, %v, %v", got, ok, err)
	}
	if _, ok, err := cwt.ClaimsFromHeaders(&msg.Unprotected); ok || err != nil {
		t.Fatalf("absent label 15: ok=%v err=%v", ok, err)
	}
}

func TestDecodeUCCS(t *testing.T) {
	cs, err := cwt.DecodeUCCS(h(t, "d90259a1016161")) // 601({1: "a"})
	if err != nil || cs.Issuer != "a" {
		t.Fatalf("DecodeUCCS = %+v, %v", cs, err)
	}
	if _, err := cwt.DecodeUCCS(h(t, "a1016161")); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Fatalf("untagged UCCS: %v", err)
	}
}

func TestCnf_TwoMethods(t *testing.T) {
	// cnf {1: <key>, 3: h'01'} — two methods.
	k, _ := cose.NewKeyFromPublic(edPub)
	kb, _ := k.MarshalCBOR()
	in := append(append(h(t, "a108a201"), kb...), h(t, "034101")...)
	if _, err := cwt.DecodeClaimsSet(in); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Fatalf("decode two methods: %v", err)
	}
	if _, err := (&cwt.ClaimsSet{Confirmation: &cwt.Confirmation{Key: k, KeyID: []byte{1}}}).Encode(); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Fatalf("encode two methods: %v", err)
	}
}

func TestCnf_OKP(t *testing.T) {
	// OKP without crv: {1: 1, -2: x}
	noCrv := append(h(t, "a108a101a201012158 20"), edPub...)
	if _, err := cwt.DecodeClaimsSet(noCrv); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Fatalf("OKP without crv: %v", err)
	}
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// {1: 1, -1: 4 (X25519), -2: x}
	xkey := append(h(t, "a108a101a3010120042158 20"), x.PublicKey().Bytes()...)
	cs, err := cwt.DecodeClaimsSet(xkey)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Confirmation.Key.Curve() != cose.CurveX25519 {
		t.Fatalf("X25519 key read as curve %d", cs.Confirmation.Key.Curve())
	}
}

func TestCnf_Symmetric(t *testing.T) {
	k, err := cose.ParseKey(h(t, rfc8392A21Key))
	if err != nil {
		t.Fatal(err)
	}
	out, err := (&cwt.ClaimsSet{Confirmation: &cwt.Confirmation{Key: k}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	cs, err := cwt.DecodeClaimsSet(out)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cs.Confirmation.Key.SymmetricKey()
	if err != nil || !bytes.Equal(got, h(t, "231f4c4d4d3051fdc2ec0a3851d5b383")) {
		t.Fatalf("symmetric key = %x, %v", got, err)
	}
	if !cs.Confirmation.Match(k) {
		t.Fatal("Match by value")
	}
}

func TestCnf_EncryptedKey(t *testing.T) {
	// v0.2.2 form: a byte string, kept in Encrypted.
	cs, err := cwt.DecodeClaimsSet(h(t, "a108a102420102"))
	if err != nil || !bytes.Equal(cs.Confirmation.Encrypted, []byte{1, 2}) || cs.Confirmation.EncryptedKey != nil {
		t.Fatalf("bstr form: %+v, %v", cs, err)
	}
	// RFC 8747 §3.3 form: a COSE_Encrypt0.
	msg, err := cose.Encrypt0Seal([]byte("cose-key"), aesKey, cose.AlgA128GCM, cose.WithNonce(nonce))
	if err != nil {
		t.Fatal(err)
	}
	out, err := (&cwt.ClaimsSet{Confirmation: &cwt.Confirmation{EncryptedKey: &cwt.EncryptedKey{Encrypt0: msg}}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, h(t, "a108a10283")) { // untagged 3-element array
		t.Fatalf("Encode = %x, want untagged COSE_Encrypt0", out)
	}
	cs, err = cwt.DecodeClaimsSet(out)
	if err != nil || cs.Confirmation.EncryptedKey == nil || cs.Confirmation.EncryptedKey.Encrypt0 == nil {
		t.Fatalf("decode: %+v, %v", cs, err)
	}
	pt, err := cose.Encrypt0Open(cs.Confirmation.EncryptedKey.Encrypt0, aesKey)
	if err != nil || string(pt) != "cose-key" {
		t.Fatalf("decrypt = %q, %v", pt, err)
	}
}

func TestCnf_MatchKid(t *testing.T) {
	k, _ := cose.NewKeyFromPublic(edPub)
	k.SetID([]byte("kid-1"))
	if !(&cwt.Confirmation{KeyID: []byte("kid-1")}).Match(k) || (&cwt.Confirmation{KeyID: []byte("x")}).Match(k) {
		t.Fatal("Match by kid")
	}
}

func TestSeal_IVHeader(t *testing.T) {
	data, err := cwt.Seal(validClaims(), aesKey, cose.AlgA128GCM)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := cose.UnmarshalEncrypt0(data)
	if err != nil || len(msg.Unprotected.IV()) != 12 {
		t.Fatalf("IV header: %v", err)
	}
	tok, err := cwt.OpenToken(context.Background(), data, aesKey, cwt.VerifyOptions{Validator: fixedNow(cwt.NewValidator(), t0)})
	if err != nil || tok.Claims.Issuer != "as" {
		t.Fatalf("OpenToken = %+v, %v", tok, err)
	}
	if _, err := cwt.OpenToken(context.Background(), data, aesKey, cwt.VerifyOptions{
		Validator: fixedNow(cwt.NewValidator(), t0), AllowedAlgorithms: []cose.Algorithm{cose.AlgA256GCM},
	}); !errors.Is(err, cose.ErrAlgorithmMismatch) {
		t.Fatalf("disallowed alg: %v", err)
	}
	// The deprecated Encrypt output carries no IV, so OpenToken refuses it.
	old, _ := cwt.Encrypt(validClaims(), aesKey, nonce, cose.AlgA128GCM)
	if _, err := cwt.OpenToken(context.Background(), old, aesKey, cwt.VerifyOptions{}); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Fatalf("OpenToken(Encrypt output): %v", err)
	}
}
