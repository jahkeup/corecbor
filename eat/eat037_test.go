// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
	"github.com/jahkeup/corecbor/eat"
)

// Proposal 037 tests.

func edKeys(t *testing.T) cose.KeyResolver {
	t.Helper()
	k, err := cose.NewKeyFromPublic(edPub)
	if err != nil {
		t.Fatal(err)
	}
	return cose.KeySetResolver(cose.KeySet{k})
}

// signWith signs payload with edPriv and the given headers.
func signWith(t *testing.T, payload []byte, prot, unprot cose.Headers) []byte {
	t.Helper()
	s, err := cose.NewSigner(edPriv, cose.WithProtectedHeaders(prot))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	msg.Unprotected = unprot
	b, err := cose.MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func encodeClaimsT(t *testing.T, c *eat.Claims) []byte {
	t.Helper()
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func verifyOpts(t *testing.T) eat.VerifyOptions {
	t.Helper()
	v := cwt.NewValidator()
	v.Now = func() time.Time { return t0 }
	return eat.VerifyOptions{Keys: edKeys(t), Validator: v}
}

func typHeaders(t *testing.T, typ any) cose.Headers {
	t.Helper()
	var h cose.Headers
	if err := h.SetType(typ); err != nil {
		t.Fatal(err)
	}
	return h
}

// W8/W9: eat.VerifyToken bounds the envelope, checks typ, accepts tag
// 61 and validates the claims.
func TestVerifyToken037(t *testing.T) {
	ctx := context.Background()
	good := encodeClaimsT(t, fullClaims())

	for typ, want := range map[any]error{
		"application/eat+cwt": nil,
		`application/eat+cwt; eat_profile="tag:psacertified.org,2023:psa#tfm"`: nil,
		"application/cwt":  nil,
		uint64(263):        nil,
		uint64(61):         nil,
		"application/json": cwt.ErrUnexpectedType,
		uint64(60):         cwt.ErrUnexpectedType,
	} {
		_, err := eat.VerifyToken(ctx, signWith(t, good, typHeaders(t, typ), cose.Headers{}), verifyOpts(t))
		if (want == nil) != (err == nil) || (want != nil && !errors.Is(err, want)) {
			t.Errorf("typ %v: VerifyToken = %v, want %v", typ, err, want)
		}
	}

	signed := signWith(t, good, cose.Headers{}, cose.Headers{})
	for name, data := range map[string][]byte{
		"tag18":        signed,
		"tag61(tag18)": append([]byte{0xd8, 0x3d}, signed...),
		"untagged":     signed[1:],
	} {
		tok, err := eat.VerifyToken(ctx, data, verifyOpts(t))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if tok.Claims.Issuer != "attester" || tok.Tagged != (name == "tag61(tag18)") {
			t.Errorf("%s: token %+v", name, tok)
		}
	}
	// RFC 8392 §7.2 step 2: tag 61 must be followed by a COSE tag.
	if _, err := eat.VerifyToken(ctx, append([]byte{0xd8, 0x3d}, signed[1:]...), verifyOpts(t)); !errors.Is(err, eat.ErrMalformedEAT) {
		t.Errorf("61(untagged): %v, want ErrMalformedEAT", err)
	}
	opts := verifyOpts(t)
	opts.RequireTag = true
	if _, err := eat.VerifyToken(ctx, signed, opts); !errors.Is(err, eat.ErrMalformedEAT) {
		t.Errorf("RequireTag: %v", err)
	}

	// Claims are validated: the CWT validator, then RFC 9711 values.
	if _, err := eat.VerifyToken(ctx, signed, eat.VerifyOptions{Keys: edKeys(t)}); !errors.Is(err, cwt.ErrTokenExpired) {
		t.Errorf("real clock: %v, want cwt.ErrTokenExpired", err)
	}
	short := fullClaims()
	short.Nonce = [][]byte{{1}}
	if _, err := eat.VerifyToken(ctx, signWith(t, encodeClaimsT(t, short), cose.Headers{}, cose.Headers{}), verifyOpts(t)); !errors.Is(err, eat.ErrInvalidNonce) {
		t.Errorf("1-byte nonce: %v, want ErrInvalidNonce", err)
	}
	if _, err := eat.VerifyToken(ctx, signed, eat.VerifyOptions{}); !errors.Is(err, cwt.ErrKeyResolution) {
		t.Errorf("no keys: %v", err)
	}
	other, _ := cose.NewKeyFromPublic(edPriv2.Public())
	if _, err := eat.VerifyToken(ctx, signed, eat.VerifyOptions{Keys: cose.KeySetResolver(cose.KeySet{other})}); !errors.Is(err, cose.ErrVerification) {
		t.Errorf("wrong key: %v", err)
	}

	// Envelope limits (cose.RecommendedDecodeLimits: 1 MiB).
	var big cose.Headers
	big.Set(int64(-70000), bytes.Repeat([]byte{1}, 2<<20))
	if _, err := eat.VerifyToken(ctx, signWith(t, good, cose.Headers{}, big), verifyOpts(t)); !errors.Is(err, eat.ErrMalformedEAT) {
		t.Errorf("2 MiB header: %v, want ErrMalformedEAT", err)
	}

	// Nested: a payload that is itself a signed EAT (RFC 8392 §7.2 step 6).
	outer := signWith(t, signed, cose.Headers{}, cose.Headers{})
	tok, err := eat.VerifyToken(ctx, outer, verifyOpts(t))
	if err != nil || tok.Nested == nil || tok.Claims.Issuer != "attester" {
		t.Fatalf("nested: %+v, %v", tok, err)
	}
	opts = verifyOpts(t)
	opts.MaxNesting = -1
	if _, err := eat.VerifyToken(ctx, outer, opts); !errors.Is(err, cwt.ErrUnexpectedType) {
		t.Errorf("MaxNesting -1: %v", err)
	}

	// Decoding options pass through.
	legacy := encodeClaimsT(t, &eat.Claims{ClaimsSet: cwt.ClaimsSet{Expiration: t0.Add(time.Hour)}})
	opts = verifyOpts(t)
	opts.Options = []eat.Option{eat.WithLegacyDraftClaimKeys()} //nolint:staticcheck // pass-through check
	if _, err := eat.VerifyToken(ctx, signWith(t, legacy, cose.Headers{}, cose.Headers{}), opts); err != nil {
		t.Errorf("Options: %v", err)
	}
}

// W8: the v0.2.2 entry point accepts tag 61 (RFC 9711 §3) and bounds
// the envelope.
func TestVerify_Legacy037(t *testing.T) {
	verifier, _ := cose.NewVerifier(edPub)
	signed := signedToken(fullClaims(), edPriv)
	if _, err := eat.Verify(append([]byte{0xd8, 0x3d}, signed...), verifier); err != nil {
		t.Errorf("Verify(61(18(...))): %v", err)
	}
	var big cose.Headers
	big.Set(int64(-70000), bytes.Repeat([]byte{1}, 9<<20))
	if _, err := eat.Verify(signWith(t, encodeClaimsT(t, fullClaims()), cose.Headers{}, big), verifier); !errors.Is(err, eat.ErrMalformedEAT) {
		t.Errorf("9 MiB header: %v, want ErrMalformedEAT", err)
	}
}

// W7: no symmetric cnf key by value in a signed EAT (RFC 8747 §3.2).
func TestSymmetricCnf037(t *testing.T) {
	// RFC 8392 A.2.1 128-bit symmetric COSE_Key.
	k, err := cose.ParseKey(hx(t, "a42050231f4c4d4d3051fdc2ec0a3851d5b3830104024c53796d6d6574726963313238030a"))
	if err != nil {
		t.Fatal(err)
	}
	c := fullClaims()
	c.Confirmation = &cwt.Confirmation{Key: k}
	isErr := func(err error) bool {
		var ce *cwt.ClaimError
		return errors.Is(err, cwt.ErrSymmetricKeyNotEncrypted) && errors.As(err, &ce) && ce.Key == cwt.IntKey(cwt.ClaimCnf)
	}
	s, _ := cose.NewSigner(edPriv)
	if _, err := eat.Sign(c, s); !isErr(err) {
		t.Errorf("Sign: %v", err)
	}
	inline := &eat.Claims{Submods: map[string]eat.Submod{"tee": {Claims: c}}}
	if _, err := eat.Sign(inline, s); !isErr(err) {
		t.Errorf("Sign, inline submodule: %v", err)
	}
	data := signWith(t, encodeClaimsT(t, c), cose.Headers{}, cose.Headers{})
	verifier, _ := cose.NewVerifier(edPub)
	if _, err := eat.Verify(data, verifier); !isErr(err) {
		t.Errorf("Verify: %v", err)
	}
	if _, err := eat.VerifyToken(context.Background(), data, verifyOpts(t)); !isErr(err) {
		t.Errorf("VerifyToken: %v", err)
	}
}
