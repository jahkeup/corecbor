// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt_test

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
	g "github.com/jahkeup/corecbor/internal/goldentest"
)

// TestGoldenV022 enforces proposal 034 for the cwt module.
func TestGoldenV022(t *testing.T) {
	g.Check(t, "testdata/golden/v0.2.2/cwt.json", cwtGoldenCases(), goldenChanges)
}

var cwtSentinels = []g.Sentinel{
	{Name: "ErrTokenExpired", Err: cwt.ErrTokenExpired},
	{Name: "ErrTokenNotYetValid", Err: cwt.ErrTokenNotYetValid},
	{Name: "ErrAudienceMismatch", Err: cwt.ErrAudienceMismatch},
	{Name: "ErrMissingExpiration", Err: cwt.ErrMissingExpiration},
	{Name: "ErrMissingConfirmation", Err: cwt.ErrMissingConfirmation},
	{Name: "ErrMalformedClaims", Err: cwt.ErrMalformedClaims},
	{Name: "cose.ErrVerification", Err: cose.ErrVerification},
	{Name: "cose.ErrMalformed", Err: cose.ErrMalformed},
	{Name: "cose.ErrDecryption", Err: cose.ErrDecryption},
	{Name: "cose.ErrMACVerification", Err: cose.ErrMACVerification},
	{Name: "cose.ErrInvalidKey", Err: cose.ErrInvalidKey},
	{Name: "cose.ErrUnsupportedAlgorithm", Err: cose.ErrUnsupportedAlgorithm},
}

func hexOf(b []byte, err error) string { return g.Hex(b, err, cwtSentinels) }
func okOf(err error) string            { return g.OK(err, cwtSentinels) }

var (
	t0     = time.Unix(1700000000, 0)
	edPriv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	edPub  = edPriv.Public().(ed25519.PublicKey)
	macKey = bytes.Repeat([]byte{0x0b}, 32)
	aesKey = bytes.Repeat([]byte{0x0d}, 16)
	nonce  = bytes.Repeat([]byte{0x0f}, 12)
)

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// describe renders a ClaimsSet deterministically (no pointers, UTC times).
func describe(cs *cwt.ClaimsSet, err error) string {
	if err != nil {
		return g.Err(err, cwtSentinels)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ok:iss=%q sub=%q aud=%q exp=%s nbf=%s iat=%s cti=%x",
		cs.Issuer, cs.Subject, cs.Audience, fmtTime(cs.Expiration), fmtTime(cs.NotBefore), fmtTime(cs.IssuedAt), cs.CWTID)
	if c := cs.Confirmation; c != nil {
		fmt.Fprintf(&b, " cnf{kid=%x enc=%x", c.KeyID, c.Encrypted)
		if c.Key != nil {
			pub, perr := c.Key.PublicKey()
			eq := false
			if p, ok := pub.(ed25519.PublicKey); ok && perr == nil {
				eq = p.Equal(edPub)
			}
			fmt.Fprintf(&b, " key{kty=%d crv=%d ed25519-equal=%v}", c.Key.KeyType(), c.Key.Curve(), eq)
		}
		b.WriteString("}")
	}
	if cs.Private != nil {
		fmt.Fprintf(&b, " private=%v", cs.Private)
	}
	return b.String()
}

func baseClaims() *cwt.ClaimsSet {
	return &cwt.ClaimsSet{
		Issuer:     "coap://as.example.com",
		Subject:    "erikw",
		Audience:   "coap://light.example.com",
		Expiration: t0.Add(time.Hour),
		NotBefore:  t0,
		IssuedAt:   t0,
		CWTID:      []byte{0x0b, 0x71},
	}
}

func cwtGoldenCases() []g.Case {
	var cases []g.Case
	add := func(id string, run func() string) { cases = append(cases, g.Case{ID: id, Run: run}) }
	encodeOf := func(cs *cwt.ClaimsSet) string { return hexOf(cs.Encode()) }

	add("cwt/encode/rfc8392-like", func() string { return encodeOf(baseClaims()) })
	add("cwt/encode/empty", func() string { return encodeOf(&cwt.ClaimsSet{}) })
	add("cwt/encode/subsecond-exp", func() string {
		return encodeOf(&cwt.ClaimsSet{Expiration: t0.Add(500 * time.Millisecond)})
	})
	add("cwt/encode/pre-1970-iat", func() string { return encodeOf(&cwt.ClaimsSet{IssuedAt: time.Unix(-10, 0)}) })
	add("cwt/encode/private-claims", func() string {
		return encodeOf(&cwt.ClaimsSet{Private: map[any]any{int64(-70000): "neg", "name": int64(3), int64(500): []byte{1}}})
	})
	add("cwt/encode/private-unsupported-type", func() string {
		return encodeOf(&cwt.ClaimsSet{Private: map[any]any{"x": struct{}{}}})
	})
	add("cwt/encode/private-shadows-iss", func() string {
		return encodeOf(&cwt.ClaimsSet{Issuer: "a", Private: map[any]any{int64(1): "b"}})
	})
	add("cwt/encode/cnf-kid", func() string {
		return encodeOf(&cwt.ClaimsSet{Confirmation: &cwt.Confirmation{KeyID: []byte("kid")}})
	})
	add("cwt/encode/cnf-key", func() string {
		k, err := cose.NewKeyFromPublic(edPub)
		if err != nil {
			return okOf(err)
		}
		return encodeOf(&cwt.ClaimsSet{Confirmation: &cwt.Confirmation{Key: k}})
	})
	add("cwt/encode/cnf-encrypted", func() string {
		return encodeOf(&cwt.ClaimsSet{Confirmation: &cwt.Confirmation{Encrypted: []byte{1, 2}}})
	})

	decode := func(hexIn string) string { return describe(cwt.DecodeClaimsSet(g.MustHex(hexIn))) }
	add("cwt/decode/roundtrip", func() string {
		b, err := baseClaims().Encode()
		if err != nil {
			return okOf(err)
		}
		return describe(cwt.DecodeClaimsSet(b))
	})
	add("cwt/decode/roundtrip-cnf-key", func() string {
		k, _ := cose.NewKeyFromPublic(edPub)
		b, err := (&cwt.ClaimsSet{Confirmation: &cwt.Confirmation{Key: k}}).Encode()
		if err != nil {
			return okOf(err)
		}
		return describe(cwt.DecodeClaimsSet(b))
	})
	add("cwt/decode/not-map", func() string { return decode("80") })
	add("cwt/decode/garbage", func() string { return decode("ff") })
	add("cwt/decode/iss-not-text", func() string { return decode("a10101") })
	add("cwt/decode/aud-array", func() string { return decode("a103816161") })
	add("cwt/decode/exp-float", func() string { return decode("a104fb41d954fc40200000") })
	add("cwt/decode/exp-negative", func() string { return decode("a10429") })
	add("cwt/decode/exp-uint-max", func() string { return decode("a1041bffffffffffffffff") })
	add("cwt/decode/exp-nan", func() string { return decode("a104f97e00") })
	add("cwt/decode/exp-text", func() string { return decode("a1046161") })
	add("cwt/decode/duplicate-exp", func() string { return decode("a2041a6553f100041a00000001") })
	add("cwt/decode/private-text-key", func() string { return decode("a1646e616d6503") })
	add("cwt/decode/private-int-key", func() string { return decode("a11901f46161") })
	add("cwt/decode/private-bytes-key", func() string { return decode("a1410101") })
	add("cwt/decode/private-array-key", func() string { return decode("a1810101") })
	add("cwt/decode/negint-key-aliases-iss", func() string { return decode("a13bfffffffffffffffe6161") })
	add("cwt/decode/cnf-kid", func() string { return decode("a108a10343010203") })
	add("cwt/decode/cnf-unknown-member", func() string { return decode("a108a10a01") })
	add("cwt/decode/cnf-not-map", func() string { return decode("a10801") })

	// Validator outcomes at a fixed Now.
	now := func() time.Time { return t0 }
	validate := func(v cwt.Validator, cs *cwt.ClaimsSet) string {
		v.Now = now
		return okOf(v.Validate(cs))
	}
	add("cwt/validate/zero-validator-no-exp", func() string { return validate(cwt.Validator{}, &cwt.ClaimsSet{}) })
	add("cwt/validate/valid", func() string { return validate(cwt.Validator{Audience: "coap://light.example.com"}, baseClaims()) })
	add("cwt/validate/expired", func() string {
		return validate(cwt.Validator{}, &cwt.ClaimsSet{Expiration: t0.Add(-time.Second)})
	})
	add("cwt/validate/exp-equals-now", func() string {
		return validate(cwt.Validator{}, &cwt.ClaimsSet{Expiration: t0})
	})
	add("cwt/validate/expired-within-leeway", func() string {
		return validate(cwt.Validator{Leeway: time.Minute}, &cwt.ClaimsSet{Expiration: t0.Add(-time.Second)})
	})
	add("cwt/validate/nbf-future", func() string {
		return validate(cwt.Validator{}, &cwt.ClaimsSet{NotBefore: t0.Add(time.Second)})
	})
	add("cwt/validate/nbf-equals-now", func() string {
		return validate(cwt.Validator{}, &cwt.ClaimsSet{NotBefore: t0})
	})
	add("cwt/validate/iat-future", func() string {
		return validate(cwt.Validator{}, &cwt.ClaimsSet{IssuedAt: t0.Add(time.Hour)})
	})
	add("cwt/validate/audience-mismatch", func() string {
		return validate(cwt.Validator{Audience: "other"}, baseClaims())
	})
	add("cwt/validate/audience-unset-token-has-aud", func() string { return validate(cwt.Validator{}, baseClaims()) })
	add("cwt/validate/require-exp-missing", func() string {
		return validate(cwt.Validator{RequireExpiration: true}, &cwt.ClaimsSet{})
	})
	add("cwt/validate/require-cnf-missing", func() string {
		return validate(cwt.Validator{RequireConfirmation: true}, &cwt.ClaimsSet{})
	})
	add("cwt/validate/require-cnf-present", func() string {
		return validate(cwt.Validator{RequireConfirmation: true}, &cwt.ClaimsSet{Confirmation: &cwt.Confirmation{KeyID: []byte{1}}})
	})
	add("cwt/validate/negative-leeway", func() string {
		return validate(cwt.Validator{Leeway: -time.Minute}, &cwt.ClaimsSet{Expiration: t0.Add(time.Second)})
	})

	// Signed / MACed / encrypted tokens.
	signer, _ := cose.NewSigner(edPriv)
	verifier, _ := cose.NewVerifier(edPub)
	add("cwt/sign/ed25519", func() string { return hexOf(cwt.Sign(baseClaims(), signer)) })
	add("cwt/sign/verify", func() string {
		b, err := cwt.Sign(baseClaims(), signer)
		if err != nil {
			return okOf(err)
		}
		return describe(cwt.Verify(b, verifier))
	})
	add("cwt/sign/verify-tag61-wrapped", func() string {
		b, err := cwt.Sign(baseClaims(), signer)
		if err != nil {
			return okOf(err)
		}
		return describe(cwt.Verify(append([]byte{0xd8, 0x3d}, b...), verifier))
	})
	add("cwt/sign/verify-untagged", func() string {
		b, err := cwt.Sign(baseClaims(), signer)
		if err != nil {
			return okOf(err)
		}
		return describe(cwt.Verify(b[1:], verifier))
	})
	add("cwt/mac/hmac256", func() string { return hexOf(cwt.MAC(baseClaims(), macKey, cose.AlgHMAC256)) })
	add("cwt/mac/verify", func() string {
		b, err := cwt.MAC(baseClaims(), macKey, cose.AlgHMAC256)
		if err != nil {
			return okOf(err)
		}
		return describe(cwt.VerifyMAC(b, macKey, cose.AlgHMAC256))
	})
	add("cwt/mac/verify-wrong-key", func() string {
		b, err := cwt.MAC(baseClaims(), macKey, cose.AlgHMAC256)
		if err != nil {
			return okOf(err)
		}
		return describe(cwt.VerifyMAC(b, bytes.Repeat([]byte{1}, 32), cose.AlgHMAC256))
	})
	add("cwt/encrypt/a128gcm", func() string { return hexOf(cwt.Encrypt(baseClaims(), aesKey, nonce, cose.AlgA128GCM)) })
	add("cwt/encrypt/decrypt", func() string {
		b, err := cwt.Encrypt(baseClaims(), aesKey, nonce, cose.AlgA128GCM)
		if err != nil {
			return okOf(err)
		}
		return describe(cwt.Decrypt(b, aesKey, nonce, cose.AlgA128GCM))
	})
	add("cwt/encrypt/decrypt-wrong-nonce", func() string {
		b, err := cwt.Encrypt(baseClaims(), aesKey, nonce, cose.AlgA128GCM)
		if err != nil {
			return okOf(err)
		}
		return describe(cwt.Decrypt(b, aesKey, bytes.Repeat([]byte{1}, 12), cose.AlgA128GCM))
	})
	return cases
}
