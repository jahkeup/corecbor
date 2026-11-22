// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
	"github.com/jahkeup/corecbor/eat"
	g "github.com/jahkeup/corecbor/internal/goldentest"
)

// TestGoldenV022 enforces proposal 034 for the eat module. v0.2.2 uses
// draft-era claim keys; those vectors record that behavior as-is so the
// RFC 9711 fix (proposal 032) shows up as allowlisted changes.
func TestGoldenV022(t *testing.T) {
	g.Check(t, "testdata/golden/v0.2.2/eat.json", eatGoldenCases(), goldenChanges)
}

var errPolicy = errors.New("golden: policy rejected")

var eatSentinels = []g.Sentinel{
	{Name: "ErrNonceMismatch", Err: eat.ErrNonceMismatch},
	{Name: "ErrSecurityLevel", Err: eat.ErrSecurityLevel},
	{Name: "ErrSecureBootRequired", Err: eat.ErrSecureBootRequired},
	{Name: "ErrDebugEnabled", Err: eat.ErrDebugEnabled},
	{Name: "ErrMalformedEAT", Err: eat.ErrMalformedEAT},
	{Name: "ErrProfileMismatch", Err: eat.ErrProfileMismatch},
	{Name: "cwt.ErrTokenExpired", Err: cwt.ErrTokenExpired},
	{Name: "cwt.ErrMalformedClaims", Err: cwt.ErrMalformedClaims},
	{Name: "cose.ErrVerification", Err: cose.ErrVerification},
	{Name: "cose.ErrMalformed", Err: cose.ErrMalformed},
	{Name: "errPolicy", Err: errPolicy},
}

func hexOf(b []byte, err error) string { return g.Hex(b, err, eatSentinels) }
func okOf(err error) string            { return g.OK(err, eatSentinels) }

var (
	t0      = time.Unix(1700000000, 0)
	edPriv  = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	edPub   = edPriv.Public().(ed25519.PublicKey)
	edPriv2 = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	nonce8  = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ueid    = append([]byte{0x01}, bytes.Repeat([]byte{0xaa}, 16)...)
)

// Hooks for the API calls the cases make. They default to the v0.2.2
// calls; golden_legacy_test.go swaps in WithLegacyDraftClaimKeys to show
// the legacy selector reproduces every vector. Written with v0.2.2
// signatures so tools/golden-regen.sh can compile this file there.
var (
	encodeClaims = func(c *eat.Claims) ([]byte, error) { return c.Encode() }
	decodeClaims = func(b []byte) (*eat.Claims, error) { return eat.DecodeClaims(b) }
	signClaims   = func(c *eat.Claims, s *cose.Signer) ([]byte, error) { return eat.Sign(c, s) }
	verifyClaims = func(b []byte, v *cose.Verifier) (*eat.Claims, error) { return eat.Verify(b, v) }
)

func ptrBool(b bool) *bool    { return &b }
func ptrU64(u uint64) *uint64 { return &u }

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// describe renders Claims deterministically: pointers dereferenced, maps sorted.
func describe(c *eat.Claims, err error) string {
	if err != nil {
		return g.Err(err, eatSentinels)
	}
	return "ok:" + describeClaims(c)
}

func describeClaims(c *eat.Claims) string {
	var b strings.Builder
	fmt.Fprintf(&b, "iss=%q exp=%s nonce=%x ueid=%x oemid=%x seclevel=%d", c.Issuer, fmtTime(c.Expiration), c.Nonce, c.UEID, c.OEMId, c.SecurityLevel)
	if c.SecureBoot != nil {
		fmt.Fprintf(&b, " secboot=%v", *c.SecureBoot)
	}
	fmt.Fprintf(&b, " debug=%d", c.Debug)
	if c.Uptime != nil {
		fmt.Fprintf(&b, " uptime=%d", *c.Uptime)
	}
	fmt.Fprintf(&b, " profile=%q", c.Profile)
	for _, sw := range c.SWComponents {
		fmt.Fprintf(&b, " sw{%q %x %q %x %q}", sw.Type, sw.MeasurementValue, sw.Version, sw.SignerID, sw.MeasurementDescription)
	}
	names := make([]string, 0, len(c.Submods))
	for n := range c.Submods {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s := c.Submods[n]
		if s.Claims != nil {
			fmt.Fprintf(&b, " submod[%s]{%s}", n, describeClaims(s.Claims))
		} else {
			fmt.Fprintf(&b, " submod[%s]{token %d bytes}", n, len(s.Token))
		}
	}
	return b.String()
}

func fullClaims() *eat.Claims {
	return &eat.Claims{
		ClaimsSet:    cwt.ClaimsSet{Issuer: "attester", Expiration: t0.Add(time.Hour)},
		Nonce:        [][]byte{nonce8},
		UEID:         ueid,
		OEMId:        []byte{0x00, 0x00, 0x5e},
		SecureBoot:   ptrBool(true),
		Debug:        eat.DebugDisabled,
		Profile:      "https://example.com/profile",
		SWComponents: nil,
	}
}

func signedToken(c *eat.Claims, priv ed25519.PrivateKey) []byte {
	s, err := cose.NewSigner(priv)
	if err != nil {
		panic(err)
	}
	b, err := signClaims(c, s)
	if err != nil {
		panic(err)
	}
	return b
}

func eatGoldenCases() []g.Case {
	var cases []g.Case
	add := func(id string, run func() string) { cases = append(cases, g.Case{ID: id, Run: run}) }
	encodeOf := func(c *eat.Claims) string { return hexOf(encodeClaims(c)) }

	// Encode, one vector per claim so key renumbering is attributable.
	add("eat/encode/basic", func() string { return encodeOf(fullClaims()) })
	add("eat/encode/nonce-multiple", func() string { return encodeOf(&eat.Claims{Nonce: [][]byte{nonce8, {9, 9, 9, 9, 9, 9, 9, 9}}}) })
	add("eat/encode/debug-enabled", func() string { return encodeOf(&eat.Claims{Debug: eat.DebugEnabled}) })
	add("eat/encode/debug-permanent", func() string { return encodeOf(&eat.Claims{Debug: eat.DebugPermanentDisable}) })
	add("eat/encode/secure-boot-false", func() string { return encodeOf(&eat.Claims{SecureBoot: ptrBool(false)}) })
	add("eat/encode/security-level", func() string { return encodeOf(&eat.Claims{SecurityLevel: eat.SecLevelHardware}) })
	add("eat/encode/uptime", func() string { return encodeOf(&eat.Claims{Uptime: ptrU64(100)}) })
	add("eat/encode/sw-components", func() string {
		return encodeOf(&eat.Claims{SWComponents: []eat.SWComponent{{
			Type: "BL", MeasurementValue: []byte{0xde, 0xad}, Version: "1.0", SignerID: []byte{0xbe, 0xef}, MeasurementDescription: "sha-256",
		}}})
	})
	add("eat/encode/submods-inline", func() string {
		return encodeOf(&eat.Claims{Submods: map[string]eat.Submod{
			"radio": {Claims: &eat.Claims{UEID: ueid}},
			"gps":   {Claims: &eat.Claims{Nonce: [][]byte{nonce8}}},
		}})
	})
	add("eat/encode/submods-token", func() string {
		return encodeOf(&eat.Claims{Submods: map[string]eat.Submod{"tee": {Token: signedToken(&eat.Claims{UEID: ueid}, edPriv)}}})
	})

	// Decode.
	decode := func(hexIn string) string { return describe(decodeClaims(g.MustHex(hexIn))) }
	add("eat/decode/roundtrip-basic", func() string {
		b, err := encodeClaims(fullClaims())
		if err != nil {
			return okOf(err)
		}
		return describe(decodeClaims(b))
	})
	add("eat/decode/roundtrip-submods", func() string {
		b, err := encodeClaims(&eat.Claims{Submods: map[string]eat.Submod{
			"radio": {Claims: &eat.Claims{UEID: ueid}},
			"tee":   {Token: signedToken(&eat.Claims{UEID: ueid}, edPriv)},
		}})
		if err != nil {
			return okOf(err)
		}
		return describe(decodeClaims(b))
	})
	add("eat/decode/roundtrip-uptime-seclevel", func() string {
		b, err := encodeClaims(&eat.Claims{Uptime: ptrU64(7), SecurityLevel: eat.SecLevelRestrictedOS})
		if err != nil {
			return okOf(err)
		}
		return describe(decodeClaims(b))
	})
	add("eat/decode/rfc9711-uptime-261", func() string { return decode("a119010518 64") })
	add("eat/decode/rfc9711-submods-266", func() string { return decode("a119010aa16161a10a480102030405060708") })
	add("eat/decode/rfc9711-bootcount-267", func() string { return decode("a119010b05") })
	add("eat/decode/rfc9711-bootseed-268", func() string { return decode("a119010c4101") })
	add("eat/decode/rfc9711-dbgstat-text", func() string { return decode("a11901076864697361626c6564") })
	add("eat/decode/profile-oid-bstr", func() string { return decode("a1190109430601ff") })
	add("eat/decode/nonce-short", func() string { return decode("a10a4101") })
	add("eat/decode/ueid-bad-type", func() string { return decode("a1190100420900") })
	add("eat/decode/unknown-claim", func() string { return decode("a2190200010a48" + "0102030405060708") })
	add("eat/decode/not-map", func() string { return decode("80") })

	// Sign / Verify.
	verifier, _ := cose.NewVerifier(edPub)
	add("eat/sign/ed25519", func() string { return "hex:" + fmt.Sprintf("%x", signedToken(fullClaims(), edPriv)) })
	add("eat/sign/verify", func() string { return describe(verifyClaims(signedToken(fullClaims(), edPriv), verifier)) })
	add("eat/sign/verify-wrong-key", func() string { return describe(verifyClaims(signedToken(fullClaims(), edPriv2), verifier)) })

	// Appraiser outcomes.
	appraise := func(a eat.Appraiser, c *eat.Claims) string { return okOf(a.Appraise(c)) }
	add("eat/appraise/all-pass", func() string {
		return appraise(eat.Appraiser{RequireNonce: nonce8, RequireSecureBoot: true, RequireDebugDisabled: true, RequireProfile: "https://example.com/profile"}, fullClaims())
	})
	add("eat/appraise/nonce-mismatch", func() string {
		return appraise(eat.Appraiser{RequireNonce: []byte{9}}, fullClaims())
	})
	add("eat/appraise/nonce-absent-not-required", func() string { return appraise(eat.Appraiser{}, &eat.Claims{}) })
	add("eat/appraise/security-level-low", func() string {
		return appraise(eat.Appraiser{RequireSecurityLevel: eat.SecLevelHardware}, &eat.Claims{SecurityLevel: eat.SecLevelUnrestricted})
	})
	add("eat/appraise/secure-boot-missing", func() string {
		return appraise(eat.Appraiser{RequireSecureBoot: true}, &eat.Claims{})
	})
	add("eat/appraise/debug-enabled", func() string {
		return appraise(eat.Appraiser{RequireDebugDisabled: true}, &eat.Claims{Debug: eat.DebugEnabled})
	})
	add("eat/appraise/debug-unknown-value", func() string {
		return appraise(eat.Appraiser{RequireDebugDisabled: true}, &eat.Claims{Debug: eat.DebugStatus(99)})
	})
	add("eat/appraise/profile-mismatch", func() string {
		return appraise(eat.Appraiser{RequireProfile: "other"}, fullClaims())
	})
	add("eat/appraise/cwt-expired", func() string {
		v := &cwt.Validator{Now: func() time.Time { return t0.Add(2 * time.Hour) }}
		return appraise(eat.Appraiser{CWTValidator: v}, fullClaims())
	})
	add("eat/appraise/sw-policy-reject", func() string {
		c := &eat.Claims{SWComponents: []eat.SWComponent{{Type: "BL"}}}
		return appraise(eat.Appraiser{SWComponentPolicy: func([]eat.SWComponent) error { return errPolicy }}, c)
	})
	add("eat/appraise/custom-reject", func() string {
		return appraise(eat.Appraiser{Custom: []func(*eat.Claims) error{func(*eat.Claims) error { return errPolicy }}}, &eat.Claims{})
	})
	submodClaims := func() *eat.Claims {
		return &eat.Claims{Submods: map[string]eat.Submod{"tee": {Token: signedToken(&eat.Claims{UEID: ueid}, edPriv2)}}}
	}
	seen := func(name string, c *eat.Claims) error {
		if c == nil || len(c.UEID) == 0 {
			return errPolicy
		}
		return nil
	}
	add("eat/appraise/submod-token-no-verifier", func() string {
		return appraise(eat.Appraiser{SubmodPolicy: seen}, submodClaims())
	})
	add("eat/appraise/submod-token-wrong-verifier", func() string {
		return appraise(eat.Appraiser{SubmodPolicy: seen, SubmodVerifier: verifier}, submodClaims())
	})
	add("eat/appraise/submod-inline", func() string {
		c := &eat.Claims{Submods: map[string]eat.Submod{"radio": {Claims: &eat.Claims{UEID: ueid}}}}
		return appraise(eat.Appraiser{SubmodPolicy: seen}, c)
	})
	return cases
}
