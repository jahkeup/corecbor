// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
	"github.com/jahkeup/corecbor/eat"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ik(n int64) corecbor.Value {
	if n >= 0 {
		return corecbor.Uint(uint64(n))
	}
	return corecbor.NegInt(uint64(-1 - n))
}

func entry(k int64, v corecbor.Value) corecbor.MapEntry {
	return corecbor.MapEntry{Key: ik(k), Value: v}
}

func encodeValue(t *testing.T, v corecbor.Value) []byte {
	t.Helper()
	b, err := corecbor.New(corecbor.ModeCoreDeterministic).Encode(nil, v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestClaimKeys_IANA checks the claim constants against the IANA CWT
// Claims registry snapshot in testdata (fetched 2026-11-21).
func TestClaimKeys_IANA(t *testing.T) {
	raw, err := os.ReadFile("testdata/cwt-claims.xml")
	if err != nil {
		t.Fatal(err)
	}
	reg := map[string]int64{}
	rec := regexp.MustCompile(`(?s)<record[^>]*>(.*?)</record>`)
	claim := regexp.MustCompile(`<claim>(.*?)</claim>`)
	key := regexp.MustCompile(`<key>(-?\d+)</key>`)
	for _, m := range rec.FindAllStringSubmatch(string(raw), -1) {
		c, k := claim.FindStringSubmatch(m[1]), key.FindStringSubmatch(m[1])
		if c == nil || k == nil {
			continue
		}
		n, _ := strconv.ParseInt(k[1], 10, 64)
		reg[c[1]] = n
	}
	want := map[string]int64{
		"Nonce": eat.ClaimNonce, "UEID": eat.ClaimUEID, "SUEIDs": eat.ClaimSUEIDs,
		"Hardware OEM ID": eat.ClaimOEMID, "Hardware Model": eat.ClaimHWModel,
		"Hardware Version": eat.ClaimHWVersion, "Uptime": eat.ClaimUptime,
		"OEM Authorized Boot": eat.ClaimOEMBoot, "Debug Status": eat.ClaimDbgStat,
		"Location": eat.ClaimLocation, "EAT Profile": eat.ClaimProfile,
		"Submodules Section": eat.ClaimSubmods, "Boot Count": eat.ClaimBootCount,
		"Boot Seed": eat.ClaimBootSeed, "DLOAs": eat.ClaimDLOAs,
		"Software Name": eat.ClaimSWName, "Software Version": eat.ClaimSWVersion,
		"Software Manifests": eat.ClaimManifests, "Measurements": eat.ClaimMeasurements,
		"Software Measurement Results": eat.ClaimMeasRes, "Intended Use": eat.ClaimIntUse,
		"psa-software-components": eat.ClaimPSASoftwareComponents,
	}
	for name, k := range want {
		got, ok := reg[name]
		if !ok {
			t.Errorf("registry has no %q", name)
		} else if got != k {
			t.Errorf("%q: constant %d, registry %d", name, k, got)
		}
	}
}

// TestRFC9711_AppendixA_A13 decodes Appendix A.1.3 from the CWT payload bytes in
// A.2.1. Its UEID is 16 bytes, which RFC 9711 §4.2.1.1 makes too short
// for a RAND UEID (reported, unverified erratum 9193 corrects the
// example to 17 bytes); the vector follows the RFC text, so Validate
// reports it.
func TestRFC9711_AppendixA_A13(t *testing.T) {
	c, err := eat.DecodeClaims(hx(t, rfcA21Payload))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(c.Nonce[0]) != "d79b964ddd5471c1393c8888" {
		t.Errorf("nonce = %x", c.Nonce)
	}
	if hex.EncodeToString(c.UEID) != "0198f50a4ff6c05861c8860d13a638ea" {
		t.Errorf("ueid = %x", c.UEID)
	}
	if c.OEMIDPEN == nil || *c.OEMIDPEN != 64242 {
		t.Errorf("oemid PEN = %v", c.OEMIDPEN)
	}
	if c.SecureBoot == nil || !*c.SecureBoot || c.Debug != eat.DebugPermanentDisable || c.DbgStat == nil {
		t.Errorf("oemboot/dbgstat = %v %d %v", c.SecureBoot, c.Debug, c.DbgStat)
	}
	if c.HWVersion == nil || c.HWVersion.Version != "3.1" || c.HWVersion.Scheme == nil || *c.HWVersion.Scheme != 1 {
		t.Errorf("hwversion = %+v", c.HWVersion)
	}
	if err := c.Validate(); !errors.Is(err, eat.ErrInvalidUEID) {
		t.Errorf("Validate = %v, want ErrInvalidUEID (16-byte RAND UEID in the RFC text)", err)
	}
	// The RFC's payload lists hwversion (260) last, so it isn't in Core
	// Deterministic key order; Encode equals its deterministic re-encoding.
	v, err := corecbor.NewDecoder(corecbor.WithoutInternalArena()).Decode(hx(t, rfcA21Payload))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encode()
	if err != nil || !bytes.Equal(b, encodeValue(t, v)) {
		t.Errorf("re-encode = %x, %v", b, err)
	}
}

// TestRFC9711_AppendixA_A12 decodes the board/device submodules example.
func TestRFC9711_AppendixA_A12(t *testing.T) {
	in := corecbor.MakeMap(
		entry(10, corecbor.Bytes(hx(t, "e253cabedc9eec24ac4e25bcbeaf7765"))),
		entry(256, corecbor.Bytes(hx(t, "0198f50a4ff6c05861c8860d13a638ea"))),
		entry(258, corecbor.Bytes(hx(t, "894823"))),
		entry(259, corecbor.Bytes(hx(t, "549dcecc8b987c737b44e40f7c635ce8"))),
		entry(260, corecbor.MakeArray(corecbor.Text("1.3.4"), ik(1))),
		entry(270, corecbor.Text("Acme OS")),
		entry(271, corecbor.MakeArray(corecbor.Text("3.5.5"), ik(1))),
		entry(262, corecbor.Bool(true)),
		entry(263, ik(3)),
		entry(6, ik(1526542894)),
		entry(266, corecbor.MakeMap(
			corecbor.MapEntry{Key: corecbor.Text("board"), Value: corecbor.MakeMap(
				entry(258, corecbor.Bytes(hx(t, "9bef8787eba13e2c8f6e7cb4b1f4619a"))),
				entry(259, corecbor.Bytes(hx(t, "ee80f5a66c1fb9742999a8fdab930893"))),
				entry(260, corecbor.MakeArray(corecbor.Text("2.0a"), ik(2))),
			)},
			corecbor.MapEntry{Key: corecbor.Text("device"), Value: corecbor.MakeMap(
				entry(258, ik(61234)),
				entry(260, corecbor.MakeArray(corecbor.Text("4.0"), ik(1))),
			)},
		)),
	)
	data := encodeValue(t, in)
	c, err := eat.DecodeClaims(data)
	if err != nil {
		t.Fatal(err)
	}
	if c.SWName != "Acme OS" || c.SWVersion.Version != "3.5.5" || c.HWVersion.Version != "1.3.4" {
		t.Errorf("sw/hw = %q %+v %+v", c.SWName, c.SWVersion, c.HWVersion)
	}
	if !c.IssuedAt.Equal(time.Unix(1526542894, 0)) {
		t.Errorf("iat = %v", c.IssuedAt)
	}
	board, device := c.Submods["board"].Claims, c.Submods["device"].Claims
	if board == nil || len(board.OEMId) != 16 || board.HWVersion.Version != "2.0a" {
		t.Errorf("board = %+v", board)
	}
	if device == nil || device.OEMIDPEN == nil || *device.OEMIDPEN != 61234 {
		t.Errorf("device = %+v", device)
	}
	b, err := c.Encode()
	if err != nil || !bytes.Equal(b, data) {
		t.Errorf("round trip: %x, %v", b, err)
	}
}

// TestRFC9711_AppendixA_A11_A14_A15 decodes the manifest, key-attestation and
// measurement examples (private claims -80000/-80001 preserved).
func TestRFC9711_AppendixA_A11_A14_A15(t *testing.T) {
	cases := map[string]corecbor.Value{
		"A.1.1": corecbor.MakeMap(
			entry(10, corecbor.Bytes(hx(t, rfcA11Nonce))),
			entry(262, corecbor.Bool(true)),
			entry(263, ik(2)),
			entry(272, corecbor.MakeArray(corecbor.MakeArray(ik(258), corecbor.Bytes(hx(t, rfcA11CoSWID))))),
		),
		"A.1.4": corecbor.MakeMap(
			entry(10, corecbor.Bytes(hx(t, rfcA14Nonce))),
			entry(262, corecbor.Bool(true)),
			entry(272, corecbor.MakeArray(corecbor.MakeArray(ik(258), corecbor.Bytes(hx(t, rfcA14CoSWID))))),
			entry(-80000, corecbor.Text("fingerprint")),
			entry(-80001, corecbor.MakeMap(
				entry(1, ik(2)),
				entry(2, corecbor.Bytes(hx(t, rfcA14KeyKid))),
				entry(-2, corecbor.Bytes(hx(t, rfcA14KeyX))),
				entry(-3, corecbor.Bytes(hx(t, rfcA14KeyY))),
			)),
			entry(266, corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Text("HLOS"), Value: corecbor.MakeMap(
				entry(10, corecbor.Bytes(hx(t, rfcA14HLOSNonce))),
				entry(262, corecbor.Bool(true)),
				entry(272, corecbor.MakeArray(corecbor.MakeArray(ik(258), corecbor.Bytes(hx(t, rfcA14HLOSCoSWID))))),
			)})),
		),
		"A.1.5": corecbor.MakeMap(
			entry(10, corecbor.Bytes(hx(t, rfcA15Nonce))),
			entry(262, corecbor.Bool(true)),
			entry(256, corecbor.Bytes(hx(t, rfcA15UEID))),
			entry(266, corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Text("OS"), Value: corecbor.MakeMap(
				entry(262, corecbor.Bool(true)),
				entry(273, corecbor.MakeArray(corecbor.MakeArray(ik(258), corecbor.Bytes(hx(t, rfcA15CoSWID))))),
			)})),
		),
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			data := encodeValue(t, v)
			c, err := eat.DecodeClaims(data)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "A.1.1":
				if len(c.Manifests) != 1 || *c.Manifests[0].ContentFormat != 258 || c.Debug != eat.DebugDisabledSince {
					t.Errorf("manifests/dbgstat = %+v %d", c.Manifests, c.Debug)
				}
			case "A.1.4":
				if _, ok := c.PrivateClaims[cwt.IntKey(-80000)]; !ok {
					t.Error("private claim -80000 dropped")
				}
				if _, ok := c.PrivateClaims[cwt.IntKey(-80001)]; !ok {
					t.Error("private claim -80001 dropped")
				}
				if h := c.Submods["HLOS"].Claims; h == nil || len(h.Manifests) != 1 {
					t.Errorf("HLOS submod = %+v", h)
				}
			case "A.1.5":
				if m := c.Submods["OS"].Claims; m == nil || len(m.Measurements) != 1 || len(m.Measurements[0].Value) != 244 {
					t.Errorf("OS submod = %+v", m)
				}
			}
			b, err := c.Encode()
			if err != nil || !bytes.Equal(b, data) {
				t.Errorf("round trip: %x, %v", b, err)
			}
		})
	}
}

// TestDetachedBundle decodes RFC 9711 Appendix A.2.2 and checks the
// detached digest against the detached TEE claims set.
func TestDetachedBundle(t *testing.T) {
	bundle := corecbor.MakeTag(eat.TagDetachedEATBundle, corecbor.MakeArray(
		corecbor.Bytes(hx(t, rfcA22MainToken)),
		corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Text("TEE"), Value: corecbor.Bytes(hx(t, rfcA22TEE))}),
	))
	for name, data := range map[string][]byte{"tagged": encodeValue(t, bundle), "untagged": encodeValue(t, bundle.TagInner())} {
		t.Run(name, func(t *testing.T) {
			b, err := eat.DecodeDetachedBundle(data)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b.Token, hx(t, rfcA22MainToken)) || !bytes.Equal(b.Detached["TEE"], hx(t, rfcA22TEE)) {
				t.Fatal("bundle parts differ")
			}
		})
	}

	// The main token is 61(18([...])); take its payload.
	v, err := corecbor.NewDecoder(corecbor.WithoutInternalArena()).Decode(hx(t, rfcA22MainToken))
	if err != nil {
		t.Fatal(err)
	}
	for v.Kind == corecbor.KindTag {
		v = v.TagInner()
	}
	payload := v.Array()[2].BytesVal()
	main, err := eat.DecodeClaims(payload)
	if err != nil {
		t.Fatal(err)
	}
	d := main.Submods["TEE"].Detached
	if d == nil || d.Alg != -16 || len(d.Digest) != 32 {
		t.Fatalf("TEE submod = %+v", main.Submods["TEE"])
	}
	// RFC 9711 inconsistency: the hex main token carries digest
	// 8def652f…, but SHA-256 of the detached TEE claims set is the
	// ab86f765… shown in the RFC's own diagnostic notation of the same
	// token (near reported, unverified erratum 9196 on this payload). The
	// diagnostic digest is the one consistent with the detached claims.
	sum := sha256.Sum256(hx(t, rfcA22TEE))
	if hex.EncodeToString(sum[:]) != rfcA22DiagDigest {
		t.Errorf("sha256(TEE claims) = %x, want the diagnostic digest %s", sum, rfcA22DiagDigest)
	}
	if hex.EncodeToString(d.Digest) != "8def652f47000710d9f466a4c666e209dd74f927a1cea352b03143e188838abe" {
		t.Errorf("hex main token digest = %x (RFC text changed?)", d.Digest)
	}
	tee, err := eat.DecodeClaims(hx(t, rfcA22TEE))
	if err != nil || len(tee.Manifests) != 1 {
		t.Fatalf("TEE claims = %+v, %v", tee, err)
	}
	// Appraise the token as the diagnostic notation gives it.
	main.Submods["TEE"] = eat.Submod{Detached: &eat.DetachedDigest{Alg: -16, Digest: hx(t, rfcA22DiagDigest)}}

	// Appraisal: detached submodules fail closed without a checker.
	a := eat.Appraiser{SubmodPolicy: func(string, *eat.Claims) error { return nil }}
	if err := a.Appraise(main); !errors.Is(err, eat.ErrSubmodUnverified) {
		t.Errorf("no SubmodDetached: %v, want ErrSubmodUnverified", err)
	}
	var called bool
	a.SubmodDetached = func(_ context.Context, name string, got eat.DetachedDigest) error {
		called = name == "TEE" && bytes.Equal(got.Digest, sum[:])
		return nil
	}
	if err := a.Appraise(main); err != nil || !called {
		t.Errorf("SubmodDetached: err=%v called=%v", err, called)
	}
}

func TestDecode_RegistryKeys(t *testing.T) {
	data := encodeValue(t, corecbor.MakeMap(
		entry(261, ik(100)),
		entry(266, corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Text("a"), Value: corecbor.MakeMap(entry(10, corecbor.Bytes(nonce8)))})),
		entry(267, ik(5)),
		entry(268, corecbor.Bytes([]byte{1})),
	))
	c, err := eat.DecodeClaims(data)
	if err != nil {
		t.Fatal(err)
	}
	if *c.Uptime != 100 || *c.BootCount != 5 || !bytes.Equal(c.BootSeed, []byte{1}) || c.Submods["a"].Claims == nil {
		t.Errorf("decoded %+v", c)
	}
}

func TestAppraise_SubmodFailClosed(t *testing.T) {
	tok := signedToken(&eat.Claims{UEID: ueid}, edPriv)
	c := &eat.Claims{Submods: map[string]eat.Submod{"tee": {Token: tok}, "js": {JSON: []byte(`["JWT","x"]`)}}}
	var visited []string
	a := eat.Appraiser{SubmodPolicy: func(name string, _ *eat.Claims) error { visited = append(visited, name); return nil }}
	err := a.Appraise(c)
	if !errors.Is(err, eat.ErrSubmodUnverified) || !strings.Contains(err.Error(), `"js"`) {
		t.Fatalf("Appraise = %v, want ErrSubmodUnverified for js (sorted first)", err)
	}
	a.SubmodVerify = func(_ context.Context, name string, b []byte) (*eat.Claims, error) {
		if name == "js" {
			return &eat.Claims{}, nil
		}
		v, _ := cose.NewVerifier(edPub)
		return eat.Verify(b, v)
	}
	visited = nil
	if err := a.Appraise(c); err != nil || strings.Join(visited, ",") != "js,tee" {
		t.Fatalf("Appraise = %v, visited %v", err, visited)
	}
}

func TestRoundTrip_Unknown(t *testing.T) {
	data := encodeValue(t, corecbor.MakeMap(
		entry(8, corecbor.MakeMap(entry(3, corecbor.Bytes([]byte{1, 2})))),
		entry(256, corecbor.Bytes(ueid)),
		entry(299, corecbor.MakeArray(ik(1), corecbor.Bytes([]byte{9}))),
		entry(9999, corecbor.Text("x")),
		corecbor.MapEntry{Key: corecbor.Text("vendor"), Value: corecbor.MakeArray(ik(1), ik(2))},
		entry(2395, ik(12288)),
	))
	c, err := eat.DecodeClaims(data)
	if err != nil {
		t.Fatal(err)
	}
	if c.Confirmation == nil || !bytes.Equal(c.Confirmation.KeyID, []byte{1, 2}) {
		t.Errorf("cnf = %+v", c.Confirmation)
	}
	b, err := c.Encode()
	if err != nil || !bytes.Equal(b, data) {
		t.Errorf("round trip: %x, %v (want %x)", b, err, data)
	}
}

func TestDbgStat(t *testing.T) {
	zero := eat.DebugEnabled
	b, _ := (&eat.Claims{DbgStat: &zero}).Encode()
	if hex.EncodeToString(b) != "a119010700" {
		t.Errorf("DbgStat 0 = %x, want explicit 0", b)
	}
	b, _ = (&eat.Claims{Debug: eat.DebugEnabled}).Encode()
	if hex.EncodeToString(b) != "a0" {
		t.Errorf("Debug 0 = %x, want omitted as in v0.2.2", b)
	}
	four := eat.DebugDisabledFullyAndPermanently
	if err := (&eat.Claims{DbgStat: &four}).Validate(); err != nil {
		t.Errorf("dbgstat 4: %v", err)
	}
	five := eat.DebugStatus(5)
	if err := (&eat.Claims{DbgStat: &five}).Validate(); !errors.Is(err, eat.ErrUnknownDebugStatus) {
		t.Errorf("Validate dbgstat 5: %v", err)
	}
	min := eat.DebugDisabled
	a := eat.Appraiser{MinDebugStatus: &min}
	if err := a.Appraise(&eat.Claims{DbgStat: &five}); !errors.Is(err, eat.ErrUnknownDebugStatus) {
		t.Errorf("MinDebugStatus, 5: %v", err)
	}
	if err := a.Appraise(&eat.Claims{DbgStat: &zero}); !errors.Is(err, eat.ErrDebugStatus) {
		t.Errorf("MinDebugStatus, 0: %v", err)
	}
	if err := a.Appraise(&eat.Claims{}); !errors.Is(err, eat.ErrUnknownDebugStatus) {
		t.Errorf("MinDebugStatus, absent: %v", err)
	}
}

func TestNonce_Length(t *testing.T) {
	for n, ok := range map[int]bool{7: false, 8: true, 64: true, 65: false} {
		data := encodeValue(t, corecbor.MakeMap(entry(10, corecbor.Bytes(make([]byte, n)))))
		c, err := eat.DecodeClaims(data)
		if err != nil {
			t.Fatalf("%d: decode: %v (v0.2.2 acceptance kept)", n, err)
		}
		err = c.Validate()
		if ok != (err == nil) || (!ok && !errors.Is(err, eat.ErrInvalidNonce)) {
			t.Errorf("%d-byte nonce: Validate = %v", n, err)
		}
	}
}

func TestUEID_Validate(t *testing.T) {
	for name, tc := range map[string]struct {
		id []byte
		ok bool
	}{
		"rand-128":   {append([]byte{1}, make([]byte, 16)...), true},
		"rand-256":   {append([]byte{1}, make([]byte, 32)...), true},
		"rand-short": {append([]byte{1}, make([]byte, 15)...), false},
		"eui-48":     {append([]byte{2}, make([]byte, 6)...), true},
		"eui-64":     {append([]byte{2}, make([]byte, 8)...), true},
		"imei":       {append([]byte{3}, bytes.Repeat([]byte{9}, 14)...), true},
		"imei-ascii": {append([]byte{3}, bytes.Repeat([]byte{'9'}, 14)...), false},
		"type-4":     {append([]byte{4}, make([]byte, 16)...), false},
		"length-6":   {[]byte{2, 0, 0, 0, 0, 0}, false},
		"length-34":  {append([]byte{1}, make([]byte, 33)...), false},
		"type-0x00":  {make([]byte, 17), false},
		"empty-ueid": {nil, false},
	} {
		err := eat.UEID(tc.id).Validate()
		if tc.ok != (err == nil) || (!tc.ok && !errors.Is(err, eat.ErrInvalidUEID)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestProfile_OID(t *testing.T) {
	oid := hx(t, "2b0601040181a020") // 1.3.6.1.4.1.4128
	data := encodeValue(t, corecbor.MakeMap(entry(265, corecbor.Bytes(oid))))
	c, err := eat.DecodeClaims(data)
	if err != nil || !bytes.Equal(c.ProfileOID, oid) || c.Profile != "" {
		t.Fatalf("decode = %+v, %v", c, err)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("valid OID: %v", err)
	}
	if err := (&eat.Appraiser{RequireProfileOID: oid}).Appraise(c); err != nil {
		t.Errorf("RequireProfileOID: %v", err)
	}
	if err := (&eat.Appraiser{RequireProfileOID: []byte{0x2a}}).Appraise(c); !errors.Is(err, eat.ErrProfileMismatch) {
		t.Errorf("RequireProfileOID mismatch: %v", err)
	}
	bad := &eat.Claims{ProfileOID: []byte{0x06, 0x01, 0xff}}
	if err := bad.Validate(); !errors.Is(err, eat.ErrInvalidProfile) {
		t.Errorf("truncated OID: %v", err)
	}
	if err := (&eat.Claims{Profile: "not a uri"}).Validate(); !errors.Is(err, eat.ErrInvalidProfile) {
		t.Errorf("relative profile: %v", err)
	}
	if err := (&eat.Claims{Profile: "tag:psacertified.org,2023:psa#tfm"}).Validate(); err != nil {
		t.Errorf("tag URI profile: %v", err)
	}
}

func TestNumericDate_Pre1970(t *testing.T) {
	c := &eat.Claims{ClaimsSet: cwt.ClaimsSet{IssuedAt: time.Unix(-10, 0)}}
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(b) != "a10629" {
		t.Errorf("iat -10 = %x, want a10629", b)
	}
	d, err := eat.DecodeClaims(b)
	if err != nil || d.IssuedAt.Unix() != -10 {
		t.Errorf("decode = %v, %v", d.IssuedAt, err)
	}
}

func TestNewClaims_RoundTrip(t *testing.T) {
	h := 12.5
	ts := int64(1526542894)
	age := uint64(3)
	iu := eat.IntendedUseRegistration
	cf := uint64(258)
	c := &eat.Claims{
		SUEIDs:    map[string][]byte{"wifi": append([]byte{1}, make([]byte, 16)...)},
		HWModel:   []byte{1, 2},
		Location:  &eat.Location{Latitude: 47.6, Longitude: -122, HeadingNull: true, Speed: &h, Timestamp: &ts, Age: &age},
		DLOAs:     []eat.DLOA{{Registrar: "https://example.com", PlatformLabel: "p", ApplicationLabel: "a"}},
		Manifests: []eat.TypedBytes{{ContentFormat: &cf, Value: []byte{0xa0}}, {MediaType: "application/swid+cbor", Value: []byte{0xa0}}},
		MeasRes: []eat.MeasResGroup{{System: "verifier", Results: []eat.MeasResIndividual{
			{IDText: "os", IsText: true, Result: eat.MeasResultSuccess}, {ID: []byte{1}, Result: eat.MeasResultAbsent},
		}}},
		IntUse: &iu,
	}
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := eat.DecodeClaims(b)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := d.Encode()
	if err != nil || !bytes.Equal(b, b2) {
		t.Fatalf("round trip differs: %x vs %x (%v)", b, b2, err)
	}
	if !d.Location.HeadingNull || d.Location.Heading != nil || *d.Location.Speed != 12.5 || *d.IntUse != iu {
		t.Errorf("decoded %+v %+v", d.Location, d.IntUse)
	}
}

func TestCompatDraftClaimKeys(t *testing.T) {
	legacy := eat.WithLegacyDraftClaimKeys() //nolint:staticcheck // exercising the deprecated selector
	c := &eat.Claims{Uptime: ptrU64(7), SecurityLevel: eat.SecLevelRestrictedOS}
	b, err := c.Encode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(b) != "a21901050219010a07" {
		t.Errorf("legacy encode = %x, want 261: 2, 266: 7", b)
	}
	d, err := eat.DecodeClaims(b, legacy)
	if err != nil || d.SecurityLevel != eat.SecLevelRestrictedOS || *d.Uptime != 7 {
		t.Fatalf("legacy decode = %+v, %v", d, err)
	}
	// The same bytes under RFC 9711 numbering: 261 is uptime, and 266
	// (submods) must be a map.
	if _, err := eat.DecodeClaims(b); !errors.Is(err, eat.ErrMalformedEAT) {
		t.Errorf("RFC decode of legacy bytes: %v", err)
	}
	if _, err := c.Encode(); !errors.Is(err, eat.ErrClaimNumbering) {
		t.Errorf("RFC encode of SecurityLevel: %v", err)
	}
	if _, err := (&eat.Claims{BootCount: ptrU64(1)}).Encode(legacy); !errors.Is(err, eat.ErrClaimNumbering) {
		t.Errorf("legacy encode of BootCount: %v", err)
	}
	if _, err := (&eat.Claims{}).Encode(eat.CompatV02()); err != nil { //nolint:staticcheck // exercising the deprecated bundle
		t.Errorf("CompatV02: %v", err)
	}
}

// TestCompatNoMixedNumbering: under the legacy selector an RFC 9711
// submods claim at 266 is read as (draft) uptime, never as submods.
func TestCompatNoMixedNumbering(t *testing.T) {
	legacy := eat.WithLegacyDraftClaimKeys() //nolint:staticcheck // exercising the deprecated selector
	data := encodeValue(t, corecbor.MakeMap(entry(266, corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Text("a"), Value: corecbor.MakeMap()}))))
	c, err := eat.DecodeClaims(data, legacy)
	if err == nil {
		t.Fatalf("legacy decode read RFC submods: %+v", c)
	}
	if c, err := eat.DecodeClaims(encodeValue(t, corecbor.MakeMap(entry(270, corecbor.Text("os")))), legacy); err != nil || c.SWName != "" {
		t.Errorf("legacy decode of RFC-only swname: %+v, %v (want kept as a private claim)", c, err)
	} else if _, ok := c.PrivateClaims[cwt.IntKey(270)]; !ok {
		t.Error("RFC-only claim not preserved under legacy numbering")
	}
}

func TestAppraiserDefaults(t *testing.T) {
	c := &eat.Claims{Nonce: [][]byte{{1}}}
	if err := (&eat.Appraiser{}).Appraise(c); err != nil {
		t.Errorf("zero Appraiser: %v (want v0.2.2 behavior: no checks)", err)
	}
	err := eat.NewAppraiser().Appraise(c)
	if !errors.Is(err, eat.ErrInvalidNonce) {
		t.Errorf("NewAppraiser: %v, want ErrInvalidNonce", err)
	}
	c.Nonce = [][]byte{nonce8}
	if err := eat.NewAppraiser().Appraise(c); !errors.Is(err, cwt.ErrMissingExpiration) {
		t.Errorf("NewAppraiser without exp: %v, want cwt.ErrMissingExpiration", err)
	}
}

// TestDeprecationMarkers checks the 032 selectors and draft-era fields
// are marked Deprecated with the v0.32.0 floor where they are selectors.
func TestDeprecationMarkers(t *testing.T) {
	fset := token.NewFileSet()
	docs := map[string]string{}
	for _, f := range []string{"options.go", "claims.go", "appraiser.go"} {
		af, err := parser.ParseFile(fset, f, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				docs[n.Name.Name] = n.Doc.Text()
			case *ast.Field:
				for _, name := range n.Names {
					docs[name.Name] = n.Doc.Text()
				}
			}
			return true
		})
	}
	for name, floor := range map[string]bool{
		"WithLegacyDraftClaimKeys": true, "CompatV02": true,
		"SecurityLevel": false, "RequireSecurityLevel": false,
	} {
		d := docs[name]
		if !strings.Contains(d, "Deprecated:") || (floor && !strings.Contains(d, "v0.32.0")) {
			t.Errorf("%s doc lacks Deprecated marker: %q", name, d)
		}
	}
}
