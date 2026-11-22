// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

type ianaAlg struct {
	name, recommended string
}

// loadIANAAlgorithms reads testdata/iana-cose-algorithms.csv, a snapshot
// of the IANA COSE Algorithms registry.
func loadIANAAlgorithms(t *testing.T) map[Algorithm]ianaAlg {
	t.Helper()
	f, err := os.Open("testdata/iana-cose-algorithms.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[Algorithm]ianaAlg{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 3)
		if len(parts) != 3 {
			t.Fatalf("bad snapshot line %q", line)
		}
		v, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		out[Algorithm(v)] = ianaAlg{name: strings.Trim(parts[1], `"`), recommended: parts[2]}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// ianaNames maps each registered constant to its IANA name, so a typo in
// a value is caught even when the value happens to be registered.
var ianaNames = map[Algorithm]string{
	AlgEdDSA: "EdDSA", AlgES256: "ES256", AlgES384: "ES384", AlgES512: "ES512",
	AlgESP256: "ESP256", AlgESP384: "ESP384", AlgESP512: "ESP512",
	AlgEd25519: "Ed25519", AlgEd448: "Ed448",
	AlgESB256: "ESB256", AlgESB320: "ESB320", AlgESB384: "ESB384", AlgESB512: "ESB512",
	AlgMLDSA44: "ML-DSA-44", AlgMLDSA65: "ML-DSA-65", AlgMLDSA87: "ML-DSA-87",
	AlgA128GCM: "A128GCM", AlgA192GCM: "A192GCM", AlgA256GCM: "A256GCM",
	AlgAESCCM_16_64_128: "AES-CCM-16-64-128", AlgAESCCM_16_64_256: "AES-CCM-16-64-256",
	AlgAESCCM_64_64_128: "AES-CCM-64-64-128", AlgAESCCM_64_64_256: "AES-CCM-64-64-256",
	AlgAESCCM_16_128_128: "AES-CCM-16-128-128", AlgAESCCM_16_128_256: "AES-CCM-16-128-256",
	AlgAESCCM_64_128_128: "AES-CCM-64-128-128", AlgAESCCM_64_128_256: "AES-CCM-64-128-256",
	AlgChaCha20Poly1305: "ChaCha20/Poly1305",
	AlgHMAC256_64:       "HMAC 256/64", AlgHMAC256: "HMAC 256/256", AlgHMAC384: "HMAC 384/384", AlgHMAC512: "HMAC 512/512",
	AlgDirect: "direct", AlgA128KW: "A128KW", AlgA192KW: "A192KW", AlgA256KW: "A256KW",
	AlgECDH_ES_HKDF_256: "ECDH-ES + HKDF-256", AlgECDH_ES_HKDF_512: "ECDH-ES + HKDF-512",
	AlgECDH_ES_A128KW: "ECDH-ES + A128KW", AlgECDH_ES_A192KW: "ECDH-ES + A192KW", AlgECDH_ES_A256KW: "ECDH-ES + A256KW",
	AlgPS256: "PS256", AlgPS384: "PS384", AlgPS512: "PS512",
	AlgRS256: "RS256", AlgRS384: "RS384", AlgRS512: "RS512",
	AlgSHA1: "SHA-1", AlgSHA256_64: "SHA-256/64", AlgSHA256: "SHA-256",
	AlgSHA512_256: "SHA-512/256", AlgSHA384: "SHA-384", AlgSHA512: "SHA-512",
}

// TestAlgorithmRegistry checks every Algorithm constant against the IANA
// snapshot. The three corecbor-specific identifiers are checked for what
// they are: -11 collides with a registered algorithm (which is why it is
// deprecated), 35 is unregistered (HPKE code points are TBD), and the
// private PBES2 identifier is in the private-use range.
func TestAlgorithmRegistry(t *testing.T) {
	reg := loadIANAAlgorithms(t)
	for name, alg := range algorithmConstants() {
		switch alg {
		case AlgPBES2_HS256_A128KW:
			if got := reg[alg].name; got != "direct+HKDF-SHA-512" {
				t.Errorf("%s (-11): IANA name %q; the deprecation note assumes direct+HKDF-SHA-512", name, got)
			}
			continue
		case AlgHPKEBaseP256SHA256AES128GCM:
			if e, ok := reg[alg]; ok && e.name != "Unassigned" {
				t.Errorf("%s (35) is now registered as %q: revisit proposal 029 HPKE", name, e.name)
			}
			continue
		case AlgPrivatePBES2_HS256_A128KW:
			if alg >= -65536 {
				t.Errorf("%s = %d is not in the private-use range (< -65536)", name, alg)
			}
			if _, ok := reg[alg]; ok {
				t.Errorf("%s = %d is registered", name, alg)
			}
			continue
		}
		want, ok := ianaNames[alg]
		if !ok {
			t.Errorf("%s (%d): add its IANA name to ianaNames", name, alg)
			continue
		}
		got, ok := reg[alg]
		if !ok {
			t.Errorf("%s = %d is not in the IANA registry", name, alg)
			continue
		}
		if got.name != want {
			t.Errorf("%s = %d: IANA name %q, want %q", name, alg, got.name, want)
		}
		if alg.Deprecated() != (got.recommended == "Deprecated") {
			t.Errorf("%s.Deprecated() = %v, IANA recommended = %q", name, alg.Deprecated(), got.recommended)
		}
	}
}

// TestConstantsFrozen pins values that proposal 034 forbids changing.
func TestConstantsFrozen(t *testing.T) {
	for _, c := range []struct {
		alg  Algorithm
		want int64
	}{
		{AlgPBES2_HS256_A128KW, -11},
		{AlgHPKEBaseP256SHA256AES128GCM, 35},
		{AlgHPKE_Base_P256_SHA256_AES128GCM, 35},
		{AlgES256, -7},
		{AlgEdDSA, -8},
		{AlgECDH_ES_HKDF_256, -25},
	} {
		if int64(c.alg) != c.want {
			t.Errorf("%s = %d, want %d", c.alg, int64(c.alg), c.want)
		}
	}
}

func TestAlgorithmStringNoDuplicates(t *testing.T) {
	seen := map[Algorithm]string{}
	for name, alg := range algorithmConstants() {
		if prev, ok := seen[alg]; ok && alg != 35 {
			t.Errorf("%s and %s share value %d", prev, name, alg)
		}
		seen[alg] = name
	}
}
