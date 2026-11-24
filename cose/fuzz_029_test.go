// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdh"
	"crypto/rsa"
	"encoding/hex"
	"math/big"
	"testing"
)

// cosewgSeedKeys returns the ECDH private keys and RSA public key of the
// cose-wg vectors, so fuzzed mutations of them reach key agreement,
// key unwrap and signature verification.
func cosewgSeedKeys(f *testing.F) (map[string]*ecdh.PrivateKey, *rsa.PublicKey) {
	f.Helper()
	ecKeys := make(map[string]*ecdh.PrivateKey)
	var rsaPub *rsa.PublicKey
	for _, v := range cosewgEncVectors {
		b, err := hex.DecodeString(v.cbor)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
		switch {
		case v.kind == "rsapss" && rsaPub == nil:
			n, _ := new(big.Int).SetString(v.x, 16)
			e, _ := new(big.Int).SetString(v.y, 16)
			rsaPub = &rsa.PublicKey{N: n, E: int(e.Int64())}
		case v.crv != "" && ecKeys[v.crv] == nil:
			d, _ := hex.DecodeString(v.d)
			k, err := cosewgCurves[v.crv].NewPrivateKey(d)
			if err != nil {
				f.Fatal(err)
			}
			ecKeys[v.crv] = k
		}
	}
	return ecKeys, rsaPub
}

// FuzzDecrypt029 (proposal 029): the decrypt and verify surfaces it
// touched return an error or nil for any input: Encrypt0Open (IV,
// Partial IV, AES-CCM), ECDH-ES recipients in every mode including the
// v0.2 encoding, PBES2 with both label sets, and RSA-PSS verification.
func FuzzDecrypt029(f *testing.F) {
	ecKeys, rsaPub := cosewgSeedKeys(f)
	var ecdhRecipients []KeyDeriver
	for _, k := range ecKeys {
		for _, alg := range []Algorithm{AlgECDH_ES_HKDF_256, AlgECDH_ES_HKDF_512, AlgECDH_ES_A128KW, AlgECDH_ES_A192KW, AlgECDH_ES_A256KW} {
			ecdhRecipients = append(ecdhRecipients, &ECDHESKey{PrivateKey: k, Alg: alg})
		}
	}
	// Counts up to 64 keep each input fast; the opt-in lets them reach
	// PBKDF2 below the 1,000 floor.
	pbes2 := &PBES2Key{Password: []byte("pw"), MaxCount: 64, InsecureAllowWeakParams: true}
	rsaV, err := NewVerifier(rsaPub, WithAllowedAlgorithms(AlgPS256, AlgPS384, AlgPS512, AlgRS256))
	if err != nil {
		f.Fatal(err)
	}
	aesKey := make([]byte, 16)
	baseIV := make([]byte, 13)
	ccm := WithEncryptAlgorithms(cosewgCCMAlgs...)

	f.Fuzz(func(t *testing.T, data []byte) {
		if m, err := UnmarshalEncrypt0(data); err == nil {
			_, _ = Encrypt0Open(m, aesKey)
			_, _ = Encrypt0Open(m, aesKey, ccm, WithPartialIV(baseIV, nil))
		}
		if m, err := UnmarshalEncrypt(data); err == nil {
			for i := range m.Recipients {
				for _, r := range ecdhRecipients {
					_, _ = DecryptMulti(m, r, i)
					_, _ = DecryptMulti(m, r, i, CompatV02Encryption())
				}
				_, _ = DecryptMulti(m, pbes2, i)
				_, _ = DecryptMulti(m, pbes2, i, WithLegacyPBES2Labels())
			}
		}
		if m, err := UnmarshalMac(data); err == nil {
			for i := range m.Recipients {
				for _, r := range ecdhRecipients {
					_ = VerifyMACMulti(m, r, i)
				}
			}
		}
		if m, err := UnmarshalSign(data); err == nil {
			_, _ = VerifyMulti(m, []*Verifier{rsaV})
		}
		if m, err := UnmarshalSign1(data); err == nil {
			_ = rsaV.Verify(m)
		}
	})
}
