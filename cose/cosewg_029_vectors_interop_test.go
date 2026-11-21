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

// cosewgCCMAlgs are the AES-CCM content algorithms of RFC 9053 §4.2.
var cosewgCCMAlgs = []Algorithm{
	AlgAESCCM_16_64_128, AlgAESCCM_16_64_256, AlgAESCCM_64_64_128, AlgAESCCM_64_64_256,
	AlgAESCCM_16_128_128, AlgAESCCM_16_128_256, AlgAESCCM_64_128_128, AlgAESCCM_64_128_256,
}

var cosewgECDHAlgs = map[string]Algorithm{
	"ECDH-ES":        AlgECDH_ES_HKDF_256,
	"ECDH-ES-512":    AlgECDH_ES_HKDF_512,
	"ECDH-ES-A128KW": AlgECDH_ES_A128KW,
	"ECDH-ES-A192KW": AlgECDH_ES_A192KW,
	"ECDH-ES-A256KW": AlgECDH_ES_A256KW,
}

var cosewgCurves = map[string]ecdh.Curve{
	"P-256": ecdh.P256(), "P-384": ecdh.P384(), "P-521": ecdh.P521(), "X25519": ecdh.X25519(),
}

// TestCOSEWGVectors029 checks the cose-wg/Examples ECDH-ES (direct
// and key wrap) and AES-KW COSE_Encrypt and COSE_Mac messages, the
// AES-CCM COSE_Encrypt0 messages and the RSA-PSS COSE_Sign messages
// (proposal 029).
func TestCOSEWGVectors029(t *testing.T) {
	for _, v := range cosewgEncVectors {
		t.Run(v.name, func(t *testing.T) {
			wire, err := hex.DecodeString(v.cbor)
			if err != nil {
				t.Fatal(err)
			}
			d, err := hex.DecodeString(v.d)
			if err != nil {
				t.Fatal(err)
			}
			var got []byte
			switch v.kind {
			case "ecdh", "ecdhmac":
				alg, ok := cosewgECDHAlgs[v.alg]
				if !ok {
					t.Fatalf("unmapped alg %q", v.alg)
				}
				priv, err := cosewgCurves[v.crv].NewPrivateKey(d)
				if err != nil {
					t.Fatal(err)
				}
				key := &ECDHESKey{PrivateKey: priv, Alg: alg}
				if v.kind == "ecdhmac" {
					msg, err := UnmarshalMac(wire)
					if err != nil {
						t.Fatal(err)
					}
					err = VerifyMACMulti(msg, key, 0)
					if v.fail != (err != nil) {
						t.Fatalf("VerifyMACMulti = %v, fail %v", err, v.fail)
					}
					return
				}
				msg, err := UnmarshalEncrypt(wire)
				if err != nil {
					t.Fatal(err)
				}
				got, err = DecryptMulti(msg, key, 0)
				if v.fail {
					if err == nil {
						t.Fatal("fail vector decrypted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
			case "ccm0":
				msg, err := UnmarshalEncrypt0(wire)
				if err != nil {
					t.Fatal(err)
				}
				got, err = Encrypt0Open(msg, d, WithEncryptAlgorithms(cosewgCCMAlgs...))
				if v.fail {
					if err == nil {
						t.Fatal("fail vector decrypted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
			case "aeskw":
				msg, err := UnmarshalEncrypt(wire)
				if err != nil {
					t.Fatal(err)
				}
				got, err = DecryptMulti(msg, &AESKWKey{Key: d}, 0)
				if v.fail != (err != nil) {
					t.Fatalf("DecryptMulti = %v, fail %v", err, v.fail)
				}
				if v.fail {
					return
				}
			case "aeskwmac":
				msg, err := UnmarshalMac(wire)
				if err != nil {
					t.Fatal(err)
				}
				if err := VerifyMACMulti(msg, &AESKWKey{Key: d}, 0); v.fail != (err != nil) {
					t.Fatalf("VerifyMACMulti = %v, fail %v", err, v.fail)
				}
				return
			case "rsapss":
				msg, err := UnmarshalSign(wire)
				if err != nil {
					t.Fatal(err)
				}
				n, _ := new(big.Int).SetString(v.x, 16)
				e, _ := new(big.Int).SetString(v.y, 16)
				vf, err := NewVerifier(&rsa.PublicKey{N: n, E: int(e.Int64())})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := VerifyMulti(msg, []*Verifier{vf}); v.fail != (err != nil) {
					t.Fatalf("VerifyMulti = %v, fail %v", err, v.fail)
				}
				if string(msg.Payload) != v.plaintext {
					t.Fatalf("payload = %q", msg.Payload)
				}
				return
			default:
				t.Fatalf("kind %q", v.kind)
			}
			if string(got) != v.plaintext {
				t.Fatalf("plaintext = %q", got)
			}
		})
	}
}
