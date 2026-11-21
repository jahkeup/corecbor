// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// cose-wg x509-examples: x5bag / x5chain with one and two certificates,
// and an x5t digest. Each message is verified with the key taken from
// the certificate it carries (or the digest's certificate), the way a
// relying party would after validating the chain.
func TestCOSEWGX509Headers(t *testing.T) {
	aliceDER, _ := hex.DecodeString(cosewgAliceDER)
	for _, tc := range cosewgX509 {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := UnmarshalSign(wire)
			if err != nil {
				t.Fatal(err)
			}
			sig := msg.Signatures[0]
			var certs [][]byte
			chain, err := sig.Unprotected.X5Chain()
			if err != nil {
				t.Fatal(err)
			}
			bag, err := sig.Unprotected.X5Bag()
			if err != nil {
				t.Fatal(err)
			}
			certs = append(chain, bag...)
			if ch, ok, err := sig.Unprotected.X5T(); err != nil {
				t.Fatal(err)
			} else if ok {
				if ch.Alg != AlgSHA256 || !ch.Matches(aliceDER) {
					t.Fatalf("x5t %+v does not match alice.der", ch)
				}
				certs = append(certs, aliceDER)
			}
			wantCerts := map[string]int{"signed-01": 1, "signed-02": 2, "signed-03": 1, "signed-04": 2, "signed-05": 1}
			if n := wantCerts[strings.TrimPrefix(tc.name, "x509-examples/")]; len(certs) != n {
				t.Fatalf("got %d certificates, want %d", len(certs), n)
			}
			if certs[0][0] != 0x30 || !strings.EqualFold(hex.EncodeToString(certs[0]), cosewgAliceDER) {
				t.Fatal("leaf certificate is not alice.der")
			}
			cert, err := x509.ParseCertificate(certs[0])
			if err != nil {
				t.Fatal(err)
			}
			v, err := NewVerifier(cert.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyMulti(msg, []*Verifier{v}); err != nil {
				t.Fatalf("verify with certificate key: %v", err)
			}
		})
	}
	// The input key of signed-05 is the certificate's key.
	x, _ := hex.DecodeString(cosewgAliceX)
	y, _ := hex.DecodeString(cosewgAliceY)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(aliceDER)
	if !pub.Equal(cert.PublicKey) {
		t.Fatal("signed-05 key differs from alice.der")
	}
}

// cose-wg rsa-pss-examples: COSE_Sign with PS256, PS384, PS512.
func TestCOSEWGRSAPSS(t *testing.T) {
	for _, tc := range cosewgRSAPSS {
		t.Run(tc.name, func(t *testing.T) {
			wire, _ := hex.DecodeString(tc.wire)
			msg, err := UnmarshalSign(wire)
			if err != nil {
				t.Fatal(err)
			}
			n, _ := hex.DecodeString(tc.n)
			e, _ := hex.DecodeString(tc.e)
			pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
			v, err := NewVerifier(pub)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyMulti(msg, []*Verifier{v}); err != nil {
				t.Fatalf("VerifyMulti: %v", err)
			}
			// The same key as a COSE_Key (kty 3) verifies too.
			k := &Key{params: map[int64]any{keyLabelKty: int64(KeyTypeRSA), keyLabelRSAN: n, keyLabelRSAE: e}}
			kv, err := NewVerifierFromKey(k)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyMulti(msg, []*Verifier{kv}); err != nil {
				t.Fatalf("VerifyMulti with COSE_Key: %v", err)
			}
			// Tampered payload fails.
			msg.Payload = append([]byte(nil), msg.Payload...)
			msg.Payload[0] ^= 1
			if _, err := VerifyMulti(msg, []*Verifier{v}); err == nil {
				t.Fatal("tampered payload verified")
			}
		})
	}
}
