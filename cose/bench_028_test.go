// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// Proposal 028 performance: extra protected headers are pre-encoded per
// Signer, so they shouldn't add per-message work beyond the bytes.
func BenchmarkSign1ES256(b *testing.B) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var prot Headers
	prot.SetKeyID([]byte("issuer-key-1"))
	_ = prot.SetType("application/example+cose")
	for name, opts := range map[string][]SignerOption{
		"alg-only":      nil,
		"extra-headers": {WithProtectedHeaders(prot)},
	} {
		s, err := NewSigner(key, opts...)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := s.Sign([]byte("payload")); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkParseKeyEC2(b *testing.B) {
	data, _ := hex.DecodeString(webauthnES256AuthData[2*(32+1+4+16+2+32):])
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseKey(data); err != nil {
			b.Fatal(err)
		}
	}
}
