// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestKeyECDHRoundTrip(t *testing.T) {
	for name, tc := range map[string]struct {
		curve ecdh.Curve
		kty   KeyType
		crv   Curve
		size  int
	}{
		"X25519": {ecdh.X25519(), KeyTypeOKP, CurveX25519, 32},
		"P-256":  {ecdh.P256(), KeyTypeEC2, CurveP256, 32},
		"P-384":  {ecdh.P384(), KeyTypeEC2, CurveP384, 48},
		"P-521":  {ecdh.P521(), KeyTypeEC2, CurveP521, 66},
	} {
		t.Run(name, func(t *testing.T) {
			priv, err := tc.curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			k, err := NewKeyFromECDH(priv)
			if err != nil {
				t.Fatal(err)
			}
			if k.KeyType() != tc.kty || k.Curve() != tc.crv {
				t.Fatalf("kty/crv = %d/%d, want %d/%d", k.KeyType(), k.Curve(), tc.kty, tc.crv)
			}
			for _, label := range []int64{keyLabelX, keyLabelD} {
				if b, _ := k.bytesParam(label); len(b) != tc.size {
					t.Fatalf("label %d is %d bytes, want %d", label, len(b), tc.size)
				}
			}

			enc, err := k.MarshalCBOR()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseKey(enc)
			if err != nil {
				t.Fatalf("ParseKey(NewKeyFromECDH): %v", err)
			}
			gotPriv, err := parsed.ECDHPrivateKey()
			if err != nil || !gotPriv.Equal(priv) {
				t.Fatalf("ECDHPrivateKey = %v, %v; want the original key", gotPriv, err)
			}
			gotPub, err := parsed.ECDHPublicKey()
			if err != nil || !gotPub.Equal(priv.PublicKey()) {
				t.Fatalf("ECDHPublicKey = %v, %v; want the original public key", gotPub, err)
			}

			// Public-only keys: NewKeyFromPublic accepts *ecdh.PublicKey,
			// and ECDHPrivateKey reports the missing private part.
			pubOnly, err := NewKeyFromPublic(priv.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			if p, err := pubOnly.ECDHPublicKey(); err != nil || !p.Equal(priv.PublicKey()) {
				t.Fatalf("public-only ECDHPublicKey = %v, %v", p, err)
			}
			if _, err := pubOnly.ECDHPrivateKey(); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("public-only ECDHPrivateKey err = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestKeyECDHMismatchAndUnsupported(t *testing.T) {
	a, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b, _ := ecdh.X25519().GenerateKey(rand.Reader)
	k, err := NewKeyFromECDH(a)
	if err != nil {
		t.Fatal(err)
	}
	k.set(keyLabelD, b.Bytes()) // d no longer matches x
	if _, err := k.ECDHPrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("mismatched d: err = %v, want ErrInvalidKey", err)
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ed, err := NewKeyFromPublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ed.ECDHPublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Ed25519 ECDHPublicKey err = %v, want ErrInvalidKey", err)
	}
	if _, err := NewKeyFromECDH(nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("NewKeyFromECDH(nil) err = %v, want ErrInvalidKey", err)
	}
}
