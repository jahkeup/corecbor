// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Proposal 028 Phase 3: KeyResolver / VerifySign1, JWK interop.

// RFC 7517 Appendix A.1 / A.2 and RFC 8037 Appendix A.1.
const (
	rfc7517ECPublic  = `{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"}`
	rfc7517ECPrivate = `{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","use":"enc","kid":"1"}`
	rfc7517RSAPublic = `{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`
	rfc8037Ed25519   = `{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
)

func TestJWKInterop(t *testing.T) {
	for name, jwk := range map[string]string{
		"ec-public": rfc7517ECPublic, "ec-private": rfc7517ECPrivate,
		"rsa-public": rfc7517RSAPublic, "ed25519-private": rfc8037Ed25519,
	} {
		t.Run(name, func(t *testing.T) {
			k, err := KeyFromJWK([]byte(jwk))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := k.PublicKey(); err != nil {
				t.Fatalf("PublicKey: %v", err)
			}
			out, err := k.JWK()
			if err != nil {
				t.Fatal(err)
			}
			var in, got map[string]any
			_ = json.Unmarshal([]byte(jwk), &in)
			_ = json.Unmarshal(out, &got)
			for member, v := range in {
				if member == "use" {
					continue // converted to key_ops
				}
				if got[member] != v {
					t.Errorf("member %q: got %v, want %v", member, got[member], v)
				}
			}
			// COSE round trip preserves everything.
			enc, _ := k.MarshalCBOR()
			back, err := ParseKey(enc)
			if err != nil {
				t.Fatal(err)
			}
			out2, _ := back.JWK()
			if !bytes.Equal(out, out2) {
				t.Fatalf("JWK changed through COSE:\n%s\n%s", out, out2)
			}
		})
	}

	// "use":"enc" restricts the COSE key too: it must not verify signatures.
	enc, _ := KeyFromJWK([]byte(rfc7517ECPublic))
	if enc.Permits(KeyOpVerify) || !enc.Permits(KeyOpDecrypt) {
		t.Fatalf("use enc mapped to key_ops %v", enc.Ops())
	}
	if _, err := NewVerifierFromKey(enc); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("enc-only JWK verifier: %v", err)
	}
	// RFC 8037: the private key's derived public key is x.
	ed, _ := KeyFromJWK([]byte(rfc8037Ed25519))
	signer, err := ed.Signer()
	if err != nil {
		t.Fatal(err)
	}
	x, _ := ed.bytesParam(keyLabelX)
	if !bytes.Equal(signer.Public().(ed25519.PublicKey), x) {
		t.Fatal("RFC 8037 key mismatch")
	}

	for _, bad := range []string{
		`{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`, // short coordinates
		`{"kty":"XYZ"}`,
		`{"kty":"oct","k":"AQ","alg":"NOPE"}`,
		`{"kty":"oct","k":"AQ","use":"other"}`,
		`not json`,
	} {
		if _, err := KeyFromJWK([]byte(bad)); err == nil {
			t.Errorf("KeyFromJWK(%s) succeeded", bad)
		}
	}
	// oct key_ops sign/verify mean MAC create/verify.
	mac, err := KeyFromJWK([]byte(`{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw","key_ops":["sign","verify"]}`))
	if err != nil || !mac.Permits(KeyOpMACCreate) || mac.Permits(KeyOpSign) {
		t.Fatalf("oct key_ops: %v %v", mac.Ops(), err)
	}
	j, _ := mac.JWK()
	if !strings.Contains(string(j), `"key_ops":["sign","verify"]`) {
		t.Fatalf("oct JWK key_ops: %s", j)
	}
}

func TestVerifyWithResolver(t *testing.T) {
	ctx := context.Background()
	mk := func(kid string) (*Signer, *Key) {
		p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		k, _ := NewKeyFromPublic(&p.PublicKey)
		k.SetID([]byte(kid))
		var h Headers
		h.SetKeyID([]byte(kid))
		s, _ := NewSigner(p, WithProtectedHeaders(h))
		return s, k
	}
	sa, ka := mk("a")
	sb, kb := mk("b")
	ks := KeySet{ka, kb}
	r := KeySetResolver(ks)

	msgB, _ := sb.Sign([]byte("x"))
	if err := VerifySign1(ctx, msgB, r); err != nil {
		t.Fatalf("kid b: %v", err)
	}
	msgA, _ := sa.Sign([]byte("x"))
	if err := VerifySign1(ctx, msgA, r); err != nil {
		t.Fatalf("kid a: %v", err)
	}
	// A message claiming kid b but signed by a: kid b's key doesn't verify.
	forged := *msgA
	forged.Protected = msgB.Protected
	if err := VerifySign1(ctx, &forged, r); !errors.Is(err, ErrVerification) {
		t.Fatalf("forged kid: %v", err)
	}
	other, _ := mk("c")
	msgC, _ := other.Sign([]byte("x"))
	if err := VerifySign1(ctx, msgC, r); !errors.Is(err, ErrVerification) {
		t.Fatalf("unknown kid: %v", err)
	}
	// key_ops excluding verify keeps a key out.
	kb.SetOps(KeyOpEncrypt)
	if err := VerifySign1(ctx, msgB, r); !errors.Is(err, ErrVerification) {
		t.Fatalf("verify-forbidden key used: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := VerifySign1(cctx, msgA, r); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	det, _ := sa.SignDetached([]byte("content"))
	if err := VerifySign1(ctx, det, r); !errors.Is(err, ErrMissingPayload) {
		t.Fatalf("detached via VerifySign1: %v", err)
	}
	if err := VerifySign1Detached(ctx, det, []byte("content"), r); err != nil {
		t.Fatalf("VerifySign1Detached: %v", err)
	}
	failing := KeyResolverFunc(func(context.Context, *Headers, *Headers) ([]*Key, error) {
		return nil, errors.New("directory down")
	})
	if err := VerifySign1(ctx, msgA, failing); err == nil || errors.Is(err, ErrVerification) {
		t.Fatalf("resolver error should surface as is: %v", err)
	}
}

func TestVerifyWithResolverRSAKeyAlg(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	k := &Key{params: map[int64]any{
		keyLabelKty: int64(KeyTypeRSA), keyLabelRSAN: rk.N.Bytes(), keyLabelRSAE: []byte{1, 0, 1},
	}}
	k.SetAlgorithm(AlgPS256)
	v, err := NewVerifierFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	// The key's alg narrows the verifier to PS256.
	if len(v.policy.allowed) != 1 || v.policy.allowed[0] != AlgPS256 {
		t.Fatalf("allowed = %v", v.policy.allowed)
	}
}
