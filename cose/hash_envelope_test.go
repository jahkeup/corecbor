// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cose"
)

// rfc9995Envelope is the parameter set of the RFC 9995 §4.1 example.
var rfc9995Envelope = cose.HashEnvelope{
	HashAlg:             cose.AlgSHA256,
	PreimageContentType: "application/spdx+json",
	Location:            "https://sbom.example/.../manifest.spdx.json",
}

func p384Signer(t *testing.T, opts ...cose.SignerOption) (*cose.Signer, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := cose.NewSigner(priv, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s, priv
}

// TestHashEnvelopeRFC9995 rebuilds the RFC 9995 §4.1 example (its
// digest and signature are elided in the RFC, so the bytes can't be
// reproduced): an ES384 signature over the SHA-256 digest of an SPDX
// SBOM, with kid, typ, and labels 258/259/260 protected and an empty
// unprotected bucket.
func TestHashEnvelopeRFC9995(t *testing.T) {
	var prot cose.Headers
	prot.SetKeyID([]byte("urn:example:sbom-signer"))
	if err := prot.SetType("application/example+cose"); err != nil {
		t.Fatal(err)
	}
	s, priv := p384Signer(t, cose.WithProtectedHeaders(prot))
	sbom := []byte(`{"spdxVersion":"SPDX-2.3","name":"manifest"}`)

	msg, err := s.SignHashEnvelope(sbom, rfc9995Envelope, false)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(sbom)
	if !bytes.Equal(msg.Payload, want[:]) {
		t.Fatalf("payload = %x, want SHA-256(preimage) %x", msg.Payload, want)
	}

	wire, err := cose.MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cose.UnmarshalSign1(wire)
	if err != nil {
		t.Fatal(err)
	}
	// The protected header carries exactly the example's labels.
	if a := got.Protected.Algorithm(); a != cose.AlgES384 {
		t.Errorf("alg = %v, want ES384 (-35)", a)
	}
	for _, label := range []int64{1, 4, 16, 258, 259, 260} {
		if got.Protected.Get(label) == nil {
			t.Errorf("protected label %d missing", label)
		}
	}
	if !got.Unprotected.IsEmpty() {
		t.Errorf("unprotected bucket not empty")
	}

	v, err := cose.NewVerifier(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	env, err := v.VerifyHashEnvelope(got, nil, sbom)
	if err != nil {
		t.Fatal(err)
	}
	if env != rfc9995Envelope {
		t.Errorf("envelope = %+v, want %+v", env, rfc9995Envelope)
	}
}

// TestHashEnvelopeRejects covers the RFC 9995 §4 MUST/MUST NOT rules on
// the verify side, using messages a plain Sign1 can produce.
func TestHashEnvelopeRejects(t *testing.T) {
	s, priv := p384Signer(t)
	v, err := cose.NewVerifier(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("preimage"))
	sign := func(t *testing.T, prot, unprot map[int64]any) *cose.Sign1 {
		t.Helper()
		msg := &cose.Sign1{Payload: digest[:]}
		for l, x := range prot {
			if err := msg.Protected.SetChecked(l, x); err != nil {
				t.Fatal(err)
			}
		}
		for l, x := range unprot {
			if err := msg.Unprotected.SetChecked(l, x); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Sign1(msg); err != nil {
			t.Fatal(err)
		}
		return msg
	}
	cases := map[string]*cose.Sign1{
		"258-missing":                sign(t, nil, nil),
		"258-unprotected-only":       sign(t, nil, map[int64]any{258: int64(-16)}),
		"259-unprotected":            sign(t, map[int64]any{258: int64(-16)}, map[int64]any{259: "text/plain"}),
		"260-unprotected":            sign(t, map[int64]any{258: int64(-16)}, map[int64]any{260: "https://x.example"}),
		"label3-protected":           sign(t, map[int64]any{258: int64(-16), 3: "application/json"}, nil),
		"label3-unprotected":         sign(t, map[int64]any{258: int64(-16)}, map[int64]any{3: "application/json"}),
		"258-not-int":                sign(t, map[int64]any{258: "sha-256"}, nil),
		"259-wrong-type":             sign(t, map[int64]any{258: int64(-16), 259: []byte{1}}, nil),
		"260-wrong-type":             sign(t, map[int64]any{258: int64(-16), 260: int64(7)}, nil),
		"digest-length-mismatch":     sign(t, map[int64]any{258: int64(cose.AlgSHA512)}, nil),
		"filter-only-hash-sha256-64": sign(t, map[int64]any{258: int64(cose.AlgSHA256_64)}, nil),
	}
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.VerifyHashEnvelope(msg, nil, nil)
			if err == nil {
				t.Fatal("verified; want an RFC 9995 rule violation")
			}
			if !errors.Is(err, cose.ErrMalformed) && !errors.Is(err, cose.ErrUnsupportedAlgorithm) {
				t.Fatalf("err = %v, want ErrMalformed or ErrUnsupportedAlgorithm", err)
			}
		})
	}
}

// TestHashEnvelopeSignRejects checks that signing can't produce a
// non-conforming envelope.
func TestHashEnvelopeSignRejects(t *testing.T) {
	var ct cose.Headers
	if err := ct.SetContentType("application/json"); err != nil {
		t.Fatal(err)
	}
	withCT, _ := p384Signer(t, cose.WithProtectedHeaders(ct))
	if _, err := withCT.SignHashEnvelope([]byte("x"), rfc9995Envelope, false); !errors.Is(err, cose.ErrMalformed) {
		t.Errorf("signer with content type: err = %v, want ErrMalformed", err)
	}

	var u cose.Headers
	if err := u.SetChecked(cose.HeaderPayloadLocation, "https://x.example"); err != nil {
		t.Fatal(err)
	}
	withUnprot, _ := p384Signer(t, cose.WithUnprotectedHeaders(u))
	if _, err := withUnprot.SignHashEnvelope([]byte("x"), cose.HashEnvelope{HashAlg: cose.AlgSHA256}, false); !errors.Is(err, cose.ErrMalformed) {
		t.Errorf("signer with unprotected 260: err = %v, want ErrMalformed", err)
	}

	s, _ := p384Signer(t)
	if _, err := s.SignHashEnvelopeDigest(make([]byte, 31), cose.HashEnvelope{HashAlg: cose.AlgSHA256}, false); !errors.Is(err, cose.ErrMalformed) {
		t.Errorf("short digest: err = %v, want ErrMalformed", err)
	}
	if _, err := s.SignHashEnvelope([]byte("x"), cose.HashEnvelope{HashAlg: cose.AlgSHA1}, false); !errors.Is(err, cose.ErrUnsupportedAlgorithm) {
		t.Errorf("SHA-1: err = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := s.SignHashEnvelope([]byte("x"), cose.HashEnvelope{HashAlg: cose.AlgSHA256, PreimageContentType: -1}, false); err == nil {
		t.Error("negative content format: want error")
	}
}

// TestHashEnvelopePreimage checks digest/preimage handling for attached
// and detached envelopes.
func TestHashEnvelopePreimage(t *testing.T) {
	s, priv := p384Signer(t)
	v, err := cose.NewVerifier(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pre := []byte("large artifact")
	digest := sha256.Sum256(pre)
	env := cose.HashEnvelope{HashAlg: cose.AlgSHA256, PreimageContentType: uint64(42)}

	attached, err := s.SignHashEnvelope(pre, env, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v.VerifyHashEnvelope(attached, nil, nil); err != nil || got != env {
		t.Fatalf("attached, signature only: env=%+v err=%v", got, err)
	}
	if _, err := v.VerifyHashEnvelope(attached, nil, []byte("other")); !errors.Is(err, cose.ErrVerification) {
		t.Errorf("wrong preimage: err = %v, want ErrVerification", err)
	}
	other := sha256.Sum256([]byte("other"))
	if _, err := v.VerifyHashEnvelope(attached, other[:], nil); !errors.Is(err, cose.ErrVerification) {
		t.Errorf("digest differs from payload: err = %v, want ErrVerification", err)
	}

	detached, err := s.SignHashEnvelope(pre, env, true)
	if err != nil {
		t.Fatal(err)
	}
	if detached.Payload != nil {
		t.Fatal("detached envelope has a payload")
	}
	if _, err := v.VerifyHashEnvelope(detached, nil, nil); !errors.Is(err, cose.ErrMissingPayload) {
		t.Errorf("detached, nothing supplied: err = %v, want ErrMissingPayload", err)
	}
	if _, err := v.VerifyHashEnvelope(detached, digest[:], nil); err != nil {
		t.Errorf("detached, digest supplied: %v", err)
	}
	if _, err := v.VerifyHashEnvelope(detached, nil, pre); err != nil {
		t.Errorf("detached, preimage supplied: %v", err)
	}
	if _, err := v.VerifyHashEnvelope(detached, other[:], nil); !errors.Is(err, cose.ErrVerification) {
		t.Errorf("detached, wrong digest: err = %v, want ErrVerification", err)
	}
	if _, err := v.VerifyHashEnvelope(detached, digest[:16], nil); !errors.Is(err, cose.ErrMalformed) {
		t.Errorf("detached, short digest: err = %v, want ErrMalformed", err)
	}
}

func TestHashEnvelopeResolverAndAlgorithms(t *testing.T) {
	for _, alg := range []cose.Algorithm{cose.AlgSHA256, cose.AlgSHA384, cose.AlgSHA512, cose.AlgSHA512_256} {
		t.Run(alg.String(), func(t *testing.T) {
			var prot cose.Headers
			prot.SetKeyID([]byte("k1"))
			s, priv := p384Signer(t, cose.WithProtectedHeaders(prot), cose.WithFullySpecifiedAlgorithms())
			msg, err := s.SignHashEnvelope([]byte("p"), cose.HashEnvelope{HashAlg: alg}, true)
			if err != nil {
				t.Fatal(err)
			}
			k, err := cose.NewKeyFromPublic(&priv.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			k.SetID([]byte("k1"))
			env, err := cose.VerifySign1HashEnvelope(context.Background(), msg, nil, []byte("p"), cose.KeySetResolver(cose.KeySet{k}))
			if err != nil || env.HashAlg != alg {
				t.Fatalf("env=%+v err=%v", env, err)
			}
		})
	}
}

// TestHashEnvelopeMessage builds an envelope that also carries other
// protected parameters (as a SCITT signed statement does).
func TestHashEnvelopeMessage(t *testing.T) {
	s, priv := p384Signer(t)
	msg := &cose.Sign1{}
	if err := msg.Protected.SetChecked(int64(15), corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Uint(1), Value: corecbor.Text("iss")})); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("p"))
	if err := s.SignHashEnvelopeMessage(context.Background(), msg, digest[:], cose.HashEnvelope{HashAlg: cose.AlgSHA256}, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := msg.Protected.CWTClaims(); !ok {
		t.Error("CWT Claims lost")
	}
	v, err := cose.NewVerifier(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyHashEnvelope(msg, nil, []byte("p")); err != nil {
		t.Fatal(err)
	}
}
