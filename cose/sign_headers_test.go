// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/jahkeup/corecbor"
)

// Proposal 028 Phase 1: caller headers, detached payloads, typed
// accessors, KMS-style signers.

func fixedEd25519(b byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	return ed25519.NewKeyFromSeed(seed)
}

func scittHeaders(t *testing.T) (Headers, Headers) {
	t.Helper()
	var prot, unprot Headers
	prot.SetKeyID([]byte("issuer-key-1"))
	claims := corecbor.MakeMap(
		corecbor.MapEntry{Key: corecbor.Uint(1), Value: corecbor.Text("https://issuer.example")},
		corecbor.MapEntry{Key: corecbor.Uint(2), Value: corecbor.Text("pkg:example/widget@1.0")},
	)
	if err := prot.SetCWTClaims(claims); err != nil {
		t.Fatal(err)
	}
	if err := prot.SetType("application/example-statement+cose"); err != nil {
		t.Fatal(err)
	}
	if err := unprot.SetX5Chain([]byte{0x30, 0x03, 0x02, 0x01, 0x01}); err != nil {
		t.Fatal(err)
	}
	return prot, unprot
}

func TestSignWithHeadersSCITT(t *testing.T) {
	key := fixedEd25519(7)
	prot, unprot := scittHeaders(t)
	s, err := NewSigner(key, WithProtectedHeaders(prot), WithUnprotectedHeaders(unprot))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := s.Sign([]byte("statement"))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	// Ed25519 is deterministic, so the whole message is pinned (digest
	// below). The protected map is in Core Deterministic order: 1, 4, 15, 16.
	if hex.EncodeToString(wire[:5]) != "d2845868a4" {
		t.Fatalf("unexpected head %x", wire[:5])
	}

	got, err := UnmarshalSign1(wire)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(got); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if kid := got.Protected.KeyID(); string(kid) != "issuer-key-1" {
		t.Fatalf("kid = %q", kid)
	}
	claims, ok := got.Protected.CWTClaims()
	if !ok || len(claims.Map()) != 2 || claims.Map()[0].Value.TextVal() != "https://issuer.example" {
		t.Fatalf("CWTClaims = %v, %v", claims, ok)
	}
	if _, typ, ok := got.Protected.Type(); !ok || typ != "application/example-statement+cose" {
		t.Fatalf("typ = %q, %v", typ, ok)
	}
	chain, err := got.Unprotected.X5Chain()
	if err != nil || len(chain) != 1 || hex.EncodeToString(chain[0]) != "3003020101" {
		t.Fatalf("x5chain = %x, %v", chain, err)
	}
	// Pin the bytes: a change in header encoding must be deliberate.
	sum := sha256.Sum256(wire)
	if hex.EncodeToString(sum[:]) != scittFixtureSHA256 {
		t.Fatalf("wire changed: sha256 %x\n%x", sum, wire)
	}
}

// scittFixtureSHA256 pins TestSignWithHeadersSCITT's output bytes.
const scittFixtureSHA256 = "ff4244c2b5068f2acc9f8ebd43d79c5748ddd50a2f0b77faf510b3fe4cf7bd08"

func TestSignerHeaderValidation(t *testing.T) {
	key := fixedEd25519(1)
	var prot Headers
	prot.SetAlgorithm(AlgES256)
	if _, err := NewSigner(key, WithProtectedHeaders(prot)); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("mismatched alg: %v, want ErrAlgorithmMismatch", err)
	}
	prot = Headers{}
	prot.SetAlgorithm(AlgEdDSA) // matching alg is fine
	if _, err := NewSigner(key, WithProtectedHeaders(prot)); err != nil {
		t.Fatalf("matching alg: %v", err)
	}
	var p, u Headers
	p.SetKeyID([]byte("k"))
	u.SetKeyID([]byte("k"))
	if _, err := NewSigner(key, WithProtectedHeaders(p), WithUnprotectedHeaders(u)); !errors.Is(err, ErrDuplicateLabel) {
		t.Fatalf("kid in both buckets: %v, want ErrDuplicateLabel", err)
	}
	var alg Headers
	alg.SetAlgorithm(AlgEdDSA)
	if _, err := NewSigner(key, WithUnprotectedHeaders(alg)); !errors.Is(err, ErrDuplicateLabel) {
		t.Fatalf("unprotected alg: %v, want ErrDuplicateLabel", err)
	}
	// The caller's Headers is copied: changing it later doesn't affect the Signer.
	var h Headers
	h.SetKeyID([]byte("before"))
	s, err := NewSigner(key, WithProtectedHeaders(h))
	if err != nil {
		t.Fatal(err)
	}
	h.SetKeyID([]byte("after"))
	msg, _ := s.Sign([]byte("x"))
	if string(msg.Protected.KeyID()) != "before" {
		t.Fatalf("Signer headers aliased the caller's: kid %q", msg.Protected.KeyID())
	}
}

func TestSignNoOptionsUnchanged(t *testing.T) {
	key := fixedEd25519(3)
	s, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := s.Sign([]byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	// Protected bucket is exactly {1: -8} (h'a10127') and unprotected empty.
	if hex.EncodeToString(wire[:9]) != "d28443a10127a04170" {
		t.Fatalf("header bytes changed: %x", wire[:9])
	}
}

func TestSign1PerMessageHeaders(t *testing.T) {
	key := fixedEd25519(4)
	var def Headers
	def.SetKeyID([]byte("default"))
	s, err := NewSigner(key, WithProtectedHeaders(def))
	if err != nil {
		t.Fatal(err)
	}
	msg := &Sign1{Payload: []byte("m")}
	if err := msg.Protected.SetContentType(uint64(60)); err != nil {
		t.Fatal(err)
	}
	if err := msg.Unprotected.SetX5U("https://example/chain.pem"); err != nil {
		t.Fatal(err)
	}
	if err := s.Sign1(msg); err != nil {
		t.Fatal(err)
	}
	wire, err := MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalSign1(wire)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := NewVerifier(key.Public())
	if err := v.Verify(got); err != nil {
		t.Fatal(err)
	}
	if string(got.Protected.KeyID()) != "default" {
		t.Fatalf("signer default kid lost: %q", got.Protected.KeyID())
	}
	if ct, _, ok := got.Protected.ContentType(); !ok || ct != 60 {
		t.Fatalf("content type = %d, %v", ct, ok)
	}
	if u, ok := got.Unprotected.X5U(); !ok || u != "https://example/chain.pem" {
		t.Fatalf("x5u = %q", u)
	}
	if got.Protected.Algorithm() != AlgEdDSA {
		t.Fatalf("alg = %v", got.Protected.Algorithm())
	}

	bad := &Sign1{Payload: []byte("m")}
	bad.Protected.SetAlgorithm(AlgES384)
	if err := s.Sign1(bad); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("per-message alg mismatch: %v", err)
	}
	dup := &Sign1{Payload: []byte("m")}
	dup.Unprotected.SetKeyID([]byte("x")) // signer's protected already has kid
	if err := s.Sign1(dup); !errors.Is(err, ErrDuplicateLabel) {
		t.Fatalf("kid in both buckets: %v", err)
	}
}

func TestSignDetached(t *testing.T) {
	key := fixedEd25519(5)
	s, _ := NewSigner(key)
	v, _ := NewVerifier(key.Public())
	content := []byte("large artifact")
	msg, err := s.SignDetached(content)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Payload != nil {
		t.Fatal("SignDetached kept the payload")
	}
	wire, err := MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalSign1(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Payload != nil {
		t.Fatal("wire payload not null")
	}
	if err := v.Verify(got); !errors.Is(err, ErrMissingPayload) {
		t.Fatalf("Verify of detached: %v, want ErrMissingPayload", err)
	}
	if err := v.VerifyDetached(got, content); err != nil {
		t.Fatalf("VerifyDetached: %v", err)
	}
	if err := v.VerifyDetached(got, []byte("other")); !errors.Is(err, ErrVerification) {
		t.Fatalf("VerifyDetached wrong content: %v", err)
	}
}

func TestSignMultiBodyHeaders(t *testing.T) {
	a, b := fixedEd25519(8), fixedEd25519(9)
	var kidA Headers
	kidA.SetKeyID([]byte("a"))
	sa, _ := NewSigner(a, WithProtectedHeaders(kidA))
	sb, _ := NewSigner(b)
	var body Headers
	if err := body.SetContentType("application/json"); err != nil {
		t.Fatal(err)
	}
	msg, err := SignMulti([]byte("doc"), []*Signer{sa, sb}, WithProtectedHeaders(body), WithSignerExternalData([]byte("aad")))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := MarshalSign(msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalSign(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, ct, ok := got.Protected.ContentType(); !ok || ct != "application/json" {
		t.Fatalf("body content type = %q", ct)
	}
	if string(got.Signatures[0].Protected.KeyID()) != "a" {
		t.Fatalf("signer headers lost: %q", got.Signatures[0].Protected.KeyID())
	}
	va, _ := NewVerifier(a.Public(), WithVerifierExternalData([]byte("aad")))
	vb, _ := NewVerifier(b.Public(), WithVerifierExternalData([]byte("aad")))
	if idx, err := VerifyMulti(got, []*Verifier{va, vb}, RequireAll); err != nil || len(idx) != 2 {
		t.Fatalf("VerifyMulti = %v, %v", idx, err)
	}
	// Without the external AAD the signatures don't verify.
	vn, _ := NewVerifier(a.Public())
	if _, err := VerifyMulti(got, []*Verifier{vn}); !errors.Is(err, ErrVerification) {
		t.Fatalf("missing AAD: %v", err)
	}

	det, err := SignMultiDetached([]byte("doc"), []*Signer{sa})
	if err != nil {
		t.Fatal(err)
	}
	if det.Payload != nil {
		t.Fatal("SignMultiDetached kept the payload")
	}
	va2, _ := NewVerifier(a.Public())
	if _, err := VerifyMultiDetached(det, []byte("doc"), []*Verifier{va2}); err != nil {
		t.Fatalf("VerifyMultiDetached: %v", err)
	}
}

// kmsEd25519 is a crypto.Signer that isn't an ed25519.PrivateKey, like a
// KMS or HSM client.
type kmsEd25519 struct{ priv ed25519.PrivateKey }

func (k kmsEd25519) Public() crypto.PublicKey { return k.priv.Public() }
func (k kmsEd25519) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.priv.Sign(r, msg, opts)
}

func TestKMSEd25519Signer(t *testing.T) {
	key := fixedEd25519(10)
	s, err := NewSigner(kmsEd25519{key})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := s.Sign([]byte("hi"))
	if err != nil {
		t.Fatalf("KMS Ed25519 Sign: %v", err)
	}
	v, _ := NewVerifier(key.Public())
	if err := v.Verify(msg); err != nil {
		t.Fatal(err)
	}
}

type ctxSigner struct {
	kmsEd25519
	sawCtx bool
}

func (c *ctxSigner) SignContext(ctx context.Context, r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	c.sawCtx = true
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.Sign(r, digest, opts)
}

func TestSignContextCancel(t *testing.T) {
	cs := &ctxSigner{kmsEd25519: kmsEd25519{fixedEd25519(11)}}
	s, err := NewSigner(cs)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.SignContext(ctx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("SignContext cancelled = %v", err)
	}
	if !cs.sawCtx {
		t.Fatal("ContextSigner not used")
	}
	if _, err := s.SignContext(context.Background(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	// A plain signer also honors cancellation before signing.
	plain, _ := NewSigner(fixedEd25519(12))
	if _, err := plain.SignContext(ctx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("plain SignContext cancelled = %v", err)
	}
}

func TestX5ChainForms(t *testing.T) {
	c1, c2 := []byte{0x30, 0x01, 0x00}, []byte{0x30, 0x01, 0x01}
	var h Headers
	if err := h.SetX5Chain(c1); err != nil {
		t.Fatal(err)
	}
	if v := h.Get(headerLabelX5Chain); v == nil {
		t.Fatal("not set")
	} else if _, isBytes := v.([]byte); !isBytes {
		t.Fatalf("single certificate stored as %T, want bstr", v)
	}
	if err := h.SetX5Chain(c1, c2); err != nil {
		t.Fatal(err)
	}
	m, _ := h.toCBORMap()
	enc, _ := sharedEncoder.Encode(nil, m)
	got, err := decodeProtected(enc, DecodeLimits{})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := got.X5Chain()
	if err != nil || len(chain) != 2 || chain[1][2] != 0x01 {
		t.Fatalf("X5Chain = %x, %v", chain, err)
	}
	// A one-element array is not a valid COSE_X509.
	bad := Headers{params: map[any]any{headerLabelX5Chain: corecbor.MakeArray(corecbor.Bytes(c1))}}
	if _, err := bad.X5Chain(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("[bstr] = %v, want ErrMalformed", err)
	}
	if err := h.SetX5Chain(); !errors.Is(err, ErrUnsupportedHeader) {
		t.Fatalf("empty chain = %v", err)
	}
}

func TestX5T(t *testing.T) {
	cert := []byte("not really a certificate")
	sum := sha256.Sum256(cert)
	var h Headers
	if err := h.SetX5T(AlgSHA256, sum[:]); err != nil {
		t.Fatal(err)
	}
	ch, ok, err := h.X5T()
	if err != nil || !ok || ch.Alg != AlgSHA256 {
		t.Fatalf("X5T = %+v, %v, %v", ch, ok, err)
	}
	if !ch.Matches(cert) || ch.Matches([]byte("other")) {
		t.Fatal("Matches")
	}
	if (CertHash{Alg: AlgEdDSA, Hash: sum[:]}).Matches(cert) {
		t.Fatal("unsupported hash alg matched")
	}
	short := CertHash{Alg: AlgSHA256_64, Hash: sum[:8]}
	if !short.Matches(cert) {
		t.Fatal("SHA-256/64")
	}
}

func TestLookupProtectedFirst(t *testing.T) {
	var p, u Headers
	p.SetKeyID([]byte("p"))
	_ = u.SetIV([]byte{1})
	if v, ok := Lookup(&p, &u, 4); !ok || string(v.([]byte)) != "p" {
		t.Fatalf("Lookup kid = %v", v)
	}
	if v, ok := Lookup(&p, &u, int64(5)); !ok || v.([]byte)[0] != 1 {
		t.Fatalf("Lookup IV = %v", v)
	}
	if _, ok := Lookup(nil, &u, 99); ok {
		t.Fatal("absent label found")
	}
}

func TestVerifyRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(alg Algorithm) *Sign1 {
		t.Helper()
		var prot Headers
		prot.SetAlgorithm(alg)
		pb, _ := prot.encodeProtected()
		tbs, _ := encodeSigStructure(sharedEncoder, pb, nil, []byte("p"))
		var hash crypto.Hash
		switch alg {
		case AlgPS384:
			hash = crypto.SHA384
		default:
			hash = crypto.SHA256
		}
		d, _ := hashData(hash, tbs)
		var sig []byte
		if alg == AlgRS256 {
			sig, err = rsa.SignPKCS1v15(rand.Reader, key, hash, d)
		} else {
			sig, err = rsa.SignPSS(rand.Reader, key, hash, d, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		if err != nil {
			t.Fatal(err)
		}
		return &Sign1{Protected: prot, Payload: []byte("p"), Signature: sig}
	}
	v, err := NewVerifier(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []Algorithm{AlgPS256, AlgPS384} {
		if err := v.Verify(sign(alg)); err != nil {
			t.Fatalf("%v: %v", alg, err)
		}
	}
	if err := v.Verify(sign(AlgRS256)); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("RS256 without opt-in = %v, want ErrAlgorithmMismatch", err)
	}
	vrs, _ := NewVerifier(&key.PublicKey, WithAllowedAlgorithms(AlgRS256))
	if err := vrs.Verify(sign(AlgRS256)); err != nil {
		t.Fatalf("RS256 allowed: %v", err)
	}
	// RSA needs the alg in the protected bucket.
	m := sign(AlgPS256)
	m.Unprotected = m.Protected
	m.Protected = Headers{}
	if err := v.Verify(m); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("unprotected RSA alg = %v", err)
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := NewVerifier(&small.PublicKey); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("1024-bit RSA = %v, want ErrInvalidKey", err)
	}
	if _, err := NewSigner(key); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("RSA signer = %v", err)
	}
}
