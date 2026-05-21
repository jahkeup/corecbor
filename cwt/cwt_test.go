package cwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
)

func TestSign_Verify_Ed25519_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := cose.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := cose.NewVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}

	claims := &cwt.ClaimsSet{
		Issuer:   "test-issuer",
		Subject:  "test-subject",
		Audience: "test-audience",
	}

	token, err := cwt.Sign(claims, signer)
	if err != nil {
		t.Fatal(err)
	}

	got, err := cwt.Verify(token, verifier)
	if err != nil {
		t.Fatal(err)
	}

	if got.Issuer != claims.Issuer {
		t.Errorf("issuer: got %q, want %q", got.Issuer, claims.Issuer)
	}
	if got.Subject != claims.Subject {
		t.Errorf("subject: got %q, want %q", got.Subject, claims.Subject)
	}
	if got.Audience != claims.Audience {
		t.Errorf("audience: got %q, want %q", got.Audience, claims.Audience)
	}
}

func TestSign_Verify_ES256_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := cose.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := cose.NewVerifier(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Truncate(time.Second)
	claims := &cwt.ClaimsSet{
		Issuer:     "es256-issuer",
		Subject:    "es256-sub",
		Audience:   "es256-aud",
		Expiration: now.Add(time.Hour),
		NotBefore:  now,
		IssuedAt:   now,
		CWTID:      []byte{0xde, 0xad, 0xbe, 0xef},
	}

	token, err := cwt.Sign(claims, signer)
	if err != nil {
		t.Fatal(err)
	}

	got, err := cwt.Verify(token, verifier)
	if err != nil {
		t.Fatal(err)
	}

	if got.Issuer != claims.Issuer {
		t.Errorf("issuer: got %q, want %q", got.Issuer, claims.Issuer)
	}
	if !got.Expiration.Equal(claims.Expiration) {
		t.Errorf("expiration: got %v, want %v", got.Expiration, claims.Expiration)
	}
	if !got.NotBefore.Equal(claims.NotBefore) {
		t.Errorf("not-before: got %v, want %v", got.NotBefore, claims.NotBefore)
	}
	if !got.IssuedAt.Equal(claims.IssuedAt) {
		t.Errorf("issued-at: got %v, want %v", got.IssuedAt, claims.IssuedAt)
	}
	if string(got.CWTID) != string(claims.CWTID) {
		t.Errorf("cwt-id: got %x, want %x", got.CWTID, claims.CWTID)
	}
}

func TestValidate_Expired(t *testing.T) {
	claims := &cwt.ClaimsSet{
		Expiration: time.Now().Add(-time.Hour),
	}
	v := &cwt.Validator{}
	err := v.Validate(claims)
	if !errors.Is(err, cwt.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestValidate_NotBefore(t *testing.T) {
	claims := &cwt.ClaimsSet{
		NotBefore: time.Now().Add(time.Hour),
	}
	v := &cwt.Validator{}
	err := v.Validate(claims)
	if !errors.Is(err, cwt.ErrTokenNotYetValid) {
		t.Errorf("expected ErrTokenNotYetValid, got %v", err)
	}
}

func TestValidate_AudienceMismatch(t *testing.T) {
	claims := &cwt.ClaimsSet{
		Audience: "actual-audience",
	}
	v := &cwt.Validator{Audience: "expected-audience"}
	err := v.Validate(claims)
	if !errors.Is(err, cwt.ErrAudienceMismatch) {
		t.Errorf("expected ErrAudienceMismatch, got %v", err)
	}
}

func TestValidate_Leeway(t *testing.T) {
	claims := &cwt.ClaimsSet{
		Expiration: time.Now().Add(-1 * time.Second),
	}
	v := &cwt.Validator{Leeway: 5 * time.Second}
	err := v.Validate(claims)
	if err != nil {
		t.Errorf("expected nil with leeway, got %v", err)
	}
}

func TestValidate_RequireExpiration(t *testing.T) {
	claims := &cwt.ClaimsSet{
		Issuer: "test",
	}
	v := &cwt.Validator{RequireExpiration: true}
	err := v.Validate(claims)
	if !errors.Is(err, cwt.ErrMissingExpiration) {
		t.Errorf("expected ErrMissingExpiration, got %v", err)
	}
}

func TestClaimsSet_Encode_Decode_RoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	original := &cwt.ClaimsSet{
		Issuer:     "roundtrip-iss",
		Subject:    "roundtrip-sub",
		Audience:   "roundtrip-aud",
		Expiration: now.Add(time.Hour),
		NotBefore:  now,
		IssuedAt:   now,
		CWTID:      []byte{1, 2, 3, 4},
	}

	data, err := original.Encode()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := cwt.DecodeClaimsSet(data)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Issuer != original.Issuer {
		t.Errorf("issuer: got %q, want %q", decoded.Issuer, original.Issuer)
	}
	if decoded.Subject != original.Subject {
		t.Errorf("subject: got %q, want %q", decoded.Subject, original.Subject)
	}
	if decoded.Audience != original.Audience {
		t.Errorf("audience: got %q, want %q", decoded.Audience, original.Audience)
	}
	if !decoded.Expiration.Equal(original.Expiration) {
		t.Errorf("expiration: got %v, want %v", decoded.Expiration, original.Expiration)
	}
	if !decoded.NotBefore.Equal(original.NotBefore) {
		t.Errorf("not-before: got %v, want %v", decoded.NotBefore, original.NotBefore)
	}
	if !decoded.IssuedAt.Equal(original.IssuedAt) {
		t.Errorf("issued-at: got %v, want %v", decoded.IssuedAt, original.IssuedAt)
	}
	if string(decoded.CWTID) != string(original.CWTID) {
		t.Errorf("cwt-id: got %x, want %x", decoded.CWTID, original.CWTID)
	}
}

func TestPrivateClaims_RoundTrip(t *testing.T) {
	original := &cwt.ClaimsSet{
		Issuer: "private-test",
		Private: map[any]any{
			int64(100): "custom-string-value",
			"x-app":    int64(42),
		},
	}

	data, err := original.Encode()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := cwt.DecodeClaimsSet(data)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Issuer != original.Issuer {
		t.Errorf("issuer: got %q, want %q", decoded.Issuer, original.Issuer)
	}

	if decoded.Private == nil {
		t.Fatal("expected private claims, got nil")
	}

	if v, ok := decoded.Private[int64(100)]; !ok || v != "custom-string-value" {
		t.Errorf("private[100]: got %v, want %q", v, "custom-string-value")
	}
	if v, ok := decoded.Private["x-app"]; !ok || v != int64(42) {
		t.Errorf("private[x-app]: got %v, want 42", v)
	}
}
