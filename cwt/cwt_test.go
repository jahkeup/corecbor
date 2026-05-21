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

func TestEncrypt_Decrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	claims := &cwt.ClaimsSet{
		Issuer:  "enc-issuer",
		Subject: "enc-subject",
	}

	token, err := cwt.Encrypt(claims, key, nonce, cose.AlgA256GCM)
	if err != nil {
		t.Fatal(err)
	}

	got, err := cwt.Decrypt(token, key, nonce, cose.AlgA256GCM)
	if err != nil {
		t.Fatal(err)
	}

	if got.Issuer != claims.Issuer {
		t.Errorf("issuer: got %q, want %q", got.Issuer, claims.Issuer)
	}
	if got.Subject != claims.Subject {
		t.Errorf("subject: got %q, want %q", got.Subject, claims.Subject)
	}
}

func TestEncrypt_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	claims := &cwt.ClaimsSet{Issuer: "enc-issuer"}

	token, err := cwt.Encrypt(claims, key, nonce, cose.AlgA256GCM)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatal(err)
	}

	_, err = cwt.Decrypt(token, wrongKey, nonce, cose.AlgA256GCM)
	if err == nil {
		t.Error("expected error decrypting with wrong key, got nil")
	}
}

func TestMAC_VerifyMAC_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	claims := &cwt.ClaimsSet{
		Issuer:  "mac-issuer",
		Subject: "mac-subject",
	}

	token, err := cwt.MAC(claims, key, cose.AlgHMAC256)
	if err != nil {
		t.Fatal(err)
	}

	got, err := cwt.VerifyMAC(token, key, cose.AlgHMAC256)
	if err != nil {
		t.Fatal(err)
	}

	if got.Issuer != claims.Issuer {
		t.Errorf("issuer: got %q, want %q", got.Issuer, claims.Issuer)
	}
	if got.Subject != claims.Subject {
		t.Errorf("subject: got %q, want %q", got.Subject, claims.Subject)
	}
}

func TestMAC_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	claims := &cwt.ClaimsSet{Issuer: "mac-issuer"}

	token, err := cwt.MAC(claims, key, cose.AlgHMAC256)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatal(err)
	}

	_, err = cwt.VerifyMAC(token, wrongKey, cose.AlgHMAC256)
	if err == nil {
		t.Error("expected error verifying MAC with wrong key, got nil")
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

func TestConfirmation_Key_RoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cose.NewKeyFromPublic(pub)
	if err != nil {
		t.Fatal(err)
	}

	original := &cwt.ClaimsSet{
		Issuer: "cnf-test",
		Confirmation: &cwt.Confirmation{
			Key: key,
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

	if decoded.Confirmation == nil {
		t.Fatal("expected confirmation, got nil")
	}
	if decoded.Confirmation.Key == nil {
		t.Fatal("expected confirmation key, got nil")
	}

	gotPub, err := decoded.Confirmation.Key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	gotEd, ok := gotPub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", gotPub)
	}
	if !gotEd.Equal(pub) {
		t.Error("decoded public key does not match original")
	}
}

func TestConfirmation_KeyID_RoundTrip(t *testing.T) {
	kid := []byte("my-key-id-123")

	original := &cwt.ClaimsSet{
		Issuer: "cnf-kid-test",
		Confirmation: &cwt.Confirmation{
			KeyID: kid,
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

	if decoded.Confirmation == nil {
		t.Fatal("expected confirmation, got nil")
	}
	if string(decoded.Confirmation.KeyID) != string(kid) {
		t.Errorf("kid: got %q, want %q", decoded.Confirmation.KeyID, kid)
	}
}

func TestValidate_RequireConfirmation_Missing(t *testing.T) {
	claims := &cwt.ClaimsSet{Issuer: "test"}
	v := &cwt.Validator{RequireConfirmation: true}
	err := v.Validate(claims)
	if !errors.Is(err, cwt.ErrMissingConfirmation) {
		t.Errorf("expected ErrMissingConfirmation, got %v", err)
	}
}

func TestValidate_RequireConfirmation_Present(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cose.NewKeyFromPublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	claims := &cwt.ClaimsSet{
		Issuer:       "test",
		Confirmation: &cwt.Confirmation{Key: key},
	}
	v := &cwt.Validator{RequireConfirmation: true}
	if err := v.Validate(claims); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}
