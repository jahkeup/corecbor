package eat

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
)

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func testClaims() *Claims {
	nonce := []byte("test-nonce-12345")
	secureBoot := true
	uptime := uint64(3600)
	return &Claims{
		ClaimsSet: cwt.ClaimsSet{
			Issuer:     "test-attester",
			Subject:    "device-001",
			Audience:   "relying-party",
			Expiration: time.Now().Add(time.Hour).Truncate(time.Second),
			IssuedAt:   time.Now().Truncate(time.Second),
		},
		Nonce:         [][]byte{nonce},
		UEID:          []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		OEMId:         []byte{0xAA, 0xBB, 0xCC},
		SecurityLevel: SecLevelHardware,
		SecureBoot:    &secureBoot,
		Debug:         DebugPermanentDisable,
		Uptime:        &uptime,
	}
}

func TestSign_Verify_RoundTrip(t *testing.T) {
	pub, priv := testKeyPair(t)

	signer, err := cose.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := cose.NewVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}

	original := testClaims()

	signed, err := Sign(original, signer)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	decoded, err := Verify(signed, verifier)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if decoded.Issuer != original.Issuer {
		t.Errorf("Issuer: got %q, want %q", decoded.Issuer, original.Issuer)
	}
	if decoded.Subject != original.Subject {
		t.Errorf("Subject: got %q, want %q", decoded.Subject, original.Subject)
	}
	if decoded.Audience != original.Audience {
		t.Errorf("Audience: got %q, want %q", decoded.Audience, original.Audience)
	}
	if !decoded.Expiration.Equal(original.Expiration) {
		t.Errorf("Expiration: got %v, want %v", decoded.Expiration, original.Expiration)
	}
	if !decoded.IssuedAt.Equal(original.IssuedAt) {
		t.Errorf("IssuedAt: got %v, want %v", decoded.IssuedAt, original.IssuedAt)
	}
	if len(decoded.Nonce) != 1 || string(decoded.Nonce[0]) != string(original.Nonce[0]) {
		t.Errorf("Nonce mismatch")
	}
	if string(decoded.UEID) != string(original.UEID) {
		t.Errorf("UEID mismatch")
	}
	if string(decoded.OEMId) != string(original.OEMId) {
		t.Errorf("OEMId mismatch")
	}
	if decoded.SecurityLevel != original.SecurityLevel {
		t.Errorf("SecurityLevel: got %d, want %d", decoded.SecurityLevel, original.SecurityLevel)
	}
	if decoded.SecureBoot == nil || *decoded.SecureBoot != *original.SecureBoot {
		t.Errorf("SecureBoot mismatch")
	}
	if decoded.Debug != original.Debug {
		t.Errorf("Debug: got %d, want %d", decoded.Debug, original.Debug)
	}
	if decoded.Uptime == nil || *decoded.Uptime != *original.Uptime {
		t.Errorf("Uptime mismatch")
	}
}

func TestAppraiser_NonceMismatch(t *testing.T) {
	claims := testClaims()
	appraiser := &Appraiser{
		RequireNonce: []byte("wrong-nonce-value"),
	}

	err := appraiser.Appraise(claims)
	if !errors.Is(err, ErrNonceMismatch) {
		t.Errorf("expected ErrNonceMismatch, got %v", err)
	}
}

func TestAppraiser_SecurityLevel(t *testing.T) {
	claims := testClaims()
	claims.SecurityLevel = SecLevelUnrestricted

	appraiser := &Appraiser{
		RequireSecurityLevel: SecLevelSecureRestricted,
	}

	err := appraiser.Appraise(claims)
	if !errors.Is(err, ErrSecurityLevel) {
		t.Errorf("expected ErrSecurityLevel, got %v", err)
	}
}

func TestAppraiser_SecureBoot(t *testing.T) {
	claims := testClaims()
	secureBoot := false
	claims.SecureBoot = &secureBoot

	appraiser := &Appraiser{
		RequireSecureBoot: true,
	}

	err := appraiser.Appraise(claims)
	if !errors.Is(err, ErrSecureBootRequired) {
		t.Errorf("expected ErrSecureBootRequired, got %v", err)
	}
}

func TestAppraiser_DebugEnabled(t *testing.T) {
	claims := testClaims()
	claims.Debug = DebugEnabled

	appraiser := &Appraiser{
		RequireDebugDisabled: true,
	}

	err := appraiser.Appraise(claims)
	if !errors.Is(err, ErrDebugEnabled) {
		t.Errorf("expected ErrDebugEnabled, got %v", err)
	}
}

func TestAppraiser_CWTValidation(t *testing.T) {
	claims := testClaims()
	claims.Expiration = time.Now().Add(-time.Hour)

	appraiser := &Appraiser{
		CWTValidator: &cwt.Validator{
			RequireExpiration: true,
		},
	}

	err := appraiser.Appraise(claims)
	if !errors.Is(err, cwt.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestAppraiser_AllPass(t *testing.T) {
	claims := testClaims()

	appraiser := &Appraiser{
		RequireNonce:         claims.Nonce[0],
		RequireSecurityLevel: SecLevelHardware,
		RequireSecureBoot:    true,
		RequireDebugDisabled: true,
		CWTValidator: &cwt.Validator{
			Audience:          "relying-party",
			RequireExpiration: true,
		},
		Custom: []func(*Claims) error{
			func(c *Claims) error {
				if len(c.UEID) == 0 {
					return errors.New("UEID required")
				}
				return nil
			},
		},
	}

	err := appraiser.Appraise(claims)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}
