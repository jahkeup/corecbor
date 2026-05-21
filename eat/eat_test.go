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

func TestSWComponents_RoundTrip(t *testing.T) {
	original := testClaims()
	original.SWComponents = []SWComponent{
		{
			Type:                   "firmware",
			MeasurementValue:       []byte{0x01, 0x02, 0x03, 0x04},
			Version:                "1.0.0",
			SignerID:               []byte{0xAA, 0xBB},
			MeasurementDescription: "bootloader",
		},
		{
			Type:             "kernel",
			MeasurementValue: []byte{0x05, 0x06, 0x07, 0x08},
			Version:          "5.15.0",
		},
		{
			Type:             "rootfs",
			MeasurementValue: []byte{0x09, 0x0A, 0x0B, 0x0C},
			SignerID:         []byte{0xCC, 0xDD},
		},
	}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodeClaims(encoded)
	if err != nil {
		t.Fatalf("DecodeClaims failed: %v", err)
	}

	if len(decoded.SWComponents) != len(original.SWComponents) {
		t.Fatalf("SWComponents count: got %d, want %d", len(decoded.SWComponents), len(original.SWComponents))
	}

	for i, want := range original.SWComponents {
		got := decoded.SWComponents[i]
		if got.Type != want.Type {
			t.Errorf("[%d] Type: got %q, want %q", i, got.Type, want.Type)
		}
		if string(got.MeasurementValue) != string(want.MeasurementValue) {
			t.Errorf("[%d] MeasurementValue mismatch", i)
		}
		if got.Version != want.Version {
			t.Errorf("[%d] Version: got %q, want %q", i, got.Version, want.Version)
		}
		if string(got.SignerID) != string(want.SignerID) {
			t.Errorf("[%d] SignerID mismatch", i)
		}
		if got.MeasurementDescription != want.MeasurementDescription {
			t.Errorf("[%d] MeasurementDescription: got %q, want %q", i, got.MeasurementDescription, want.MeasurementDescription)
		}
	}
}

func TestAppraiser_SWPolicy(t *testing.T) {
	badMeasurement := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	claims := testClaims()
	claims.SWComponents = []SWComponent{
		{
			Type:             "firmware",
			MeasurementValue: badMeasurement,
		},
	}

	policyErr := errors.New("measurement value rejected")
	appraiser := &Appraiser{
		SWComponentPolicy: func(swcs []SWComponent) error {
			for _, sw := range swcs {
				if string(sw.MeasurementValue) == string(badMeasurement) {
					return policyErr
				}
			}
			return nil
		},
	}

	err := appraiser.Appraise(claims)
	if !errors.Is(err, policyErr) {
		t.Errorf("expected policy error, got %v", err)
	}
}

func TestAppraiser_ProfileMismatch(t *testing.T) {
	claims := testClaims()
	claims.Profile = "https://example.com/profile/v1"

	appraiser := &Appraiser{
		RequireProfile: "https://example.com/profile/v2",
	}

	err := appraiser.Appraise(claims)
	if !errors.Is(err, ErrProfileMismatch) {
		t.Errorf("expected ErrProfileMismatch, got %v", err)
	}
}

func TestAppraiser_ProfileMatch(t *testing.T) {
	claims := testClaims()
	claims.Profile = "https://example.com/profile/v1"

	appraiser := &Appraiser{
		RequireProfile: "https://example.com/profile/v1",
	}

	err := appraiser.Appraise(claims)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestSubmods_InlineClaims_RoundTrip(t *testing.T) {
	sub1 := &Claims{
		SecurityLevel: SecLevelHardware,
		Debug:         DebugPermanentDisable,
	}
	sub2 := &Claims{
		SecurityLevel: SecLevelSecureRestricted,
	}

	original := testClaims()
	original.Submods = map[string]Submod{
		"cpu":  {Claims: sub1},
		"wifi": {Claims: sub2},
	}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodeClaims(encoded)
	if err != nil {
		t.Fatalf("DecodeClaims failed: %v", err)
	}

	if len(decoded.Submods) != 2 {
		t.Fatalf("Submods count: got %d, want 2", len(decoded.Submods))
	}

	cpuSub, ok := decoded.Submods["cpu"]
	if !ok {
		t.Fatal("missing submod 'cpu'")
	}
	if cpuSub.Claims == nil {
		t.Fatal("cpu submod: expected inline Claims, got nil")
	}
	if cpuSub.Claims.SecurityLevel != SecLevelHardware {
		t.Errorf("cpu SecurityLevel: got %d, want %d", cpuSub.Claims.SecurityLevel, SecLevelHardware)
	}
	if cpuSub.Claims.Debug != DebugPermanentDisable {
		t.Errorf("cpu Debug: got %d, want %d", cpuSub.Claims.Debug, DebugPermanentDisable)
	}

	wifiSub, ok := decoded.Submods["wifi"]
	if !ok {
		t.Fatal("missing submod 'wifi'")
	}
	if wifiSub.Claims == nil {
		t.Fatal("wifi submod: expected inline Claims, got nil")
	}
	if wifiSub.Claims.SecurityLevel != SecLevelSecureRestricted {
		t.Errorf("wifi SecurityLevel: got %d, want %d", wifiSub.Claims.SecurityLevel, SecLevelSecureRestricted)
	}
}

func TestSubmods_NestedToken_RoundTrip(t *testing.T) {
	pub, priv := testKeyPair(t)
	signer, err := cose.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := cose.NewVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}

	subClaims := &Claims{
		SecurityLevel: SecLevelHardware,
		Debug:         DebugDisabled,
	}
	nestedToken, err := Sign(subClaims, signer)
	if err != nil {
		t.Fatalf("Sign nested token failed: %v", err)
	}

	original := testClaims()
	original.Submods = map[string]Submod{
		"tpm": {Token: nestedToken},
	}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodeClaims(encoded)
	if err != nil {
		t.Fatalf("DecodeClaims failed: %v", err)
	}

	if len(decoded.Submods) != 1 {
		t.Fatalf("Submods count: got %d, want 1", len(decoded.Submods))
	}

	tpmSub, ok := decoded.Submods["tpm"]
	if !ok {
		t.Fatal("missing submod 'tpm'")
	}
	if tpmSub.Token == nil {
		t.Fatal("tpm submod: expected Token bytes, got nil")
	}

	verified, err := Verify(tpmSub.Token, verifier)
	if err != nil {
		t.Fatalf("Verify nested token failed: %v", err)
	}
	if verified.SecurityLevel != SecLevelHardware {
		t.Errorf("nested SecurityLevel: got %d, want %d", verified.SecurityLevel, SecLevelHardware)
	}
}

func TestAppraiser_SubmodPolicy(t *testing.T) {
	sub := &Claims{
		SecurityLevel: SecLevelUnrestricted,
	}

	claims := testClaims()
	claims.Submods = map[string]Submod{
		"peripheral": {Claims: sub},
	}

	policyErr := errors.New("submod security level too low")
	appraiser := &Appraiser{
		SubmodPolicy: func(name string, c *Claims) error {
			if c.SecurityLevel < SecLevelSecureRestricted {
				return policyErr
			}
			return nil
		},
	}

	err := appraiser.Appraise(claims)
	if !errors.Is(err, policyErr) {
		t.Errorf("expected policyErr, got %v", err)
	}
}

func TestAppraiser_NestedTokenVerification(t *testing.T) {
	pub, priv := testKeyPair(t)
	signer, err := cose.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := cose.NewVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}

	subClaims := &Claims{
		SecurityLevel: SecLevelHardware,
	}
	nestedToken, err := Sign(subClaims, signer)
	if err != nil {
		t.Fatalf("Sign nested token failed: %v", err)
	}

	claims := testClaims()
	claims.Submods = map[string]Submod{
		"tpm": {Token: nestedToken},
	}

	var seenName string
	var seenLevel SecurityLevel
	appraiser := &Appraiser{
		SubmodVerifier: verifier,
		SubmodPolicy: func(name string, c *Claims) error {
			seenName = name
			seenLevel = c.SecurityLevel
			return nil
		},
	}

	if err := appraiser.Appraise(claims); err != nil {
		t.Fatalf("Appraise failed: %v", err)
	}
	if seenName != "tpm" {
		t.Errorf("SubmodPolicy name: got %q, want %q", seenName, "tpm")
	}
	if seenLevel != SecLevelHardware {
		t.Errorf("SubmodPolicy SecurityLevel: got %d, want %d", seenLevel, SecLevelHardware)
	}
}
