// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package psa exposes the claims of Arm's Platform Security
// Architecture (PSA) attestation token (RFC 9783) on top of an EAT
// decoded by package eat.
//
// A PSA token is an EAT: decode it with eat.Verify or eat.DecodeClaims,
// then lift the PSA claims with FromEAT. psa-software-components (2399)
// is the same data as eat.Claims.SWComponents.
package psa

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cwt"
	"github.com/jahkeup/corecbor/eat"
)

// PSA claim keys (RFC 9783 §10.1).
const (
	ClaimClientID                 int64 = 2394
	ClaimSecurityLifecycle        int64 = 2395
	ClaimImplementationID         int64 = 2396
	ClaimCertificationReference   int64 = 2398
	ClaimSoftwareComponents       int64 = 2399
	ClaimVerificationServiceIndic int64 = 2400
)

// Profile is the RFC 9783 §5.2 PSA TFM profile (eat_profile value).
const Profile = "tag:psacertified.org,2023:psa#tfm"

// Security lifecycle states (RFC 9783 §4.3.1): the high byte of
// psa-security-lifecycle; the low byte is implementation defined.
const (
	LifecycleUnknown                uint16 = 0x0000
	LifecycleAssemblyAndTest        uint16 = 0x1000
	LifecyclePSARoTProvisioning     uint16 = 0x2000
	LifecycleSecured                uint16 = 0x3000
	LifecycleNonPSARoTDebug         uint16 = 0x4000
	LifecycleRecoverablePSARoTDebug uint16 = 0x5000
	LifecycleDecommissioned         uint16 = 0x6000
)

// LifecycleState returns the state part of a psa-security-lifecycle
// value (its high byte).
func LifecycleState(v uint16) uint16 { return v & 0xff00 }

// ErrMalformedPSA indicates a PSA claim has the wrong type.
var ErrMalformedPSA = errors.New("psa: malformed claim")

// SoftwareComponent is an RFC 9783 psa-software-components entry. It is
// the same type as eat.SWComponent.
type SoftwareComponent = eat.SWComponent

// Claims is a PSA attestation token's claims: the EAT it is carried in,
// plus the PSA-specific claims. Pointer fields are nil when absent.
type Claims struct {
	*eat.Claims

	ClientID            *int64  // 2394
	SecurityLifecycle   *uint16 // 2395
	ImplementationID    []byte  // 2396
	CertificationRef    string  // 2398
	SoftwareComponents  []SoftwareComponent
	VerificationService string // 2400
}

// FromEAT lifts the PSA claims out of c's PrivateClaims (and
// SWComponents). c is referenced, not copied; ToEAT writes changes back.
func FromEAT(c *eat.Claims) (*Claims, error) {
	p := &Claims{Claims: c, SoftwareComponents: c.SWComponents}
	if v, ok := c.PrivateClaims[cwt.IntKey(ClaimClientID)]; ok {
		n, err := intOf(v, "psa-client-id")
		if err != nil {
			return nil, err
		}
		if n < math.MinInt32 || n > math.MaxInt32 {
			return nil, fmt.Errorf("%w: psa-client-id %d outside int32", ErrMalformedPSA, n)
		}
		p.ClientID = &n
	}
	if v, ok := c.PrivateClaims[cwt.IntKey(ClaimSecurityLifecycle)]; ok {
		if v.Kind != corecbor.KindUint || v.UintVal() > math.MaxUint16 {
			return nil, fmt.Errorf("%w: psa-security-lifecycle must be a uint16", ErrMalformedPSA)
		}
		l := uint16(v.UintVal())
		p.SecurityLifecycle = &l
	}
	if v, ok := c.PrivateClaims[cwt.IntKey(ClaimImplementationID)]; ok {
		if v.Kind != corecbor.KindBytes {
			return nil, fmt.Errorf("%w: psa-implementation-id must be bytes", ErrMalformedPSA)
		}
		p.ImplementationID = v.BytesVal()
	}
	if v, ok := c.PrivateClaims[cwt.IntKey(ClaimCertificationReference)]; ok {
		if v.Kind != corecbor.KindText {
			return nil, fmt.Errorf("%w: psa-certification-reference must be text", ErrMalformedPSA)
		}
		p.CertificationRef = v.TextVal()
	}
	if v, ok := c.PrivateClaims[cwt.IntKey(ClaimVerificationServiceIndic)]; ok {
		if v.Kind != corecbor.KindText {
			return nil, fmt.Errorf("%w: psa-verification-service-indicator must be text", ErrMalformedPSA)
		}
		p.VerificationService = v.TextVal()
	}
	return p, nil
}

// ToEAT writes the PSA claims into the embedded eat.Claims
// (PrivateClaims and SWComponents) and returns it, ready for
// eat.Sign or Encode.
func (p *Claims) ToEAT() *eat.Claims {
	c := p.Claims
	if c == nil {
		c = &eat.Claims{}
		p.Claims = c
	}
	set := func(k int64, v corecbor.Value, present bool) {
		if !present {
			delete(c.PrivateClaims, cwt.IntKey(k))
			return
		}
		if c.PrivateClaims == nil {
			c.PrivateClaims = make(map[cwt.ClaimKey]corecbor.Value)
		}
		c.PrivateClaims[cwt.IntKey(k)] = v
	}
	var cid corecbor.Value
	if p.ClientID != nil {
		cid = intValue(*p.ClientID)
	}
	set(ClaimClientID, cid, p.ClientID != nil)
	var lc corecbor.Value
	if p.SecurityLifecycle != nil {
		lc = corecbor.Uint(uint64(*p.SecurityLifecycle))
	}
	set(ClaimSecurityLifecycle, lc, p.SecurityLifecycle != nil)
	set(ClaimImplementationID, corecbor.Bytes(p.ImplementationID), p.ImplementationID != nil)
	set(ClaimCertificationReference, corecbor.Text(p.CertificationRef), p.CertificationRef != "")
	set(ClaimVerificationServiceIndic, corecbor.Text(p.VerificationService), p.VerificationService != "")
	c.SWComponents = p.SoftwareComponents
	return c
}

// ErrInvalidPSA indicates a PSA token that lacks a claim RFC 9783
// requires or carries one that breaks its rules. Validate returns it
// inside a *cwt.ClaimError for the claim.
var ErrInvalidPSA = errors.New("psa: invalid PSA attestation token")

// profileBase is the tag URI PSA profiles are fragments of (RFC 9783
// §4.5.2.1); Profile is the TFM one.
const profileBase = "tag:psacertified.org,2023:psa#"

var certRef = regexp.MustCompile(`^[0-9]{13}-[0-9]{5}$`)

// Validate checks p against the PSA profile (RFC 9783 §4, §5): it
// requires eat_profile to be Profile or another profile derived from the
// PSA tag URI (§4.5.2.1); exactly one nonce of 32, 48 or 64 bytes; a
// client ID; an instance ID (UEID) of 33 bytes starting 0x01; a 32-byte
// implementation ID; and a security lifecycle. A boot seed, when
// present, is 8..32 bytes; a certification reference matches
// "[0-9]{13}-[0-9]{5}"; each software component has a measurement value
// and signer ID of 32, 48 or 64 bytes. Run it with the EAT checks
// (eat.Claims.Validate, or eat.VerifyToken / eat.NewAppraiser); the
// token signature is the caller's to verify. Errors are *cwt.ClaimError
// wrapping ErrInvalidPSA.
func (p *Claims) Validate() error {
	c := p.Claims
	if c == nil {
		c = &eat.Claims{}
	}
	bad := func(k int64, format string, args ...any) error {
		return &cwt.ClaimError{Key: cwt.IntKey(k), Err: fmt.Errorf("%w: "+format, append([]any{ErrInvalidPSA}, args...)...)}
	}
	hashSize := func(b []byte) bool { return len(b) == 32 || len(b) == 48 || len(b) == 64 }
	switch {
	case !strings.HasPrefix(c.Profile, profileBase) || len(c.Profile) == len(profileBase):
		return bad(eat.ClaimProfile, "eat_profile %q is not a PSA profile (want %q)", c.Profile, Profile)
	case len(c.Nonce) != 1:
		return bad(eat.ClaimNonce, "exactly one nonce is required, got %d", len(c.Nonce))
	case !hashSize(c.Nonce[0]):
		return bad(eat.ClaimNonce, "nonce is %d bytes, want 32, 48 or 64", len(c.Nonce[0]))
	case p.ClientID == nil:
		return bad(ClaimClientID, "psa-client-id is required")
	case len(c.UEID) != 33 || c.UEID[0] != byte(eat.UEIDTypeRAND):
		return bad(eat.ClaimUEID, "instance ID must be 33 bytes starting 0x01, got %d bytes", len(c.UEID))
	case len(p.ImplementationID) != 32:
		return bad(ClaimImplementationID, "psa-implementation-id must be 32 bytes, got %d", len(p.ImplementationID))
	case p.SecurityLifecycle == nil:
		return bad(ClaimSecurityLifecycle, "psa-security-lifecycle is required")
	case c.BootSeed != nil && (len(c.BootSeed) < 8 || len(c.BootSeed) > 32):
		return bad(eat.ClaimBootSeed, "boot seed is %d bytes, want 8..32", len(c.BootSeed))
	case p.CertificationRef != "" && !certRef.MatchString(p.CertificationRef):
		return bad(ClaimCertificationReference, "psa-certification-reference %q does not match [0-9]{13}-[0-9]{5}", p.CertificationRef)
	}
	for i, sw := range p.SoftwareComponents {
		if !hashSize(sw.MeasurementValue) || !hashSize(sw.SignerID) {
			return bad(ClaimSoftwareComponents, "component %d: measurement value and signer ID must be 32, 48 or 64 bytes", i)
		}
	}
	return nil
}

func intOf(v corecbor.Value, what string) (int64, error) {
	n, err := v.Int64()
	if err != nil {
		return 0, fmt.Errorf("%w: %s must be an integer", ErrMalformedPSA, what)
	}
	return n, nil
}

func intValue(n int64) corecbor.Value {
	if n >= 0 {
		return corecbor.Uint(uint64(n))
	}
	return corecbor.NegInt(uint64(-1 - n))
}
