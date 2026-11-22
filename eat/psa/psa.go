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
