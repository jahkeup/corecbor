// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
)

// Appraiser evaluates EAT claims against a set of policy requirements.
//
// The zero value keeps v0.2.2's behavior (a nil CWTValidator skips CWT
// validation; no RFC 9711 value checks), except that submodules fail
// closed: a nested-token submodule reached by SubmodPolicy without
// SubmodVerifier or SubmodVerify returns ErrSubmodUnverified.
// NewAppraiser returns the recommended current-standards configuration.
type Appraiser struct {
	RequireNonce []byte
	// RequireSecurityLevel rejects claims whose SecurityLevel is below it.
	//
	// Deprecated: security level is not an RFC 9711 claim. Claims decoded
	// with RFC 9711 numbering never carry it, so a non-zero value fails
	// closed with ErrSecurityLevel; it is meaningful only for claims
	// decoded with WithLegacyDraftClaimKeys.
	RequireSecurityLevel SecurityLevel
	RequireSecureBoot    bool
	// RequireDebugDisabled rejects DebugEnabled (dbgstat 0, or absent),
	// as in v0.2.2. Use MinDebugStatus to also reject unknown values.
	RequireDebugDisabled bool
	RequireProfile       string
	SWComponentPolicy    func([]SWComponent) error
	CWTValidator         *cwt.Validator
	Custom               []func(*Claims) error
	SubmodPolicy         func(name string, claims *Claims) error
	SubmodVerifier       *cose.Verifier

	// NonceVerifier, when set, is called with the token's nonces.
	NonceVerifier func(nonces [][]byte) error
	// MinDebugStatus, when set, requires dbgstat to be present, known
	// (0..4, else ErrUnknownDebugStatus) and at least this value (else
	// ErrDebugStatus).
	MinDebugStatus *DebugStatus
	// RequireProfileOID requires eat_profile in OID form equal to it.
	RequireProfileOID []byte
	// ValidateValues runs Claims.Validate (RFC 9711 value constraints).
	ValidateValues bool
	// SubmodVerify verifies a nested-token submodule (CBOR token bytes,
	// or the JSON-Selector text of a nested JSON token) and returns its
	// claims for SubmodPolicy. It is used instead of SubmodVerifier when
	// both are set.
	SubmodVerify func(ctx context.Context, name string, token []byte) (*Claims, error)
	// SubmodDetached checks a detached submodule digest, typically
	// against a detached claims set from a DetachedBundle. Without it a
	// detached submodule reached by SubmodPolicy fails closed.
	SubmodDetached func(ctx context.Context, name string, d DetachedDigest) error
	// MeasurementPolicy, when set, is called with the measurements claim.
	MeasurementPolicy func(ms []TypedBytes) error
}

// NewAppraiser returns an Appraiser with current-standards defaults:
// CWTValidator = cwt.NewValidator() (exp required, iat not in the
// future) and ValidateValues = true. It is the recommended constructor;
// the zero value keeps v0.2.2 behavior.
func NewAppraiser() *Appraiser {
	return &Appraiser{CWTValidator: cwt.NewValidator(), ValidateValues: true}
}

// Appraise checks the claims against all configured policy requirements.
//
// Submodules are appraised only when SubmodPolicy is set; then a nested
// token that cannot be verified is rejected. Without a SubmodPolicy,
// claims.Submods is left unexamined: do not treat its contents as
// verified after Appraise returns.
func (a *Appraiser) Appraise(claims *Claims) error {
	return a.AppraiseContext(context.Background(), claims)
}

// AppraiseContext is Appraise with a context for the SubmodVerify and
// SubmodDetached callbacks.
func (a *Appraiser) AppraiseContext(ctx context.Context, claims *Claims) error {
	if len(a.RequireNonce) > 0 && !nonceMatches(claims.Nonce, a.RequireNonce) {
		return ErrNonceMismatch
	}
	if a.NonceVerifier != nil {
		if err := a.NonceVerifier(claims.Nonce); err != nil {
			return err
		}
	}

	if a.RequireSecurityLevel > 0 && claims.SecurityLevel < a.RequireSecurityLevel {
		return ErrSecurityLevel
	}

	if a.RequireSecureBoot && (claims.SecureBoot == nil || !*claims.SecureBoot) {
		return ErrSecureBootRequired
	}

	d, present := claims.debugStatus()
	if a.RequireDebugDisabled && d == DebugEnabled {
		return ErrDebugEnabled
	}
	if a.MinDebugStatus != nil {
		switch {
		case !present || d < DebugEnabled || d > DebugDisabledFullyAndPermanently:
			return fmt.Errorf("%w: %d", ErrUnknownDebugStatus, d)
		case d < *a.MinDebugStatus:
			return fmt.Errorf("%w: %d < %d", ErrDebugStatus, d, *a.MinDebugStatus)
		}
	}

	if a.RequireProfile != "" && claims.Profile != a.RequireProfile {
		return ErrProfileMismatch
	}
	if a.RequireProfileOID != nil && !bytes.Equal(claims.ProfileOID, a.RequireProfileOID) {
		return ErrProfileMismatch
	}

	if a.ValidateValues {
		if err := claims.Validate(); err != nil {
			return err
		}
	}

	if a.SWComponentPolicy != nil && len(claims.SWComponents) > 0 {
		if err := a.SWComponentPolicy(claims.SWComponents); err != nil {
			return err
		}
	}
	if a.MeasurementPolicy != nil && len(claims.Measurements) > 0 {
		if err := a.MeasurementPolicy(claims.Measurements); err != nil {
			return err
		}
	}

	if a.CWTValidator != nil {
		if err := a.CWTValidator.Validate(&claims.ClaimsSet); err != nil {
			return err
		}
	}

	for _, fn := range a.Custom {
		if err := fn(claims); err != nil {
			return err
		}
	}

	if a.SubmodPolicy != nil {
		for _, name := range sortedSubmodNames(claims.Submods) {
			if err := a.appraiseSubmod(ctx, name, claims.Submods[name]); err != nil {
				return fmt.Errorf("submods[%q]: %w", name, err)
			}
		}
	}

	return nil
}

func (a *Appraiser) appraiseSubmod(ctx context.Context, name string, sub Submod) error {
	var subClaims *Claims
	switch {
	case sub.Claims != nil:
		subClaims = sub.Claims
	case sub.Token != nil || sub.JSON != nil:
		tok := sub.Token
		if tok == nil {
			tok = sub.JSON
		}
		var err error
		switch {
		case a.SubmodVerify != nil:
			subClaims, err = a.SubmodVerify(ctx, name, tok)
		case a.SubmodVerifier != nil && sub.Token != nil:
			subClaims, err = Verify(sub.Token, a.SubmodVerifier)
		default:
			return ErrSubmodUnverified
		}
		if err != nil {
			return err
		}
	case sub.Detached != nil:
		if a.SubmodDetached == nil {
			return ErrSubmodUnverified
		}
		return a.SubmodDetached(ctx, name, *sub.Detached)
	}
	if subClaims == nil {
		return nil
	}
	return a.SubmodPolicy(name, subClaims)
}

func nonceMatches(nonces [][]byte, expected []byte) bool {
	for _, n := range nonces {
		if subtle.ConstantTimeCompare(n, expected) == 1 {
			return true
		}
	}
	return false
}
