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

	// Options are the decoding options (WithLegacyDraftClaimKeys,
	// WithKeepAsReceived) for nested tokens SubmodVerifier verifies;
	// pass the ones the enclosing token was decoded with.
	Options []Option
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
//
// With a SubmodPolicy, every level is appraised (RFC 9711 §4.2.18): the
// submodules of an inline submodule and of a verified nested token are
// passed to SubmodPolicy in turn, under their own names, and fail
// closed the same way, down to 16 levels (deeper is ErrMalformedEAT).
// A nested token verified with SubmodVerifier is decoded with
// cose.RecommendedDecodeLimits and Options, and validated like the
// enclosing token: CWTValidator (when set) and, with ValidateValues,
// Claims.Validate. Claims returned by SubmodVerify are the callback's
// responsibility (VerifyToken validates them).
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
		if err := a.appraiseSubmods(ctx, claims, 0); err != nil {
			return err
		}
	}

	return nil
}

// appraiseSubmods appraises every submodule of c, recursing into the
// submodules of inline submodules and verified nested tokens.
func (a *Appraiser) appraiseSubmods(ctx context.Context, c *Claims, depth int) error {
	if len(c.Submods) == 0 {
		return nil
	}
	if depth >= maxSubmodDepth {
		return fmt.Errorf("%w: submodules nested deeper than %d", ErrMalformedEAT, maxSubmodDepth)
	}
	for _, name := range sortedSubmodNames(c.Submods) {
		if err := a.appraiseSubmod(ctx, name, c.Submods[name], depth); err != nil {
			return fmt.Errorf("submods[%q]: %w", name, err)
		}
	}
	return nil
}

func (a *Appraiser) appraiseSubmod(ctx context.Context, name string, sub Submod, depth int) error {
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
			subClaims, err = a.verifyNested(sub.Token)
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
	if err := a.SubmodPolicy(name, subClaims); err != nil {
		return err
	}
	return a.appraiseSubmods(ctx, subClaims, depth+1)
}

// verifyNested verifies a nested-token submodule with SubmodVerifier:
// bounded envelope, typ check, signature, claims decoded with Options,
// no exposed symmetric key, then the appraiser's own validation.
func (a *Appraiser) verifyNested(data []byte) (*Claims, error) {
	inner, _, err := unwrapCWT(data)
	if err != nil {
		return nil, err
	}
	msg, err := cose.UnmarshalSign1With(inner, tokenDecodeLimits)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedEAT, err)
	}
	nested, err := checkTokenTypes(&msg.Protected, &msg.Unprotected)
	if err != nil {
		return nil, err
	}
	if err := a.SubmodVerifier.Verify(msg); err != nil {
		return nil, err
	}
	if nested || startsWithTag(msg.Payload) {
		// Its inner token is signed by some other key; SubmodVerify
		// can resolve it.
		return nil, fmt.Errorf("%w: a nested token that wraps another token needs SubmodVerify", ErrSubmodUnverified)
	}
	claims, err := DecodeClaims(msg.Payload, a.Options...)
	if err != nil {
		return nil, err
	}
	if err := checkNotExposed(claims, 0); err != nil {
		return nil, err
	}
	if a.CWTValidator != nil {
		if err := a.CWTValidator.Validate(&claims.ClaimsSet); err != nil {
			return nil, err
		}
	}
	if a.ValidateValues {
		if err := claims.Validate(); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

func nonceMatches(nonces [][]byte, expected []byte) bool {
	for _, n := range nonces {
		if subtle.ConstantTimeCompare(n, expected) == 1 {
			return true
		}
	}
	return false
}
