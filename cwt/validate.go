// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"slices"
	"time"
)

// Validator checks a ClaimsSet's time and audience claims. The zero
// value keeps its v0.2.2 behavior (exp optional, iat unchecked); use
// NewValidator for current-standards defaults. Fields added after
// v0.2.2 change nothing at their zero value.
type Validator struct {
	// Audience, when set, must be the aud claim or one of its elements.
	Audience string
	// Leeway is the clock-skew tolerance applied to exp, nbf and iat. It
	// must not be negative; Validate returns ErrInvalidValidator if it is.
	Leeway              time.Duration
	Now                 func() time.Time
	RequireExpiration   bool
	RequireConfirmation bool

	// Issuers, when non-empty, lists the accepted iss values.
	Issuers []string
	// MaxAge, when positive, rejects tokens whose iat is older than
	// MaxAge (plus Leeway) with ErrTokenTooOld, and requires iat.
	MaxAge time.Duration
	// RequireIssuedAt requires the iat claim.
	RequireIssuedAt bool
	// RejectFutureIssuedAt rejects an iat later than now plus Leeway with
	// ErrIssuedInFuture.
	RejectFutureIssuedAt bool
}

// NewValidator returns a Validator with current-standards defaults:
// exp required, iat in the future rejected, and a 60-second Leeway. It
// is the recommended way to build a Validator; the zero value keeps
// v0.2.2 behavior.
func NewValidator() *Validator {
	return &Validator{
		Leeway:               60 * time.Second,
		RequireExpiration:    true,
		RejectFutureIssuedAt: true,
	}
}

// Validate checks claims against v. A token is rejected on or after its
// exp (RFC 8392 §3.1.4 via RFC 7519 §4.1.4), before its nbf, and per the
// optional checks configured on v. Calling Validate on a nil *Validator
// returns ErrInvalidValidator.
func (v *Validator) Validate(claims *ClaimsSet) error {
	if v == nil {
		return ErrInvalidValidator
	}
	if v.Leeway < 0 {
		// A negative tolerance would silently reject tokens that are
		// still within their validity window.
		return ErrInvalidValidator
	}
	if claims == nil {
		return ErrMalformedClaims
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}

	if v.RequireExpiration && claims.Expiration.IsZero() {
		return ErrMissingExpiration
	}

	if v.RequireConfirmation && claims.Confirmation == nil {
		return ErrMissingConfirmation
	}

	if (v.RequireIssuedAt || v.MaxAge > 0) && claims.IssuedAt.IsZero() {
		return ErrMissingIssuedAt
	}

	if !claims.Expiration.IsZero() {
		if !now.Before(claims.Expiration.Add(v.Leeway)) {
			return ErrTokenExpired
		}
	}

	if !claims.NotBefore.IsZero() {
		if now.Before(claims.NotBefore.Add(-v.Leeway)) {
			return ErrTokenNotYetValid
		}
	}

	if !claims.IssuedAt.IsZero() {
		if v.RejectFutureIssuedAt && claims.IssuedAt.After(now.Add(v.Leeway)) {
			return ErrIssuedInFuture
		}
		if v.MaxAge > 0 && claims.IssuedAt.Before(now.Add(-v.MaxAge-v.Leeway)) {
			return ErrTokenTooOld
		}
	}

	if len(v.Issuers) > 0 && !slices.Contains(v.Issuers, claims.Issuer) {
		return ErrIssuerMismatch
	}

	if v.Audience != "" && !claims.ContainsAudience(v.Audience) {
		return ErrAudienceMismatch
	}

	return nil
}
