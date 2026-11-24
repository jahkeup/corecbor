// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"fmt"
	"slices"
	"time"
)

// Validator checks a ClaimsSet's time and audience claims. The zero
// value keeps its v0.2.2 behavior (exp optional, iat unchecked) except
// for the audience check: a token carrying aud is rejected unless the
// Validator accepts one of its audiences (RFC 7519 §4.1.3; v0.2.2
// accepted any aud when Audience was unset, a fail-open defect fixed
// under proposal 034). Use NewValidator for current-standards defaults.
// Other fields added after v0.2.2 change nothing at their zero value.
type Validator struct {
	// Audience, when set, is an audience this processor identifies
	// with: the token's aud claim must be it or contain it. Audiences
	// adds more.
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

	// Audiences lists further audiences this processor identifies with,
	// besides Audience. When either is set, the token must carry an aud
	// that is, or contains, one of them; when neither is, a token
	// carrying any aud is rejected (RFC 7519 §4.1.3). Failures are a
	// *ClaimError for aud wrapping ErrAudienceMismatch.
	Audiences []string

	// IgnoreAudience skips the aud check, for applications that don't
	// use aud: a token's aud is then not evaluated at all. Set it only
	// when audience restriction is enforced some other way. Combining
	// it with Audience or Audiences is ErrInvalidValidator.
	IgnoreAudience bool
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
	if v.IgnoreAudience && (v.Audience != "" || len(v.Audiences) > 0) {
		return fmt.Errorf("%w: IgnoreAudience with Audience or Audiences set", ErrInvalidValidator)
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

	return v.validateAudience(claims)
}

// validateAudience applies RFC 7519 §4.1.3: a token whose aud the
// processor doesn't identify with is rejected.
func (v *Validator) validateAudience(claims *ClaimsSet) error {
	if v.IgnoreAudience {
		return nil
	}
	if v.Audience == "" && len(v.Audiences) == 0 {
		if claims.Audience != "" || len(claims.Audiences) > 0 {
			return &ClaimError{Key: IntKey(ClaimAud), Err: fmt.Errorf(
				"%w: token carries aud but the validator accepts no audience (set Audience or Audiences, or IgnoreAudience)",
				ErrAudienceMismatch)}
		}
		return nil
	}
	if v.Audience != "" && claims.ContainsAudience(v.Audience) {
		return nil
	}
	for _, a := range v.Audiences {
		if claims.ContainsAudience(a) {
			return nil
		}
	}
	return &ClaimError{Key: IntKey(ClaimAud), Err: ErrAudienceMismatch}
}
