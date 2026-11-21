// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import "time"

type Validator struct {
	Audience string
	// Leeway is the clock-skew tolerance applied to exp and nbf. It must
	// not be negative; Validate returns ErrInvalidValidator if it is.
	Leeway              time.Duration
	Now                 func() time.Time
	RequireExpiration   bool
	RequireConfirmation bool
}

func (v *Validator) Validate(claims *ClaimsSet) error {
	if v.Leeway < 0 {
		// A negative tolerance would silently reject tokens that are
		// still within their validity window.
		return ErrInvalidValidator
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

	if !claims.Expiration.IsZero() {
		if now.After(claims.Expiration.Add(v.Leeway)) {
			return ErrTokenExpired
		}
	}

	if !claims.NotBefore.IsZero() {
		if now.Before(claims.NotBefore.Add(-v.Leeway)) {
			return ErrTokenNotYetValid
		}
	}

	if v.Audience != "" && claims.Audience != v.Audience {
		return ErrAudienceMismatch
	}

	return nil
}
