package cwt

import "time"

// Validator checks temporal and audience claims on a ClaimsSet.
type Validator struct {
	Audience          string
	Leeway            time.Duration
	Now               func() time.Time
	RequireExpiration bool
}

// Validate checks the claims against the validator's rules.
func (v *Validator) Validate(claims *ClaimsSet) error {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}

	if v.RequireExpiration && claims.Expiration.IsZero() {
		return ErrMissingExpiration
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
