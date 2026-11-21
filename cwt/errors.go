// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import "errors"

var (
	ErrTokenExpired        = errors.New("cwt: token has expired")
	ErrTokenNotYetValid    = errors.New("cwt: token not yet valid")
	ErrAudienceMismatch    = errors.New("cwt: audience mismatch")
	ErrMissingExpiration   = errors.New("cwt: missing required expiration")
	ErrMissingConfirmation = errors.New("cwt: missing required confirmation claim")
	ErrMalformedClaims     = errors.New("cwt: malformed claims")

	// ErrInvalidValidator indicates a Validator configured with values
	// that can't be applied, such as a negative Leeway.
	ErrInvalidValidator = errors.New("cwt: invalid validator configuration")
)
