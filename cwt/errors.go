// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"errors"
	"fmt"
)

var (
	ErrTokenExpired        = errors.New("cwt: token has expired")
	ErrTokenNotYetValid    = errors.New("cwt: token not yet valid")
	ErrAudienceMismatch    = errors.New("cwt: audience mismatch")
	ErrMissingExpiration   = errors.New("cwt: missing required expiration")
	ErrMissingConfirmation = errors.New("cwt: missing required confirmation claim")
	ErrMalformedClaims     = errors.New("cwt: malformed claims")

	// ErrInvalidValidator indicates a Validator configured with values
	// that can't be applied, such as a negative Leeway, or a nil
	// *Validator.
	ErrInvalidValidator = errors.New("cwt: invalid validator configuration")

	// ErrIssuerMismatch indicates the iss claim is not one of
	// Validator.Issuers.
	ErrIssuerMismatch = errors.New("cwt: issuer not allowed")

	// ErrIssuedInFuture indicates an iat claim later than now plus the
	// validator's leeway.
	ErrIssuedInFuture = errors.New("cwt: token issued in the future")

	// ErrTokenTooOld indicates an iat claim older than Validator.MaxAge.
	ErrTokenTooOld = errors.New("cwt: token too old")

	// ErrMissingIssuedAt indicates a required iat claim is absent.
	ErrMissingIssuedAt = errors.New("cwt: missing required issued-at")

	// ErrUnexpectedType indicates a typ or cty header that does not
	// identify a CWT (RFC 9596, RFC 8392 §7).
	ErrUnexpectedType = errors.New("cwt: unexpected content type")

	// ErrKeyResolution indicates the key resolver failed or none was
	// configured.
	ErrKeyResolution = errors.New("cwt: key resolution failed")
)

// ClaimError reports which claim failed and why. Err wraps a cwt
// sentinel (usually ErrMalformedClaims) and, where applicable, the
// underlying corecbor or cose error.
type ClaimError struct {
	Key ClaimKey
	Err error
}

func (e *ClaimError) Error() string { return fmt.Sprintf("claim %s: %v", e.Key, e.Err) }

func (e *ClaimError) Unwrap() error { return e.Err }

// claimErr builds a *ClaimError for key whose Err wraps
// ErrMalformedClaims and, when cause is non-nil, cause.
func claimErr(key ClaimKey, what string, cause error) error {
	if cause != nil {
		return &ClaimError{Key: key, Err: fmt.Errorf("%w: %s: %w", ErrMalformedClaims, what, cause)}
	}
	return &ClaimError{Key: key, Err: fmt.Errorf("%w: %s", ErrMalformedClaims, what)}
}
