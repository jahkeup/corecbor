package cwt

import "errors"

var (
	// ErrTokenExpired indicates the token's expiration time has passed.
	ErrTokenExpired = errors.New("cwt: token has expired")

	// ErrTokenNotYetValid indicates the token's not-before time has not yet arrived.
	ErrTokenNotYetValid = errors.New("cwt: token not yet valid")

	// ErrAudienceMismatch indicates the token's audience does not match the expected value.
	ErrAudienceMismatch = errors.New("cwt: audience mismatch")

	// ErrMissingExpiration indicates a required expiration claim is absent.
	ErrMissingExpiration = errors.New("cwt: missing required expiration")

	// ErrMalformedClaims indicates the claims payload could not be decoded.
	ErrMalformedClaims = errors.New("cwt: malformed claims")
)
