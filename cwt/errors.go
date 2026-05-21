package cwt

import "errors"

var (
	ErrTokenExpired        = errors.New("cwt: token has expired")
	ErrTokenNotYetValid    = errors.New("cwt: token not yet valid")
	ErrAudienceMismatch    = errors.New("cwt: audience mismatch")
	ErrMissingExpiration   = errors.New("cwt: missing required expiration")
	ErrMissingConfirmation = errors.New("cwt: missing required confirmation claim")
	ErrMalformedClaims     = errors.New("cwt: malformed claims")
)
