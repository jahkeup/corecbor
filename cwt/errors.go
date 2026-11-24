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

	// ErrAmbiguousClaimKey indicates a claim key that encoding would
	// turn into a different key: a bignum (tag 2/3) whose value fits a
	// CBOR integer, which deterministic encoding writes as that integer
	// (bignum 1 as iss). It is returned inside a *ClaimError whose
	// Key.Raw holds the key's bytes as received, and also wraps
	// ErrMalformedClaims; DecodeOptions.KeepAsReceived keeps such
	// claims instead. eat returns it the same way; for a key inside
	// an EAT submodule that *ClaimError is wrapped in the one for the
	// submods claim, so follow ClaimError.Err to the innermost.
	ErrAmbiguousClaimKey = errors.New("cwt: ambiguous claim key")

	// ErrNonCanonicalNaN indicates a claim whose key or value holds a
	// NaN other than the quiet NaN f97e00: one with a payload or the
	// sign bit set. Core Deterministic encoding writes every NaN as
	// f97e00, so Encode would change it. It is returned inside a
	// *ClaimError naming the claim and also wraps ErrMalformedClaims;
	// DecodeOptions.KeepAsReceived keeps such claims instead. eat
	// returns it the same way. Encode returns it too for a value a
	// caller set; note that Go's math.NaN() has a payload bit set (it
	// is 0x7ff8000000000001), while math.Float64frombits(0x7ff8000000000000)
	// is the quiet NaN.
	ErrNonCanonicalNaN = errors.New("cwt: NaN payload would not survive encoding")

	// ErrSymmetricKeyNotEncrypted indicates a cnf claim carrying a
	// symmetric COSE_Key by value (member 1) in a CWT that is not
	// encrypted. RFC 8747 §3.2 allows that only in an encrypted CWT;
	// otherwise the key must be an Encrypted_COSE_Key (member 2,
	// Confirmation.EncryptedKey). Sign, MAC, SetClaimsHeader and the
	// signed and MACed verifying entry points return it inside a
	// *ClaimError for cnf; Seal, Encrypt, OpenToken and Decrypt accept
	// such a key.
	ErrSymmetricKeyNotEncrypted = errors.New("cwt: symmetric cnf key in an unencrypted CWT")
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
