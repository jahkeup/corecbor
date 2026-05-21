// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

import "errors"

var (
	// ErrNonceMismatch indicates the token nonce does not match the expected value.
	ErrNonceMismatch = errors.New("eat: nonce mismatch")

	// ErrSecurityLevel indicates the token security level is below the minimum required.
	ErrSecurityLevel = errors.New("eat: security level below minimum")

	// ErrSecureBootRequired indicates secure boot is not active but is required.
	ErrSecureBootRequired = errors.New("eat: secure boot not active")

	// ErrDebugEnabled indicates debug facilities are enabled but must be disabled.
	ErrDebugEnabled = errors.New("eat: debug facilities enabled")

	// ErrMalformedEAT indicates the token payload could not be decoded as an EAT.
	ErrMalformedEAT = errors.New("eat: malformed token")

	// ErrProfileMismatch indicates the token profile does not match the required profile.
	ErrProfileMismatch = errors.New("eat: profile mismatch")
)
