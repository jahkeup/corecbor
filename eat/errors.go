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

	// ErrSubmodUnverified indicates a nested-token or detached submodule
	// was reached by submodule appraisal without a way to verify it
	// (RFC 9711 §4.2.18). Appraisal fails closed.
	ErrSubmodUnverified = errors.New("eat: submodule not verified")

	// ErrInvalidUEID indicates a UEID (or SUEID) violates RFC 9711 §4.2.1:
	// unknown type byte or a length outside the type's rules.
	ErrInvalidUEID = errors.New("eat: invalid UEID")

	// ErrInvalidNonce indicates a nonce outside RFC 9711 §4.1's 8..64 bytes.
	ErrInvalidNonce = errors.New("eat: invalid nonce")

	// ErrDebugStatus indicates the debug status is below the required minimum.
	ErrDebugStatus = errors.New("eat: debug status below minimum")

	// ErrUnknownDebugStatus indicates a dbgstat value outside RFC 9711
	// §4.2.9's 0..4.
	ErrUnknownDebugStatus = errors.New("eat: unknown debug status")

	// ErrInvalidProfile indicates an eat_profile that is neither an
	// absolute URI nor a well-formed OID (RFC 9711 §4.3.2), or both forms
	// set at once.
	ErrInvalidProfile = errors.New("eat: invalid eat_profile")

	// ErrClaimNumbering indicates a claim that cannot be represented in
	// the selected claim numbering: an RFC 9711-only claim under
	// WithLegacyDraftClaimKeys, or SecurityLevel (dropped from RFC 9711)
	// without it.
	ErrClaimNumbering = errors.New("eat: claim not representable in the selected claim numbering")

	// ErrInvalidClaimValue indicates a claim whose value, size or
	// presence violates RFC 9711 in a way the other sentinels don't
	// name: an oemid or hwmodel of the wrong size, a claim present
	// without the one it depends on (hwmodel needs oemid, and so on), a
	// manifest or measurement not identified by a CoAP Content-Format,
	// or an out-of-range measurement result. Claims.Validate returns it
	// inside a *cwt.ClaimError for the claim.
	ErrInvalidClaimValue = errors.New("eat: invalid claim value")
)
