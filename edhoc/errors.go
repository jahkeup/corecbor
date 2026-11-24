// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import "errors"

var (
	ErrAuthentication   = errors.New("edhoc: authentication failed")
	ErrMessageFormat    = errors.New("edhoc: malformed message")
	ErrStateViolation   = errors.New("edhoc: operation not valid in current state")
	ErrUnsupportedSuite = errors.New("edhoc: unsupported cipher suite")

	// ErrCredentialRejected wraps an error from a CredentialResolver
	// (Peers). Such errors also match ErrAuthentication.
	ErrCredentialRejected = errors.New("edhoc: peer credential rejected")
	// ErrConnectionIDCollision means C_I and C_R are equal, which RFC
	// 9528 §3.3 forbids. Also matches ErrMessageFormat.
	ErrConnectionIDCollision = errors.New("edhoc: connection identifiers collide")
	// ErrCriticalEAD means a critical EAD item was not accepted (RFC 9528
	// §3.8). Also matches ErrAuthentication.
	ErrCriticalEAD = errors.New("edhoc: unsupported critical EAD item")
	// ErrUnknownCredential means the peer's ID_CRED referenced (by kid
	// or x5t) a credential this party does not have; ErrorMessageFor
	// answers it with ERR_CODE 3 (RFC 9528 §6). Returned wrapped in
	// ErrAuthentication. A CredentialResolver may wrap it in its own
	// error to signal the same.
	ErrUnknownCredential = errors.New("edhoc: unknown credential referenced")
)
