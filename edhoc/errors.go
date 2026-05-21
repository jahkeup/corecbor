// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import "errors"

var (
	ErrAuthentication   = errors.New("edhoc: authentication failed")
	ErrMessageFormat    = errors.New("edhoc: malformed message")
	ErrStateViolation   = errors.New("edhoc: operation not valid in current state")
	ErrUnsupportedSuite = errors.New("edhoc: unsupported cipher suite")
)
