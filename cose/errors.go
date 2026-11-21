// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import "errors"

var (
	ErrVerification         = errors.New("cose: verification failed")
	ErrInvalidKey           = errors.New("cose: invalid key for algorithm")
	ErrUnsupportedAlgorithm = errors.New("cose: unsupported algorithm")
	ErrMalformed            = errors.New("cose: malformed message")
	ErrDecryption           = errors.New("cose: decryption failed")
	ErrMACVerification      = errors.New("cose: MAC verification failed")

	// ErrMissingPayload indicates a message with a detached (nil)
	// payload was verified without supplying the payload.
	ErrMissingPayload = errors.New("cose: payload is detached and none was supplied")
)
