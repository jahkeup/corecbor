// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"errors"
	"fmt"
)

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

	// ErrAlgorithmMismatch indicates the message's alg header doesn't
	// match the key or caller-supplied algorithm, isn't allowed by
	// policy, isn't a supported identifier, or appears in both the
	// protected and unprotected buckets (RFC 9052 §3.1).
	ErrAlgorithmMismatch = errors.New("cose: header algorithm does not match key or policy")

	// ErrCriticalHeader indicates a crit header (RFC 9052 §3.1) that is
	// malformed, not in the protected bucket, lists a label absent from
	// the protected bucket, or lists a label the caller hasn't declared
	// it processes.
	ErrCriticalHeader = errors.New("cose: unprocessed critical header parameter")

	// ErrDuplicateLabel indicates a header label that appears more than
	// once in a bucket, or in both the protected and unprotected
	// buckets of one layer (RFC 9052 §3).
	ErrDuplicateLabel = errors.New("cose: header label present more than once")

	// ErrUnsupportedHeader indicates a header label or value whose Go
	// type has no CBOR encoding here. SetChecked returns it directly;
	// a value stored with Set surfaces it from the next Marshal*.
	ErrUnsupportedHeader = errors.New("cose: header value type not encodable")

	// ErrNonFiniteKeyParam indicates a COSE_Key parameter whose value is
	// or contains a NaN or infinite float. MarshalCBOR can't write one
	// (Core Deterministic encoding, RFC 9052 §9), so ParseKey rejects it
	// rather than return a key that can't be re-encoded. It is returned
	// inside a *KeyParamError and also wraps ErrMalformed.
	// KeepParamsAsReceived keeps such parameters instead.
	ErrNonFiniteKeyParam = errors.New("cose: non-finite float in key parameter")
)

// KeyParamError reports which COSE_Key parameter failed and why. Label
// is the parameter's label: an int64, or a string for a text label.
// Err wraps a cose sentinel such as ErrNonFiniteKeyParam.
type KeyParamError struct {
	Label any
	Err   error
}

func (e *KeyParamError) Error() string {
	if s, ok := e.Label.(string); ok {
		return fmt.Sprintf("key label %q: %v", s, e.Err)
	}
	return fmt.Sprintf("key label %v: %v", e.Label, e.Err)
}

func (e *KeyParamError) Unwrap() error { return e.Err }
