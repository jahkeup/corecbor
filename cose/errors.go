package cose

import "errors"

var (
	// ErrVerification is returned when signature verification fails.
	ErrVerification = errors.New("cose: verification failed")

	// ErrInvalidKey is returned when a key is not valid for the specified algorithm.
	ErrInvalidKey = errors.New("cose: invalid key for algorithm")

	// ErrUnsupportedAlgorithm is returned for unrecognized or unsupported algorithms.
	ErrUnsupportedAlgorithm = errors.New("cose: unsupported algorithm")

	// ErrMalformed is returned when a COSE message cannot be parsed.
	ErrMalformed = errors.New("cose: malformed message")
)
