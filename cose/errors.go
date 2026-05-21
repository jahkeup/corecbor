package cose

import "errors"

var (
	ErrVerification         = errors.New("cose: verification failed")
	ErrInvalidKey           = errors.New("cose: invalid key for algorithm")
	ErrUnsupportedAlgorithm = errors.New("cose: unsupported algorithm")
	ErrMalformed            = errors.New("cose: malformed message")
	ErrDecryption           = errors.New("cose: decryption failed")
	ErrMACVerification      = errors.New("cose: MAC verification failed")
)
