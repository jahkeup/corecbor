package cose

import (
	"fmt"

	"github.com/jahkeup/corecbor/cose/internal/aeskw"
)

type AESKWKey struct {
	Key []byte
}

func (a *AESKWKey) Algorithm() Algorithm {
	switch len(a.Key) {
	case 16:
		return AlgA128KW
	case 24:
		return AlgA192KW
	case 32:
		return AlgA256KW
	default:
		return 0
	}
}

func (a *AESKWKey) WrapKey(cek []byte, opts KeyWrapOpts) ([]byte, Headers, error) {
	if err := a.validateKeyLen(); err != nil {
		return nil, Headers{}, err
	}
	wrapped, err := aeskw.Wrap(a.Key, cek)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return wrapped, Headers{}, nil
}

func (a *AESKWKey) UnwrapKey(ciphertext []byte, _ Headers, _ KeyUnwrapOpts) ([]byte, error) {
	if err := a.validateKeyLen(); err != nil {
		return nil, err
	}
	cek, err := aeskw.Unwrap(a.Key, ciphertext)
	if err != nil {
		return nil, ErrDecryption
	}
	return cek, nil
}

func (a *AESKWKey) validateKeyLen() error {
	switch len(a.Key) {
	case 16, 24, 32:
		return nil
	default:
		return fmt.Errorf("%w: AES-KW key must be 16, 24, or 32 bytes, got %d", ErrInvalidKey, len(a.Key))
	}
}
