// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import "fmt"

type KeyDeriver interface {
	Algorithm() Algorithm
	WrapKey(cek []byte, opts KeyWrapOpts) (ciphertext []byte, headers Headers, err error)
	UnwrapKey(ciphertext []byte, headers Headers, opts KeyUnwrapOpts) (cek []byte, err error)
}

type KeyWrapOpts struct {
	CEKAlgorithm Algorithm
	CEKLength    int
}

type KeyUnwrapOpts struct {
	CEKAlgorithm Algorithm
	CEKLength    int
}

type DirectKey struct {
	Key []byte
}

func (d *DirectKey) Algorithm() Algorithm { return AlgDirect }

func (d *DirectKey) WrapKey(cek []byte, opts KeyWrapOpts) ([]byte, Headers, error) {
	if opts.CEKLength > 0 && len(d.Key) != opts.CEKLength {
		return nil, Headers{}, fmt.Errorf("%w: direct key length %d does not match CEK length %d", ErrInvalidKey, len(d.Key), opts.CEKLength)
	}
	return nil, Headers{}, nil
}

func (d *DirectKey) UnwrapKey(_ []byte, _ Headers, opts KeyUnwrapOpts) ([]byte, error) {
	if opts.CEKLength > 0 && len(d.Key) != opts.CEKLength {
		return nil, fmt.Errorf("%w: direct key length %d does not match CEK length %d", ErrInvalidKey, len(d.Key), opts.CEKLength)
	}
	result := make([]byte, len(d.Key))
	copy(result, d.Key)
	return result, nil
}
