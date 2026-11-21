// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math"

	"github.com/jahkeup/corecbor/cose/internal/aeskw"
)

const (
	headerLabelPBES2Count int64 = -21

	defaultPBES2Count    = 10000
	defaultPBES2SaltLen  = 16
	defaultPBES2MaxCount = 1_000_000
)

// PBES2Key derives a key-encryption key from a password with PBKDF2.
type PBES2Key struct {
	Password []byte
	Salt     []byte
	Count    int
	// MaxCount bounds the iteration count UnwrapKey accepts from a
	// message's headers, since the sender chooses it. 0 means 1,000,000.
	// A negative value disables the bound, which lets any sender force
	// unbounded work; only use it for trusted input.
	MaxCount int
}

func (p *PBES2Key) Algorithm() Algorithm { return AlgPBES2_HS256_A128KW }

func (p *PBES2Key) WrapKey(cek []byte, _ KeyWrapOpts) ([]byte, Headers, error) {
	salt := p.Salt
	if salt == nil {
		salt = make([]byte, defaultPBES2SaltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, Headers{}, fmt.Errorf("%w: generating salt: %v", ErrInvalidKey, err)
		}
	}

	count := p.Count
	if count == 0 {
		count = defaultPBES2Count
	}

	kek, err := pbkdf2.Key(sha256.New, string(p.Password), salt, count, 16)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: PBKDF2: %v", ErrInvalidKey, err)
	}

	wrapped, err := aeskw.Wrap(kek, cek)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}

	var h Headers
	h.Set(headerLabelSalt, salt)
	h.Set(headerLabelPBES2Count, int64(count))
	return wrapped, h, nil
}

func (p *PBES2Key) UnwrapKey(ciphertext []byte, h Headers, _ KeyUnwrapOpts) ([]byte, error) {
	salt, ok := h.Get(headerLabelSalt).([]byte)
	if !ok || len(salt) == 0 {
		return nil, fmt.Errorf("%w: missing PBES2 salt in headers", ErrDecryption)
	}

	countVal := h.Get(headerLabelPBES2Count)
	var count int64
	switch c := countVal.(type) {
	case int64:
		count = c
	case int:
		count = int64(c)
	default:
		return nil, fmt.Errorf("%w: missing PBES2 count in headers", ErrDecryption)
	}
	maxCount := int64(p.MaxCount)
	if maxCount == 0 {
		maxCount = defaultPBES2MaxCount
	}
	if count <= 0 || (maxCount > 0 && count > maxCount) || count > math.MaxInt32 {
		return nil, fmt.Errorf("%w: PBES2 count %d out of range", ErrDecryption, count)
	}

	kek, err := pbkdf2.Key(sha256.New, string(p.Password), salt, int(count), 16)
	if err != nil {
		return nil, fmt.Errorf("%w: PBKDF2: %v", ErrDecryption, err)
	}

	cek, kerr := aeskw.Unwrap(kek, ciphertext)
	if kerr != nil {
		return nil, ErrDecryption
	}
	return cek, nil
}
