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
	// headerLabelPBES2Count carries the PBKDF2 iteration count. PBES2 is
	// not registered for COSE, so it lives in the private-use range
	// (< -65536), like AlgPrivatePBES2_HS256_A128KW.
	headerLabelPBES2Count int64 = -65602

	// headerLabelLegacyPBES2Count is v0.2's iteration-count label. IANA
	// registers -21 as PartyU identity; used only under
	// WithLegacyPBES2Labels.
	headerLabelLegacyPBES2Count int64 = -21

	// defaultPBES2Count is the iteration count WrapKey uses when Count
	// is 0: OWASP's current figure for PBKDF2-HMAC-SHA256 (v0.2 used
	// 10,000).
	defaultPBES2Count    = 600_000
	defaultPBES2SaltLen  = 16
	defaultPBES2MaxCount = 1_000_000

	// minPBES2Count is the floor on the iteration count for sealing and
	// opening: RFC 7518 §4.8.1.2 and NIST SP 800-132 §5.2 put the
	// minimum at 1,000.
	minPBES2Count = 1000
	// minPBES2SealSalt is the shortest salt WrapKey accepts: 128 bits,
	// as NIST SP 800-132 §5.1 requires.
	minPBES2SealSalt = 16
	// minPBES2OpenSalt is the shortest salt UnwrapKey accepts: the
	// RFC 7518 §4.8.1.1 minimum of 8 octets.
	minPBES2OpenSalt = 8
)

// PBES2Key derives a key-encryption key from a password with PBKDF2
// (PBES2-HS256+A128KW). PBES2 is a JOSE algorithm that COSE doesn't
// register, so it uses the private-use identifier
// AlgPrivatePBES2_HS256_A128KW and a private-use iteration-count label;
// only corecbor peers understand it. v0.2 used -11 and -21, which IANA
// registers for other algorithms; WithLegacyPBES2Labels restores them.
//
// WrapKey requires a non-empty Password, a Salt of at least 16 bytes
// (nil: 16 random bytes) and a Count of at least 1,000 (0: 600,000).
// UnwrapKey requires a non-empty Password, a salt of at least 8 bytes
// and a count of at least 1,000 in the message, and at most MaxCount.
// Otherwise they return ErrInvalidKey and ErrDecryption.
type PBES2Key struct {
	Password []byte
	Salt     []byte
	Count    int
	// MaxCount bounds the iteration count UnwrapKey accepts from a
	// message's headers, since the sender chooses it. 0 means 1,000,000.
	// A negative value disables the bound, which lets any sender force
	// unbounded work; only use it for trusted input.
	MaxCount int
	// InsecureAllowWeakParams lets UnwrapKey open a message whose
	// iteration count is below 1,000 or whose salt is shorter than 8
	// bytes, or use an empty Password, as v0.2 did. Such messages offer
	// little protection against password guessing; use it only to read
	// old messages and re-encrypt them. WrapKey ignores it.
	InsecureAllowWeakParams bool
}

func (p *PBES2Key) Algorithm() Algorithm { return AlgPrivatePBES2_HS256_A128KW }

func pbes2CountLabel(legacy bool) int64 {
	if legacy {
		return headerLabelLegacyPBES2Count
	}
	return headerLabelPBES2Count
}

func (p *PBES2Key) WrapKey(cek []byte, opts KeyWrapOpts) ([]byte, Headers, error) {
	if len(p.Password) == 0 {
		return nil, Headers{}, fmt.Errorf("%w: PBES2 password is empty", ErrInvalidKey)
	}
	if p.Salt != nil && len(p.Salt) < minPBES2SealSalt {
		return nil, Headers{}, fmt.Errorf("%w: PBES2 salt is %d bytes, must be at least %d (NIST SP 800-132)", ErrInvalidKey, len(p.Salt), minPBES2SealSalt)
	}
	if p.Count != 0 && p.Count < minPBES2Count {
		return nil, Headers{}, fmt.Errorf("%w: PBES2 count %d is below the minimum of %d (RFC 7518 §4.8.1.2)", ErrInvalidKey, p.Count, minPBES2Count)
	}
	return p.wrap(cek, opts)
}

// wrap is WrapKey without the floors.
func (p *PBES2Key) wrap(cek []byte, opts KeyWrapOpts) ([]byte, Headers, error) {
	salt := p.Salt
	if salt == nil {
		salt = make([]byte, defaultPBES2SaltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, Headers{}, fmt.Errorf("%w: generating salt: %w", ErrInvalidKey, err)
		}
	}

	count := p.Count
	if count == 0 {
		count = defaultPBES2Count
	}

	kek, err := pbkdf2.Key(sha256.New, string(p.Password), salt, count, 16)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: PBKDF2: %w", ErrInvalidKey, err)
	}

	wrapped, err := aeskw.Wrap(kek, cek)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	var h Headers
	h.params = map[any]any{
		headerLabelSalt:                    salt,
		pbes2CountLabel(opts.legacy.pbes2): int64(count),
	}
	return wrapped, h, nil
}

func (p *PBES2Key) UnwrapKey(ciphertext []byte, h Headers, opts KeyUnwrapOpts) ([]byte, error) {
	salt, ok := h.Get(headerLabelSalt).([]byte)
	if !ok || len(salt) == 0 {
		return nil, fmt.Errorf("%w: missing PBES2 salt in headers", ErrDecryption)
	}

	countVal := h.Get(pbes2CountLabel(opts.legacy.pbes2))
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
	if !p.InsecureAllowWeakParams {
		switch {
		case len(p.Password) == 0:
			return nil, fmt.Errorf("%w: PBES2 password is empty (see PBES2Key.InsecureAllowWeakParams)", ErrDecryption)
		case count < minPBES2Count:
			return nil, fmt.Errorf("%w: PBES2 count %d is below the minimum of %d (RFC 7518 §4.8.1.2; see PBES2Key.InsecureAllowWeakParams)", ErrDecryption, count, minPBES2Count)
		case len(salt) < minPBES2OpenSalt:
			return nil, fmt.Errorf("%w: PBES2 salt is %d bytes, must be at least %d (RFC 7518 §4.8.1.1; see PBES2Key.InsecureAllowWeakParams)", ErrDecryption, len(salt), minPBES2OpenSalt)
		}
	}

	kek, err := pbkdf2.Key(sha256.New, string(p.Password), salt, int(count), 16)
	if err != nil {
		return nil, fmt.Errorf("%w: PBKDF2: %w", ErrDecryption, err)
	}

	cek, kerr := aeskw.Unwrap(kek, ciphertext)
	if kerr != nil {
		return nil, ErrDecryption
	}
	return cek, nil
}
