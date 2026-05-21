// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package aeskw implements AES Key Wrap per RFC 3394.
package aeskw

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// Default Initial Value per RFC 3394 §2.2.3.1.
var defaultIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// Wrap wraps plaintext with the given KEK using AES Key Wrap (RFC 3394).
// Plaintext must be a multiple of 8 bytes and at least 16 bytes.
func Wrap(kek, plaintext []byte) ([]byte, error) {
	n := len(plaintext) / 8
	if len(plaintext)%8 != 0 || n < 2 {
		return nil, errors.New("aeskw: plaintext must be multiple of 8 bytes and at least 16 bytes")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	// Initialize: A = IV, R[1..n] = P[1..n]
	var a [8]byte
	copy(a[:], defaultIV[:])
	r := make([][]byte, n)
	for i := range n {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:(i+1)*8])
	}

	// Wrap: 6 rounds
	var buf [16]byte
	for j := range 6 {
		for i := range n {
			// B = AES(K, A | R[i])
			copy(buf[:8], a[:])
			copy(buf[8:], r[i])
			block.Encrypt(buf[:], buf[:])

			// A = MSB(64, B) ^ t where t = (n*j)+i+1
			t := uint64(n*j + i + 1)
			copy(a[:], buf[:8])
			tBytes := [8]byte{}
			binary.BigEndian.PutUint64(tBytes[:], t)
			for k := range 8 {
				a[k] ^= tBytes[k]
			}
			// R[i] = LSB(64, B)
			copy(r[i], buf[8:])
		}
	}

	// Output: C = A | R[1] | R[2] | ... | R[n]
	out := make([]byte, (n+1)*8)
	copy(out[:8], a[:])
	for i := range n {
		copy(out[(i+1)*8:], r[i])
	}
	return out, nil
}

// Unwrap unwraps ciphertext with the given KEK using AES Key Unwrap (RFC 3394).
// Ciphertext must be a multiple of 8 bytes and at least 24 bytes.
func Unwrap(kek, ciphertext []byte) ([]byte, error) {
	n := len(ciphertext)/8 - 1
	if len(ciphertext)%8 != 0 || n < 2 {
		return nil, errors.New("aeskw: ciphertext must be multiple of 8 bytes and at least 24 bytes")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	// Initialize: A = C[0], R[i] = C[i]
	var a [8]byte
	copy(a[:], ciphertext[:8])
	r := make([][]byte, n)
	for i := range n {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[(i+1)*8:(i+2)*8])
	}

	// Unwrap: 6 rounds in reverse
	var buf [16]byte
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			// A ^= t
			t := uint64(n*j + i + 1)
			tBytes := [8]byte{}
			binary.BigEndian.PutUint64(tBytes[:], t)
			for k := range 8 {
				a[k] ^= tBytes[k]
			}
			// B = AES-1(K, (A ^ t) | R[i])
			copy(buf[:8], a[:])
			copy(buf[8:], r[i])
			block.Decrypt(buf[:], buf[:])
			// A = MSB(64, B)
			copy(a[:], buf[:8])
			// R[i] = LSB(64, B)
			copy(r[i], buf[8:])
		}
	}

	// Check IV
	if subtle.ConstantTimeCompare(a[:], defaultIV[:]) != 1 {
		return nil, errors.New("aeskw: integrity check failed")
	}

	// Output: P = R[1] | R[2] | ... | R[n]
	out := make([]byte, n*8)
	for i := range n {
		copy(out[i*8:], r[i])
	}
	return out, nil
}
