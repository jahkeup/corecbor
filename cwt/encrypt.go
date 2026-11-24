// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"fmt"
	"slices"

	"github.com/jahkeup/corecbor/cose"
)

// Encrypt creates an encrypted CWT (COSE_Encrypt0-wrapped claims).
// The caller must supply a key appropriate for alg (e.g. 32 bytes for A256GCM)
// and a 12-byte nonce for AES-GCM algorithms. The nonce is not written
// to the message, so the recipient must learn it out of band.
//
// Deprecated: use Seal, which generates the IV and carries it in the
// IV header (label 5) so OpenToken needs no nonce.
func Encrypt(claims *ClaimsSet, key []byte, nonce []byte, alg cose.Algorithm) ([]byte, error) {
	payload, err := claims.Encode()
	if err != nil {
		return nil, err
	}

	// v0.2 semantics: AES-GCM only, caller-supplied nonce, and the nonce
	// is not transmitted, so the IV header Encrypt0Seal writes is dropped.
	if !slices.Contains(defaultEncryptAlgs, alg) {
		return nil, fmt.Errorf("%w: %s is not an AES-GCM algorithm", cose.ErrUnsupportedAlgorithm, alg)
	}
	msg, err := cose.Encrypt0Seal(payload, key, alg, cose.WithNonce(nonce))
	if err != nil {
		return nil, err
	}
	msg.Unprotected = cose.Headers{}

	return cose.MarshalEncrypt0(msg)
}

// Decrypt decodes and decrypts an encrypted CWT, returning the embedded
// claims. An outer CWT tag 61 is accepted (RFC 8392 §6). The envelope
// is decoded with an 8 MiB memory budget. It does not
// validate claims.
//
// Deprecated: use OpenToken, which reads the IV from the message and
// validates the claims.
func Decrypt(data []byte, key []byte, nonce []byte, alg cose.Algorithm) (*ClaimsSet, error) {
	inner, _, err := unwrapCWT(data)
	if err != nil {
		return nil, err
	}
	msg, err := cose.UnmarshalEncrypt0With(inner, legacyDecodeLimits)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedClaims, err)
	}

	// Kept on DecryptEncrypt0: it uses the caller's nonce and alg (and
	// accepts an absent or unprotected alg equal to it), which is this
	// deprecated function's documented v0.2 behavior and which
	// Encrypt0Open deliberately doesn't offer.
	plaintext, err := cose.DecryptEncrypt0(msg, key, nonce, alg) //nolint:staticcheck // preserves v0.2 Decrypt semantics
	if err != nil {
		return nil, err
	}

	return DecodeClaimsSet(plaintext)
}

// MAC creates a MAC'd CWT (COSE_Mac0-wrapped claims).
// The caller must supply a key and an HMAC algorithm (e.g. AlgHMAC256).
// A symmetric cnf key by value is refused with
// ErrSymmetricKeyNotEncrypted (RFC 8747 §3.2), as in Sign. opts are
// passed to cose.ComputeMAC0 (for example cose.InsecureAllowShortMACKeys).
func MAC(claims *ClaimsSet, key []byte, alg cose.Algorithm, opts ...cose.MACOption) ([]byte, error) {
	if err := claims.checkNotExposed(); err != nil {
		return nil, err
	}
	payload, err := claims.Encode()
	if err != nil {
		return nil, err
	}

	msg, err := cose.ComputeMAC0(payload, key, alg, opts...)
	if err != nil {
		return nil, err
	}

	return cose.MarshalMac0(msg)
}

// VerifyMAC verifies and decodes a MAC'd CWT, returning the embedded
// claims. An outer CWT tag 61 is accepted (RFC 8392 §6). It checks the
// MAC only; use VerifyMACToken to also validate claims. Like Verify, it
// refuses a symmetric cnf key by value (ErrSymmetricKeyNotEncrypted)
// and decodes the envelope with an 8 MiB memory budget. opts are passed
// to cose.VerifyMAC0 (for example cose.InsecureAllowShortMACKeys).
func VerifyMAC(data []byte, key []byte, alg cose.Algorithm, opts ...cose.MACOption) (*ClaimsSet, error) {
	inner, _, err := unwrapCWT(data)
	if err != nil {
		return nil, err
	}
	msg, err := cose.UnmarshalMac0With(inner, legacyDecodeLimits)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedClaims, err)
	}

	if err := cose.VerifyMAC0(msg, key, alg, opts...); err != nil {
		return nil, err
	}

	return decodePlaintextClaims(msg.Payload, DecodeOptions{})
}
