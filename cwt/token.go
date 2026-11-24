// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"fmt"

	"github.com/jahkeup/corecbor/cose"
)

// Sign encodes the claims and wraps them in a COSE_Sign1 structure. A
// symmetric cnf key by value is refused with ErrSymmetricKeyNotEncrypted
// (RFC 8747 §3.2: a signed CWT is not encrypted); use
// Confirmation.EncryptedKey, or Seal.
func Sign(claims *ClaimsSet, signer *cose.Signer) ([]byte, error) {
	if err := claims.checkNotExposed(); err != nil {
		return nil, err
	}
	payload, err := claims.Encode()
	if err != nil {
		return nil, err
	}

	msg, err := signer.Sign(payload)
	if err != nil {
		return nil, err
	}

	return cose.MarshalSign1(msg)
}

// Verify decodes and verifies a signed CWT, returning the embedded claims.
// An outer CWT tag 61 is accepted (RFC 8392 §6).
//
// Verify checks the signature only; it does not validate claims. Use
// VerifyToken, or call Validator.Validate on the result. It does refuse
// a symmetric cnf key by value with ErrSymmetricKeyNotEncrypted (RFC
// 8747 §3.2): the key has been exposed in transit.
func Verify(data []byte, verifier *cose.Verifier) (*ClaimsSet, error) {
	inner, _, err := unwrapCWT(data)
	if err != nil {
		return nil, err
	}
	msg, err := cose.UnmarshalSign1(inner)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedClaims, err)
	}

	if err := verifier.Verify(msg); err != nil {
		return nil, err
	}

	return decodePlaintextClaims(msg.Payload, DecodeOptions{})
}

// decodePlaintextClaims decodes the claims of a signed or MACed CWT,
// which may not carry a symmetric cnf key by value.
func decodePlaintextClaims(payload []byte, opts DecodeOptions) (*ClaimsSet, error) {
	cs, err := DecodeClaimsSetWith(payload, opts)
	if err != nil {
		return nil, err
	}
	if err := cs.checkNotExposed(); err != nil {
		return nil, err
	}
	return cs, nil
}
