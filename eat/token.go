// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

import (
	"fmt"

	"github.com/jahkeup/corecbor/cose"
)

// Sign encodes the claims and wraps them in a COSE_Sign1 structure. A
// symmetric cnf key by value, at the top level or in an inline
// submodule, is refused with cwt.ErrSymmetricKeyNotEncrypted (RFC 8747
// §3.2: a signed EAT is not encrypted).
func Sign(claims *Claims, signer *cose.Signer, opts ...Option) ([]byte, error) {
	if err := checkNotExposed(claims, 0); err != nil {
		return nil, err
	}
	payload, err := claims.Encode(opts...)
	if err != nil {
		return nil, err
	}

	msg, err := signer.Sign(payload)
	if err != nil {
		return nil, err
	}

	return cose.MarshalSign1(msg)
}

// Verify decodes and verifies a signed EAT, returning the embedded claims.
// An outer CWT tag 61 is accepted (RFC 9711 §3), followed by a COSE
// tag. It checks the signature only: it does not validate claims or
// typ. It is the v0.2.2 entry point; use VerifyToken, which also
// validates the claims and applies cose.RecommendedDecodeLimits.
//
// The envelope is decoded with an 8 MiB memory budget, the same as the
// claims decoder's (v0.2.2 decoded it with no limit). A symmetric cnf
// key by value is refused with cwt.ErrSymmetricKeyNotEncrypted
// (RFC 8747 §3.2).
func Verify(data []byte, verifier *cose.Verifier, opts ...Option) (*Claims, error) {
	inner, _, err := unwrapCWT(data)
	if err != nil {
		return nil, err
	}
	msg, err := cose.UnmarshalSign1With(inner, legacyDecodeLimits)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedEAT, err)
	}

	if err := verifier.Verify(msg); err != nil {
		return nil, err
	}

	claims, err := DecodeClaims(msg.Payload, opts...)
	if err != nil {
		return nil, err
	}
	if err := checkNotExposed(claims, 0); err != nil {
		return nil, err
	}
	return claims, nil
}
