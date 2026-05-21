// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"fmt"

	"github.com/jahkeup/corecbor/cose"
)

// Sign encodes the claims and wraps them in a COSE_Sign1 structure.
func Sign(claims *ClaimsSet, signer *cose.Signer) ([]byte, error) {
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
func Verify(data []byte, verifier *cose.Verifier) (*ClaimsSet, error) {
	msg, err := cose.UnmarshalSign1(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	if err := verifier.Verify(msg); err != nil {
		return nil, err
	}

	return DecodeClaimsSet(msg.Payload)
}
