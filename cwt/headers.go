// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"fmt"

	"github.com/jahkeup/corecbor/cose"
)

// ClaimsFromHeaders decodes the CWT Claims Set carried in h under label
// 15 (RFC 9597). ok is false when the header is absent; a label-15
// value that is not a claims map is an error wrapping
// ErrMalformedClaims.
//
// RFC 9597 §2: only claims in the protected bucket are integrity
// protected. Callers that rely on them should read the protected
// headers.
func ClaimsFromHeaders(h *cose.Headers) (*ClaimsSet, bool, error) {
	if h == nil {
		return nil, false, nil
	}
	v, ok := h.CWTClaims()
	if !ok {
		if h.Get(HeaderLabelCWTClaims) != nil {
			return nil, true, fmt.Errorf("%w: CWT Claims header (label 15) is not a map", ErrMalformedClaims)
		}
		return nil, false, nil
	}
	cs, err := decodeClaimsValue(v, nil, DecodeOptions{})
	if err != nil {
		return nil, true, err
	}
	return cs, true, nil
}

// SetClaimsHeader encodes c into h under label 15 (RFC 9597). Use the
// protected bucket for claims that must be integrity protected.
func SetClaimsHeader(h *cose.Headers, c *ClaimsSet) error {
	v, err := c.toValue()
	if err != nil {
		return err
	}
	if err := h.SetCWTClaims(v); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedClaims, err)
	}
	return nil
}

// DecodeUCCS decodes an Unprotected CWT Claims Set: a claims map wrapped
// in tag 601 (RFC 9781).
//
// A UCCS has no integrity protection or authentication of its own; it
// is meaningful only when carried over a channel that provides them,
// such as an authenticated TLS connection (RFC 9781 §3). Validate its
// claims as for any CWT.
func DecodeUCCS(data []byte) (*ClaimsSet, error) {
	inner, tagged := stripTag(data, TagUCCS)
	if !tagged {
		return nil, fmt.Errorf("%w: UCCS tag 601 required", ErrMalformedClaims)
	}
	return DecodeClaimsSet(inner)
}
