// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

import (
	"fmt"
	"net/url"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/cwt"
)

// Validate checks the RFC 9711 value constraints DecodeClaims does not
// enforce (it keeps v0.2.2's acceptance):
//
//   - each nonce is 8..64 bytes (§4.1);
//   - UEID and every SUEID follow §4.2.1 (UEID.Validate);
//   - dbgstat is 0..4 (§4.2.9);
//   - eat_profile is an absolute URI or a well-formed OID, not both
//     (§4.3.2).
//
// Inline submodule Claims-Sets are validated recursively. Errors are
// *cwt.ClaimError wrapping ErrInvalidNonce, ErrInvalidUEID,
// ErrUnknownDebugStatus or ErrInvalidProfile.
func (c *Claims) Validate() error {
	return c.validate(0)
}

func (c *Claims) validate(depth int) error {
	if depth > maxSubmodDepth {
		return fmt.Errorf("%w: submodules nested deeper than %d", ErrMalformedEAT, maxSubmodDepth)
	}
	for i, n := range c.Nonce {
		if len(n) < 8 || len(n) > 64 {
			return claimError(ClaimNonce, fmt.Errorf("%w: nonce[%d] is %d bytes, want 8..64", ErrInvalidNonce, i, len(n)))
		}
	}
	if len(c.UEID) > 0 {
		if err := UEID(c.UEID).Validate(); err != nil {
			return claimError(ClaimUEID, err)
		}
	}
	for name, id := range c.SUEIDs {
		if err := UEID(id).Validate(); err != nil {
			return claimError(ClaimSUEIDs, fmt.Errorf("sueids[%q]: %w", name, err))
		}
	}
	if d, ok := c.debugStatus(); ok && (d < DebugEnabled || d > DebugDisabledFullyAndPermanently) {
		return claimError(ClaimDbgStat, fmt.Errorf("%w: %d", ErrUnknownDebugStatus, d))
	}
	if err := c.validateProfile(); err != nil {
		return claimError(ClaimProfile, err)
	}
	for _, name := range sortedSubmodNames(c.Submods) {
		if s := c.Submods[name].Claims; s != nil {
			if err := s.validate(depth + 1); err != nil {
				return fmt.Errorf("submods[%q]: %w", name, err)
			}
		}
	}
	return nil
}

func claimError(k int64, err error) error { return &cwt.ClaimError{Key: cwt.IntKey(k), Err: err} }

// debugStatus returns the effective dbgstat and whether it is present:
// DbgStat when set, else a non-zero Debug.
func (c *Claims) debugStatus() (DebugStatus, bool) {
	if c.DbgStat != nil {
		return *c.DbgStat, true
	}
	return c.Debug, c.Debug != 0
}

func (c *Claims) validateProfile() error {
	switch {
	case c.Profile != "" && c.ProfileOID != nil:
		return fmt.Errorf("%w: both URI and OID forms are set", ErrInvalidProfile)
	case c.Profile != "":
		u, err := url.Parse(c.Profile)
		if err != nil || u.Scheme == "" {
			return fmt.Errorf("%w: %q is not an absolute URI", ErrInvalidProfile, c.Profile)
		}
	case c.ProfileOID != nil:
		if _, err := cbor.AsOID(cbor.MakeTag(cbor.TagOID, cbor.Bytes(c.ProfileOID))); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidProfile, err)
		}
	}
	return nil
}
