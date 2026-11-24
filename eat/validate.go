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
// enforce (it keeps v0.2.2's acceptance of values):
//
//   - each nonce is 8..64 bytes (§4.1);
//   - UEID and every SUEID follow §4.2.1 (UEID.Validate);
//   - oemid is 3 or 16 bytes, or a non-negative PEN (§4.2.3);
//   - hwmodel is 1..32 bytes and only present with oemid (§4.2.4);
//     hwversion only with hwmodel (§4.2.5); oemboot only with oemid
//     (§4.2.8); swversion only with swname (§4.2.7);
//   - dbgstat is 0..4 (§4.2.9);
//   - each dloa registrar is an absolute URI (§4.2.14);
//   - manifests and measurements are identified by a CoAP
//     Content-Format, 0..65535 (§4.2.15, §4.2.16);
//   - each measres group has results, each 1..4 (§4.2.17);
//   - eat_profile is an absolute URI or a well-formed OID, not both
//     (§4.3.2).
//
// Inline submodule Claims-Sets are validated recursively. Errors are
// *cwt.ClaimError wrapping ErrInvalidNonce, ErrInvalidUEID,
// ErrUnknownDebugStatus, ErrInvalidProfile or ErrInvalidClaimValue.
// NewAppraiser and VerifyToken run it.
func (c *Claims) Validate() error {
	return c.validate(0)
}

// invalid builds the *cwt.ClaimError Validate returns for claim k.
func invalid(k int64, format string, args ...any) error {
	return claimError(k, fmt.Errorf("%w: "+format, append([]any{ErrInvalidClaimValue}, args...)...))
}

// validateEntity applies the §4.2.3–§4.2.8 size and dependency rules.
func (c *Claims) validateEntity() error {
	hasOEMID := len(c.OEMId) > 0 || c.OEMIDPEN != nil
	switch {
	case len(c.OEMId) > 0 && len(c.OEMId) != 3 && len(c.OEMId) != 16:
		return invalid(ClaimOEMID, "oemid is %d bytes, want 3 (IEEE) or 16 (random)", len(c.OEMId))
	case c.OEMIDPEN != nil && *c.OEMIDPEN < 0:
		return invalid(ClaimOEMID, "oemid PEN %d is negative", *c.OEMIDPEN)
	case len(c.HWModel) > 32:
		return invalid(ClaimHWModel, "hwmodel is %d bytes, want 1..32", len(c.HWModel))
	case len(c.HWModel) > 0 && !hasOEMID:
		return invalid(ClaimHWModel, "hwmodel requires oemid")
	case c.HWVersion != nil && len(c.HWModel) == 0:
		return invalid(ClaimHWVersion, "hwversion requires hwmodel")
	case c.SecureBoot != nil && !hasOEMID:
		return invalid(ClaimOEMBoot, "oemboot requires oemid")
	case c.SWVersion != nil && c.SWName == "":
		return invalid(ClaimSWVersion, "swversion requires swname")
	}
	return nil
}

// validateSoftware applies the §4.2.14–§4.2.17 rules.
func (c *Claims) validateSoftware() error {
	for i, d := range c.DLOAs {
		if u, err := url.Parse(d.Registrar); err != nil || u.Scheme == "" {
			return invalid(ClaimDLOAs, "dloa[%d] registrar %q is not an absolute URI", i, d.Registrar)
		}
	}
	for _, f := range []struct {
		key int64
		ts  []TypedBytes
	}{{ClaimManifests, c.Manifests}, {ClaimMeasurements, c.Measurements}} {
		for i, t := range f.ts {
			switch {
			case t.ContentFormat == nil:
				return invalid(f.key, "[%d] is identified by media type %q, want a CoAP Content-Format", i, t.MediaType)
			case *t.ContentFormat > 65535:
				return invalid(f.key, "[%d] content format %d exceeds 65535", i, *t.ContentFormat)
			}
		}
	}
	for i, g := range c.MeasRes {
		if len(g.Results) == 0 {
			return invalid(ClaimMeasRes, "measres[%d] has no results", i)
		}
		for j, r := range g.Results {
			if r.Result < MeasResultSuccess || r.Result > MeasResultAbsent {
				return invalid(ClaimMeasRes, "measres[%d][%d] result %d is not 1..4", i, j, r.Result)
			}
		}
	}
	return nil
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
	if err := c.validateEntity(); err != nil {
		return err
	}
	if err := c.validateSoftware(); err != nil {
		return err
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
