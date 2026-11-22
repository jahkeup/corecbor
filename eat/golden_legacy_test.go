// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat_test

import (
	"testing"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/eat"
	g "github.com/jahkeup/corecbor/internal/goldentest"
)

// TestGoldenLegacyReproducesV022 runs every v0.2.2 golden case with
// WithLegacyDraftClaimKeys and requires the v0.2.2 result, with no
// numbering allowlist (proposal 032 / 034). The only allowed difference
// is the submodule fail-closed safety fix, which applies whatever the
// numbering.
func TestGoldenLegacyReproducesV022(t *testing.T) {
	legacy := eat.WithLegacyDraftClaimKeys() //nolint:staticcheck // exercising the deprecated selector
	saved := [...]any{encodeClaims, decodeClaims, signClaims, verifyClaims}
	t.Cleanup(func() {
		encodeClaims = saved[0].(func(*eat.Claims) ([]byte, error))
		decodeClaims = saved[1].(func([]byte) (*eat.Claims, error))
		signClaims = saved[2].(func(*eat.Claims, *cose.Signer) ([]byte, error))
		verifyClaims = saved[3].(func([]byte, *cose.Verifier) (*eat.Claims, error))
	})
	encodeClaims = func(c *eat.Claims) ([]byte, error) { return c.Encode(legacy) }
	decodeClaims = func(b []byte) (*eat.Claims, error) { return eat.DecodeClaims(b, legacy) }
	signClaims = func(c *eat.Claims, s *cose.Signer) ([]byte, error) { return eat.Sign(c, s, legacy) }
	verifyClaims = func(b []byte, v *cose.Verifier) (*eat.Claims, error) { return eat.Verify(b, v, legacy) }

	g.Check(t, "testdata/golden/v0.2.2/eat.json", eatGoldenCases(), map[string]string{
		"eat/appraise/submod-token-no-verifier": "proposal 032 safety defect: fails closed under any numbering",
	})
}
