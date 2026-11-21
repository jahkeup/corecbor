// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc_test

import (
	"testing"

	g "github.com/jahkeup/corecbor/internal/goldentest"

	"github.com/jahkeup/corecbor/edhoc"
)

// TestGoldenLegacyReproducesV022 runs every golden case under
// WithLegacyPreRFCProtocol with no allowlist: the deprecated selector
// must reproduce v0.2.2 exactly (proposal 034).
func TestGoldenLegacyReproducesV022(t *testing.T) {
	prevI, prevR := newInitiator, newResponder
	t.Cleanup(func() { newInitiator, newResponder = prevI, prevR })
	newInitiator = func(c edhoc.InitiatorConfig) (*edhoc.Initiator, error) {
		return edhoc.NewInitiator(c, edhoc.WithLegacyPreRFCProtocol())
	}
	newResponder = func(c edhoc.ResponderConfig) (*edhoc.Responder, error) {
		return edhoc.NewResponder(c, edhoc.WithLegacyPreRFCProtocol())
	}
	g.Check(t, "testdata/golden/v0.2.2/edhoc.json", edhocGoldenCases(), map[string]string{})
}
