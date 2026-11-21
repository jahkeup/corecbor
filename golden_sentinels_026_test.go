// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor_test

import (
	cc "github.com/jahkeup/corecbor"
	g "github.com/jahkeup/corecbor/internal/goldentest"
)

// Proposal 026 sentinels (see golden_sentinels_test.go for why these
// aren't in golden_v022_test.go).
func init() {
	rootSentinels = append(
		rootSentinels,
		g.Sentinel{Name: "ErrMalformedTag", Err: cc.ErrMalformedTag},
		g.Sentinel{Name: "ErrNonCanonicalTag", Err: cc.ErrNonCanonicalTag},
	)
}
