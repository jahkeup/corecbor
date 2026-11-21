// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt_test

import (
	g "github.com/jahkeup/corecbor/internal/goldentest"

	"github.com/jahkeup/corecbor/cwt"
)

// Sentinels added after v0.2.2. They live here, not in
// golden_v022_test.go, because tools/golden-regen.sh compiles that file
// against the v0.2.2 tag, where these identifiers don't exist.
func init() {
	cwtSentinels = append(
		cwtSentinels,
		g.Sentinel{Name: "ErrInvalidValidator", Err: cwt.ErrInvalidValidator},
	)
}
