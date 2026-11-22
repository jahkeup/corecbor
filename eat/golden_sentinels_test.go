// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat_test

import (
	g "github.com/jahkeup/corecbor/internal/goldentest"

	"github.com/jahkeup/corecbor/eat"
)

// Sentinels added after v0.2.2. They live here, not in
// golden_v022_test.go, because tools/golden-regen.sh compiles that file
// against the v0.2.2 tag, where these identifiers don't exist.
func init() {
	eatSentinels = append(
		eatSentinels,
		g.Sentinel{Name: "ErrSubmodUnverified", Err: eat.ErrSubmodUnverified},
		g.Sentinel{Name: "ErrInvalidUEID", Err: eat.ErrInvalidUEID},
		g.Sentinel{Name: "ErrInvalidNonce", Err: eat.ErrInvalidNonce},
		g.Sentinel{Name: "ErrDebugStatus", Err: eat.ErrDebugStatus},
		g.Sentinel{Name: "ErrUnknownDebugStatus", Err: eat.ErrUnknownDebugStatus},
		g.Sentinel{Name: "ErrInvalidProfile", Err: eat.ErrInvalidProfile},
		g.Sentinel{Name: "ErrClaimNumbering", Err: eat.ErrClaimNumbering},
	)
}
