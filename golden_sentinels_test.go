// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor_test

import (
	cc "github.com/jahkeup/corecbor"
	g "github.com/jahkeup/corecbor/internal/goldentest"
)

// Sentinels added after v0.2.2. They live here, not in
// golden_v022_test.go, because tools/golden-regen.sh compiles that file
// against the v0.2.2 tag, where these identifiers don't exist.
func init() {
	rootSentinels = append(
		rootSentinels,
		g.Sentinel{Name: "ErrTypeMismatch", Err: cc.ErrTypeMismatch},
		g.Sentinel{Name: "ErrInvalidKind", Err: cc.ErrInvalidKind},
		g.Sentinel{Name: "ErrTimeRange", Err: cc.ErrTimeRange},
		g.Sentinel{Name: "ErrNotDeterministic", Err: cc.ErrNotDeterministic},
		g.Sentinel{Name: "ErrReservedSimple", Err: cc.ErrReservedSimple},
		g.Sentinel{Name: "ErrUnexpectedBreak", Err: cc.ErrUnexpectedBreak},
		g.Sentinel{Name: "ErrNotPreferred", Err: cc.ErrNotPreferred},
		g.Sentinel{Name: "ErrInvalidOption", Err: cc.ErrInvalidOption},
	)
}
